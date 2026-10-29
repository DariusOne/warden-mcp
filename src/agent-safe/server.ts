import { mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import {
  configureBwCliContainment,
  runBw,
  withBwCancellation,
} from '../bw/bwCli.js';
import { loadAgentConfig } from './config.js';
import { record } from './filter.js';
import { type ConfirmHostKey, HOST_CONFIRMATION_MS } from './sshTrust.js';
import { AgentVault } from './vault.js';
import { AGENT_VERSION } from './version.js';

const READ = {
  readOnlyHint: true,
  destructiveHint: false,
  openWorldHint: false,
};
const USE = {
  readOnlyHint: false,
  destructiveHint: false,
  openWorldHint: true,
};
const WRITE = {
  readOnlyHint: false,
  destructiveHint: true,
  openWorldHint: true,
};
const str = () => z.string();
export const tools = {
  status: {
    input: {},
    annotations: READ,
    description: '查看本机接入状态，不返回秘密。',
  },
  search: {
    input: { query: str().default('') },
    annotations: READ,
    description:
      '按名称查找条目，仅返回 ID、名称、用户名、网站来源和能力标记。',
  },
  sync: {
    input: {},
    annotations: READ,
    description: '从服务器同步密码库，不修改服务端条目。',
  },
  browser_open: {
    input: { item_id: str(), url: str().default('') },
    annotations: USE,
    description: '为精确条目 ID 打开独立 Edge，只允许条目中保存的 HTTPS 来源。',
  },
  browser_state: {
    input: { page_id: str() },
    annotations: READ,
    description:
      '返回网页文字和控件引用，不返回输入值、Cookie、HTML 或 URL 参数。',
  },
  browser_fill_login: {
    input: {
      page_id: str(),
      password_ref: str(),
      username_ref: str().default(''),
    },
    annotations: USE,
    description: '在本机直接填入密码，不提交、不返回密码。',
  },
  browser_fill_totp: {
    input: { page_id: str(), ref: str() },
    annotations: USE,
    description: '直接填入当前 TOTP，不提交、不返回验证码。',
  },
  browser_action: {
    input: {
      page_id: str(),
      action: str(),
      ref: str(),
      text: str().default(''),
    },
    annotations: WRITE,
    description:
      '执行 click/fill/press，可能提交表单或修改远端，须符合用户授权。',
  },
  mysql_query: {
    input: {
      item_id: str(),
      sql: str(),
      max_rows: z.number().int().default(100),
    },
    annotations: READ,
    description: '使用条目连接 MySQL，执行有界只读查询，最多 500 行。',
  },
  ssh_exec: {
    input: {
      item_id: str(),
      command: str(),
      timeout: z.number().int().default(20),
    },
    annotations: WRITE,
    description:
      '执行已授权 SSH 命令；首次主机密钥通过客户端单独确认并在本机保存，密钥变化拒绝连接。可能修改远端。',
  },
  browser_close: {
    input: {},
    annotations: USE,
    description: '关闭本工具的全部浏览器及其会话。',
  },
  pause_access: {
    input: {},
    annotations: USE,
    description: '暂停接入、关闭浏览器并撤销会话。恢复只能使用本机管理窗口。',
  },
};

export function registerAgentTools(server: McpServer, vault: AgentVault): void {
  const confirmation =
    (requestId?: string | number): ConfirmHostKey =>
    async (message, signal) => {
      if (!server.server.getClientCapabilities()?.elicitation?.form)
        return 'unavailable';
      try {
        const reply = await server.server.elicitInput(
          {
            mode: 'form',
            message,
            requestedSchema: { type: 'object', properties: {} },
          },
          {
            signal,
            timeout: HOST_CONFIRMATION_MS,
            relatedRequestId: requestId,
          },
        );
        return reply.action;
      } catch (error) {
        if (signal.aborted) return 'cancel';
        return record(error).code === -32001 ? 'timeout' : 'unavailable';
      }
    };
  for (const [name, definition] of Object.entries(tools)) {
    server.registerTool(
      name,
      {
        description: definition.description,
        inputSchema: z.object(definition.input).strict(),
        annotations: definition.annotations,
      },
      async (args) => {
        const result = await vault.invoke(
          name,
          record(args),
          undefined,
          confirmation(),
        );
        return {
          content: [{ type: 'text' as const, text: JSON.stringify(result) }],
          structuredContent: result,
        };
      },
    );
  }
  // SDK diagnostics include unrecognized keys/tool names. Keep its listed schemas,
  // but validate calls here so even previously unknown secrets cannot be echoed.
  server.server.setRequestHandler(
    CallToolRequestSchema,
    async (request, extra) => {
      const invalid = {
        isError: true,
        content: [{ type: 'text' as const, text: 'Invalid tool request.' }],
      };
      const name = request.params.name;
      if (!Object.hasOwn(tools, name)) return invalid;
      const definition = tools[name as keyof typeof tools];
      const parsed = z
        .object(definition.input)
        .strict()
        .safeParse(request.params.arguments ?? {});
      if (!parsed.success || request.params.task) return invalid;
      try {
        const result = await withBwCancellation(extra.signal, () =>
          vault.invoke(
            name,
            record(parsed.data),
            extra.signal,
            confirmation(extra.requestId),
          ),
        );
        return {
          content: [{ type: 'text' as const, text: JSON.stringify(result) }],
          structuredContent: result,
        };
      } catch {
        return {
          isError: true,
          content: [{ type: 'text' as const, text: 'Local operation failed.' }],
        };
      }
    },
  );
}

export async function runAgentSafe(root: string): Promise<void> {
  const config = await loadAgentConfig(root);
  await configureBwCliContainment(config.python, config.worker);
  const home = join(root, 'state', 'cli');
  await mkdir(home, { recursive: true, mode: 0o700 });
  // Safe mode never inherits a debug switch or an externally supplied session.
  for (const key of Object.keys(process.env))
    if (/^(BW_|KEYCHAIN_|NODE_OPTIONS$)/.test(key)) delete process.env[key];
  process.env.WARDEN_AGENT_SAFE_PROCESS = '1';
  process.env.BW_BIN = config.bw;
  const version = await runBw(['--version'], {
    noInteraction: false,
    timeoutMs: 10_000,
    env: { BITWARDENCLI_APPDATA_DIR: home },
  });
  if (version.stdout.trim() !== '2026.9.1')
    throw new Error('agent_safe_cli_version');
  const vault = new AgentVault(root, config);
  const server = new McpServer(
    { name: 'vaultwarden', version: AGENT_VERSION },
    {
      instructions:
        '使用 status/search 后按精确条目 ID 调用工具。密码、TOTP、主密码和会话不会返回。首次 SSH 指纹必须通过客户端本次确认；工具永久批准不代替主机信任。拒绝、取消后不要自动重试；密钥变化不能自动覆盖。只可按用户授权连接或提交网页。不要通过其他工具读取凭据文件或 CLI 缓存。恢复接入使用本机管理窗口。',
    },
  );
  registerAgentTools(server, vault);
  const transport = new StdioServerTransport();
  const closed = new Promise<void>((resolve) => {
    transport.onclose = resolve;
  });
  const close = () => {
    void server.close().catch(() => {});
  };
  process.stdin.once('end', close);
  try {
    await server.connect(transport);
    if (process.stdin.readableEnded) close();
    await closed;
  } finally {
    process.stdin.off('end', close);
    await vault.revoke();
  }
}
