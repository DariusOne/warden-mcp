import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { registerTools } from '../tools/registerTools.js';
import { record } from './filter.js';
import { registerAgentTools, tools } from './server.js';
import { AgentVault } from './vault.js';

test('safe MCP exposes exactly twelve compatible tools; direct secret calls rejected', async () => {
  const root = await mkdtemp(join(tmpdir(), 'warden-protocol-'));
  const vault = new AgentVault(root, {
    server: 'https://example.invalid/bitwarden',
    bw: 'unused',
    python: 'unused',
    worker: 'unused',
  });
  await writeFile(
    join(root, 'access.json'),
    JSON.stringify({ enabled: false, allow_all: true }),
  );
  const server = new McpServer({ name: 'vaultwarden', version: 'test' });
  registerAgentTools(server, vault);
  const client = new Client({ name: 'test', version: 'test' });
  const [a, b] = InMemoryTransport.createLinkedPair();
  try {
    await server.connect(a);
    await client.connect(b);
    const listed = await client.listTools();
    const expected: Record<string, Record<string, unknown>> = {
      status: {},
      search: { query: '' },
      sync: {},
      browser_open: { item_id: null, url: '' },
      browser_state: { page_id: null },
      browser_fill_login: {
        page_id: null,
        password_ref: null,
        username_ref: '',
      },
      browser_fill_totp: { page_id: null, ref: null },
      browser_action: { page_id: null, action: null, ref: null, text: '' },
      mysql_query: { item_id: null, sql: null, max_rows: 100 },
      ssh_exec: { item_id: null, command: null, timeout: 20 },
      browser_close: {},
      pause_access: {},
    };
    assert.deepEqual(
      listed.tools.map((t) => t.name).sort(),
      Object.keys(expected).sort(),
    );
    for (const tool of listed.tools) {
      assert.equal(tool.inputSchema.additionalProperties, false);
      assert.equal(tool.inputSchema.type, 'object');
      assert.deepEqual(
        Object.keys(tool.inputSchema.properties ?? {}),
        Object.keys(expected[tool.name]),
      );
      for (const [key, defaultValue] of Object.entries(expected[tool.name])) {
        const property = record(tool.inputSchema.properties?.[key]);
        assert.equal(
          property.type,
          typeof defaultValue === 'number' ? 'integer' : 'string',
        );
        assert.equal(
          property.default,
          defaultValue === null ? undefined : defaultValue,
        );
      }
      assert.deepEqual(
        tool.inputSchema.required ?? [],
        Object.entries(expected[tool.name])
          .filter(([, value]) => value === null)
          .map(([key]) => key),
      );
      assert.equal(
        tool.annotations?.readOnlyHint,
        ['status', 'search', 'sync', 'browser_state', 'mysql_query'].includes(
          tool.name,
        ),
      );
      assert.equal(
        tool.annotations?.destructiveHint,
        ['ssh_exec', 'browser_action'].includes(tool.name),
      );
      assert.equal(
        tool.annotations?.openWorldHint,
        !['status', 'search', 'sync', 'browser_state', 'mysql_query'].includes(
          tool.name,
        ),
      );
    }
    assert.deepEqual(
      listed.tools.map((t) => t.name).sort(),
      Object.keys(tools).sort(),
    );
    assert.equal(
      listed.tools.find((t) => t.name === 'ssh_exec')?.annotations
        ?.readOnlyHint,
      false,
    );
    assert.equal(
      listed.tools.find((t) => t.name === 'browser_action')?.annotations
        ?.destructiveHint,
      true,
    );
    const result = await client.callTool({ name: 'status', arguments: {} });
    assert.equal(record(result.structuredContent).credential_enrolled, false);
    assert.deepEqual(
      JSON.parse((result.content as { text: string }[])[0]?.text ?? '{}'),
      result.structuredContent,
    );
    for (const name of [
      'keychain_get_password',
      'keychain_get_totp',
      'keychain_get_attachment',
      'keychain_send_get',
      'credentials',
      'resume_access',
    ]) {
      const r = await client.callTool({ name, arguments: {} });
      assert.equal(r.isError, true, name);
    }
    for (const name of ['search', 'sync']) {
      const r = await client.callTool({ name, arguments: {} });
      assert.equal(record(r.structuredContent).error, 'disabled');
    }
  } finally {
    await client.close();
    await server.close();
    await rm(root, { recursive: true, force: true });
  }
});

test('MCP cancellation stops private work and revokes the vault session', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'warden-cancel-'));
  await writeFile(join(root, 'access.json'), JSON.stringify({ enabled: true }));
  const vault = new AgentVault(root, {
    server: 'https://example.invalid',
    bw: 'unused',
    python: 'unused',
    worker: 'unused',
  });
  let started!: () => void, release!: () => void;
  const ready = new Promise<void>((resolve) => {
    started = resolve;
  });
  const blocked = new Promise<void>((resolve) => {
    release = resolve;
  });
  let calls = 0,
    stopped = 0,
    revoked = 0;
  t.mock.method(vault.worker, 'call', async () => {
    if (++calls === 1) {
      started();
      await blocked;
    }
    return {};
  });
  t.mock.method(vault.worker, 'stop', () => {
    stopped++;
    release();
  });
  t.mock.method(
    (vault as unknown as { bw: { revoke(): Promise<void> } }).bw,
    'revoke',
    async () => {
      revoked++;
    },
  );
  const server = new McpServer({ name: 'safe', version: 'test' });
  registerAgentTools(server, vault);
  const client = new Client({ name: 'test', version: 'test' });
  const [a, b] = InMemoryTransport.createLinkedPair();
  const abort = new AbortController();
  try {
    await server.connect(a);
    await client.connect(b);
    const pending = client.callTool(
      { name: 'browser_close', arguments: {} },
      undefined,
      { signal: abort.signal },
    );
    const rejected = assert.rejects(pending);
    await ready;
    abort.abort();
    await rejected;
    await new Promise((resolve) => setTimeout(resolve, 40));
    assert.ok(stopped > 0);
    assert.ok(revoked > 0);
    assert.equal(
      calls,
      1,
      'cancellation must not restart a worker for cleanup',
    );
  } finally {
    release();
    await new Promise((resolve) => setTimeout(resolve, 40));
    await client.close();
    await server.close();
    await rm(root, { recursive: true, force: true });
  }
});

test('MCP text and structured results share the same secret-filtered value', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'warden-filter-protocol-'));
  await writeFile(join(root, 'access.json'), JSON.stringify({ enabled: true }));
  const vault = new AgentVault(root, {
    server: 'https://example.invalid',
    bw: 'unused',
    python: 'unused',
    worker: 'unused',
  });
  const secret = 'synthetic-protocol-secret';
  vault.filter.add(secret);
  t.mock.method(vault.worker, 'call', async () => ({
    closed: true,
    nested: { [secret]: secret },
    text: Buffer.from(secret).toString('base64'),
  }));
  const server = new McpServer({ name: 'safe', version: 'test' });
  registerAgentTools(server, vault);
  const client = new Client({ name: 'test', version: 'test' });
  const [a, b] = InMemoryTransport.createLinkedPair();
  try {
    await server.connect(a);
    await client.connect(b);
    const result = await client.callTool({
      name: 'browser_close',
      arguments: {},
    });
    assert.deepEqual(
      JSON.parse((result.content as { text: string }[])[0].text),
      result.structuredContent,
    );
    assert.equal(record(result.structuredContent).ok, true);
    assert.equal(JSON.stringify(result).includes(secret), false);
    assert.equal(
      JSON.stringify(result).includes(Buffer.from(secret).toString('base64')),
      false,
    );
    assert.ok(JSON.stringify(result).includes('[REDACTED]'));
  } finally {
    await client.close();
    await server.close();
    await rm(root, { recursive: true, force: true });
  }
});

test('MCP validation and unknown-tool errors never echo attacker-controlled secret arguments', async () => {
  const root = await mkdtemp(join(tmpdir(), 'warden-protocol-'));
  const vault = new AgentVault(root, {
    server: 'https://example.invalid',
    bw: 'unused',
    python: 'unused',
    worker: 'unused',
  });
  const server = new McpServer({ name: 'safe', version: 'test' });
  registerAgentTools(server, vault);
  const client = new Client({ name: 'test', version: 'test' });
  const [a, b] = InMemoryTransport.createLinkedPair();
  const secret = 'NEVER_ECHO_UNREGISTERED_SECRET';
  try {
    await server.connect(a);
    await client.connect(b);
    for (const [name, args] of [
      ['status', { [secret]: secret }],
      [secret, {}],
      ['mysql_query', { item_id: {}, sql: { [secret]: secret } }],
      ['__proto__', {}],
    ] as const) {
      const result = await client.callTool({ name, arguments: args });
      assert.equal(result.isError, true);
      assert.equal(JSON.stringify(result).includes(secret), false);
      assert.deepEqual(result.content, [
        { type: 'text', text: 'Invalid tool request.' },
      ]);
    }
  } finally {
    await client.close();
    await server.close();
    await rm(root, { recursive: true, force: true });
  }
});

test('NOREVEAL rejects attachment and Send content before SDK invocation', async () => {
  const old = process.env.NOREVEAL;
  process.env.NOREVEAL = 'true';
  const server = new McpServer({ name: 'normal', version: 'test' });
  let reached = false;
  registerTools(server, {
    toolPrefix: 'keychain',
    toolSeparator: '_',
    getSdk: async () => {
      reached = true;
      throw new Error('must not read');
    },
  });
  const client = new Client({ name: 'test', version: 'test' });
  const [a, b] = InMemoryTransport.createLinkedPair();
  try {
    await server.connect(a);
    await client.connect(b);
    for (const [name, args] of [
      ['get_attachment', { itemId: 'i', attachmentId: 'a' }],
      ['send_list', {}],
      ['send_get', { id: 'i', text: true }],
      ['receive', { url: 'https://example.invalid/send' }],
    ] as const) {
      const r = await client.callTool({
        name: `keychain_${name}`,
        arguments: args,
      });
      assert.equal(r.isError, true);
    }
    assert.equal(reached, false);
  } finally {
    if (old === undefined) delete process.env.NOREVEAL;
    else process.env.NOREVEAL = old;
    await client.close();
    await server.close();
  }
});
