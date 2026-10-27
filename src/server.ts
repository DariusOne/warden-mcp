// src/server.ts

import { parseArgs } from 'node:util';
import { runAgentSafe } from './agent-safe/server.js';
import { createKeychainApp } from './transports/http.js';
import { runStdioTransport } from './transports/stdio.js';

const { values } = parseArgs({
  options: {
    stdio: { type: 'boolean', default: false },
    http: { type: 'boolean', default: false },
    'agent-safe': { type: 'boolean', default: false },
    'agent-root': { type: 'string' },
  },
  strict: false,
});

const useStdio =
  values.stdio === true || process.env.WARDEN_MCP_STDIO === 'true';

async function main(): Promise<void> {
  if (values['agent-safe']) {
    if (values.http || typeof values['agent-root'] !== 'string')
      throw new Error('agent_safe_config');
    await runAgentSafe(values['agent-root']);
    return;
  }
  if (useStdio) {
    await runStdioTransport();
    return;
  }

  const PORT = Number.parseInt(process.env.PORT ?? '3005', 10);
  const rawHost = process.env.WARDEN_MCP_HOST?.trim();
  const host = rawHost && rawHost.length > 0 ? rawHost : undefined;
  const app = createKeychainApp();
  const server = host
    ? app.listen(PORT, host, () => {
        console.log(`[warden-mcp] listening on http://${host}:${PORT}/sse`);
      })
    : app.listen(PORT, () => {
        console.log(`[warden-mcp] listening on http://localhost:${PORT}/sse`);
      });

  await new Promise<void>((resolve, reject) => {
    server.once('close', resolve);
    server.once('error', reject);
  });
}

void main().catch((error: unknown) => {
  console.error(
    values['agent-safe']
      ? 'Agent-safe startup failed; check local configuration.'
      : error,
  );
  process.exitCode = 1;
});
