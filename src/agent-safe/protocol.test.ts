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
