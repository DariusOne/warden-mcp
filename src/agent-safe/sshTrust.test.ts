import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test, { type TestContext } from 'node:test';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { ElicitRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { record } from './filter.js';
import { SafeError } from './privateWorker.js';
import { registerAgentTools } from './server.js';
import {
  type HostDecision,
  type HostKeyInfo,
  parseHostKey,
} from './sshTrust.js';
import { AgentVault } from './vault.js';

const id = '10000000-0000-4000-8000-000000000001';
const bytes = Buffer.alloc(64, 7);
const info: HostKeyInfo = {
  host: '127.0.0.1',
  port: 2222,
  key_type: 'ssh-ed25519',
  public_key: bytes.toString('base64'),
  binding: 'a'.repeat(64),
  fingerprint: `SHA256:${createHash('sha256').update(bytes).digest('base64').replace(/=+$/, '')}`,
  previous_fingerprints: [],
};
const args = { item_id: id, command: 'synthetic-command' };

async function fixture(t: TestContext) {
  const root = await mkdtemp(join(tmpdir(), 'warden-ssh-confirm-'));
  await writeFile(
    join(root, 'access.json'),
    JSON.stringify({ enabled: true, allow_all: true }),
  );
  const vault = new AgentVault(root, {
    server: 'https://example.invalid',
    bw: 'unused',
    python: 'unused',
    worker: 'unused',
  });
  const inner = vault as unknown as {
    bw: { revoke(): Promise<void> };
    sdk: { getItem(id: string): Promise<unknown>; sync(): Promise<void> };
  };
  const item = {
    id,
    name: 'Synthetic\nSSH',
    login: {
      username: 'fixture',
      password: 'never-output-this-fixture-password',
    },
  };
  let reads = 0,
    syncs = 0;
  const calls: { operation: string; payload: Record<string, unknown> }[] = [];
  t.mock.method(inner.bw, 'revoke', async () => {});
  t.mock.method(inner.sdk, 'getItem', async () => {
    reads++;
    return item;
  });
  t.mock.method(inner.sdk, 'sync', async () => {
    syncs++;
  });
  t.mock.method(vault.worker, 'stop', () => {});
  t.mock.method(
    vault.worker,
    'call',
    async (operation: string, payload: Record<string, unknown>) => {
      calls.push({ operation, payload });
      if (operation === 'ssh_exec' && !payload.ssh_approval)
        throw new SafeError('ssh_host_unknown', info);
      return { exit_code: 0, stdout: 'fixture-completed', stderr: '' };
    },
  );
  return {
    vault,
    root,
    item,
    calls,
    get reads() {
      return reads;
    },
    get syncs() {
      return syncs;
    },
    cleanup: async () => {
      await vault.revoke();
      await rm(root, { recursive: true, force: true });
    },
  };
}

test('private host response is bounded and cryptographically self-consistent', () => {
  assert.deepEqual(parseHostKey(info), info);
  assert.equal(
    parseHostKey({ ...info, fingerprint: `SHA256:${'A'.repeat(43)}` }),
    undefined,
  );
  assert.equal(parseHostKey({ ...info, host: 'host\nsecret' }), undefined);
  assert.equal(
    parseHostKey({ ...info, public_key: 'x'.repeat(17000) }),
    undefined,
  );
  assert.equal(
    parseHostKey({ ...info, previous_fingerprints: ['raw exception'] }),
    undefined,
  );
});

test('unknown host without a client confirmation channel cannot authenticate', async (t) => {
  const f = await fixture(t);
  try {
    const result = await f.vault.invoke('ssh_exec', args);
    assert.equal(result.error, 'ssh_confirmation_required');
    assert.equal(f.calls.length, 1);
    assert.equal(JSON.stringify(result).includes(info.public_key), false);
    assert.equal(JSON.stringify(result).includes(info.binding), false);
  } finally {
    await f.cleanup();
  }
});

for (const decision of [
  'decline',
  'cancel',
  'timeout',
  'unavailable',
] as HostDecision[]) {
  test(`confirmation ${decision} cannot execute the command`, async (t) => {
    const f = await fixture(t);
    try {
      const result = await f.vault.invoke(
        'ssh_exec',
        args,
        undefined,
        async () => decision,
      );
      assert.equal(result.ok, false);
      assert.equal(f.calls.length, 1);
      assert.equal(f.syncs, 0);
    } finally {
      await f.cleanup();
    }
  });
}

test('accept is bound to the original key and synchronizes the target before one retry', async (t) => {
  const f = await fixture(t);
  let prompts = 0;
  try {
    const result = await f.vault.invoke(
      'ssh_exec',
      args,
      undefined,
      async (message) => {
        prompts++;
        assert.ok(message.includes(info.fingerprint));
        assert.ok(message.includes('127.0.0.1:2222'));
        assert.ok(!message.includes(f.item.login.password));
        return 'accept';
      },
    );
    assert.equal(result.ok, true);
    assert.equal(prompts, 1);
    assert.equal(f.calls.length, 2);
    assert.equal(f.reads, 2);
    assert.equal(f.syncs, 1);
    const approval = f.calls[1]?.payload.ssh_approval as HostKeyInfo & {
      expires_at: number;
    };
    assert.equal(approval.public_key, info.public_key);
    assert.equal(approval.binding, info.binding);
    assert.ok(approval.expires_at > Date.now());
    assert.ok(!JSON.stringify(result).includes(f.item.login.password));
  } finally {
    await f.cleanup();
  }
});

test('pause invalidates a confirmation while no worker call is active', async (t) => {
  const f = await fixture(t);
  let shown!: () => void;
  const ready = new Promise<void>((resolve) => {
    shown = resolve;
  });
  const active = f.vault.invoke(
    'ssh_exec',
    args,
    undefined,
    async (_, signal) => {
      shown();
      return new Promise<HostDecision>((resolve) =>
        signal.addEventListener('abort', () => resolve('accept'), {
          once: true,
        }),
      );
    },
  );
  try {
    await ready;
    const paused = f.vault.invoke('pause_access', {});
    assert.equal((await active).error, 'disabled');
    assert.equal((await paused).enabled, false);
    assert.equal(f.calls.length, 1);
  } finally {
    await f.cleanup();
  }
});

test('a key overlapping known secrets is never shown or automatically trusted', async (t) => {
  const f = await fixture(t);
  let prompted = false;
  f.vault.filter.add(info.fingerprint);
  try {
    const result = await f.vault.invoke(
      'ssh_exec',
      args,
      undefined,
      async () => {
        prompted = true;
        return 'accept';
      },
    );
    assert.equal(result.error, 'ssh_confirmation_required');
    assert.equal(prompted, false);
    assert.ok(!JSON.stringify(result).includes(info.fingerprint));
    assert.equal(f.calls.length, 1);
  } finally {
    await f.cleanup();
  }
});

test('changed keys never offer an ordinary first-use confirmation', async (t) => {
  const f = await fixture(t);
  t.mock.method(f.vault.worker, 'call', async () => {
    throw new SafeError('ssh_host_changed', info);
  });
  try {
    const result = await f.vault.invoke('ssh_exec', args, undefined, async () =>
      assert.fail('unexpected approval'),
    );
    assert.equal(result.error, 'ssh_host_changed');
    assert.deepEqual(result.host_key, {
      host: info.host,
      port: info.port,
      key_type: info.key_type,
      fingerprint: info.fingerprint,
      previous_fingerprints: [],
    });
  } finally {
    await f.cleanup();
  }
});

test('real MCP form elicitation works without adding tools or accepting confirmation arguments', async (t) => {
  const f = await fixture(t);
  const server = new McpServer({ name: 'fixture', version: '0' });
  registerAgentTools(server, f.vault);
  const client = new Client(
    { name: 'fixture', version: '0' },
    { capabilities: { elicitation: { form: {} } } },
  );
  let prompts = 0;
  client.setRequestHandler(ElicitRequestSchema, async (request) => {
    prompts++;
    assert.equal(request.params.mode, 'form');
    assert.ok(request.params.message.includes(info.fingerprint));
    return { action: 'accept', content: {} };
  });
  const [a, b] = InMemoryTransport.createLinkedPair();
  try {
    await Promise.all([server.connect(a), client.connect(b)]);
    assert.equal((await client.listTools()).tools.length, 12);
    const invalid = await client.callTool({
      name: 'ssh_exec',
      arguments: { ...args, confirmed: true },
    });
    assert.equal(invalid.isError, true);
    assert.equal(prompts, 0);
    const result = await client.callTool({ name: 'ssh_exec', arguments: args });
    assert.equal(record(result.structuredContent).ok, true);
    assert.equal(prompts, 1);
    const files = await readFile(
      join(
        f.root,
        'logs',
        `audit-${new Date().toISOString().slice(0, 10)}.jsonl`,
      ),
      'utf8',
    );
    assert.ok(!files.includes(f.item.login.password));
    assert.ok(!JSON.stringify(result).includes(info.public_key));
  } finally {
    await client.close();
    await server.close();
    await f.cleanup();
  }
});
