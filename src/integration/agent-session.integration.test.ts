import assert from 'node:assert/strict';
import { mkdtemp, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { SecretFilter } from '../agent-safe/filter.js';
import { PrivateWorker } from '../agent-safe/privateWorker.js';
import { AgentSession } from '../agent-safe/session.js';
import { readBwEnv } from '../bw/bwSession.js';
import { KeychainSdk } from '../sdk/keychainSdk.js';

test('integration: private adapter authenticates, filters sessions, revokes and reopens', {
  timeout: 180_000,
}, async (t) => {
  if (!process.env.BW_HOST) {
    t.skip('BW_HOST not set (integration tests require docker compose env)');
    return;
  }
  const credentials = readBwEnv();
  const root = await mkdtemp(join(tmpdir(), 'agent-session-integration-'));
  const filter = new SecretFilter();
  const worker = new PrivateWorker('unused', 'unused', root);
  let reads = 0;
  t.mock.method(worker, 'call', async (operation: string) => {
    if (operation === 'credential_identity')
      return {
        server: credentials.host,
        login:
          credentials.login.method === 'apikey'
            ? { method: 'apikey', clientId: credentials.login.clientId }
            : { method: 'userpass', user: credentials.login.user },
      };
    assert.equal(operation, 'credentials');
    reads++;
    return {
      server: credentials.host,
      master: credentials.password,
      email:
        credentials.login.method === 'userpass' ? credentials.login.user : '',
      ...(credentials.login.method === 'apikey'
        ? {
            client_id: credentials.login.clientId,
            client_secret: credentials.login.clientSecret,
          }
        : {}),
    };
  });
  const session = new AgentSession(
    root,
    credentials.host,
    worker,
    filter,
    async () => {},
  );
  t.after(async () => {
    try {
      await session.revoke();
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
  assert.equal(reads, 0);
  const sdk = new KeychainSdk(session);
  assert.ok(Array.isArray(await sdk.listFolders({ limit: 1 })));
  await session.withSession(async (value) => {
    assert.equal(filter.text(value), '[REDACTED]');
  });
  assert.equal(filter.text(credentials.password), '[REDACTED]');
  assert.equal(reads, 1);
  await session.revoke();
  assert.ok(Array.isArray(await sdk.listFolders({ limit: 1 })));
  assert.equal(reads, 2);
  await assert.rejects(
    stat(
      join(root, 'state', 'cli', '.bitwarden-cli', '.warden-mcp-session.json'),
    ),
    { code: 'ENOENT' },
  );
});
