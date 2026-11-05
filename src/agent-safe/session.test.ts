import assert from 'node:assert/strict';
import { mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import test, { type TestContext } from 'node:test';
import { deferred, sessionFixture } from '../bw/bwSession.lifecycle.fixture.js';
import { SecretFilter } from './filter.js';
import { PrivateWorker } from './privateWorker.js';
import { AgentSession } from './session.js';

async function fixture(t: TestContext, apikey = false) {
  const f = await sessionFixture(t);
  const root = join(f.config.homeDir, 'agent');
  const profile = join(root, 'state', 'cli', '.bitwarden-cli');
  await mkdir(profile, { recursive: true });
  const filter = new SecretFilter();
  const worker = new PrivateWorker('unused', 'unused', root);
  const auth = {
    server: `${f.config.host}/bitwarden`,
    email: f.config.login.user,
    master: 'master-password',
    ...(apikey
      ? { client_id: 'client.example', client_secret: 'api-secret' }
      : {}),
  };
  const identity = {
    server: auth.server,
    login: apikey
      ? { method: 'apikey', clientId: 'client.example' }
      : { method: 'userpass', user: auth.email },
  };
  const calls: string[] = [];
  t.mock.method(worker, 'call', async (operation: string) => {
    calls.push(operation);
    return operation === 'credential_identity' ? identity : auth;
  });
  const session = new AgentSession(
    root,
    auth.server,
    worker,
    filter,
    async () => {},
  );
  t.after(() => session.revoke().catch(() => {}));
  return { session, auth, identity, calls, filter, profile, worker };
}

for (const apikey of [false, true]) {
  test(`private adapter binds real identity and reopens without session files (${apikey ? 'apikey' : 'password'})`, {
    skip: process.platform === 'win32' && 'POSIX synthetic CLI fixture',
  }, async (t) => {
    const f = await fixture(t, apikey);
    if (apikey) await writeFile(join(f.profile, 'require-login'), 'yes');
    assert.deepEqual(f.calls, [], 'construction must not read any credentials');
    const values = await Promise.all([
      f.session.withSession(async (s) => s),
      f.session.withSession(async (s) => s),
    ]);
    assert.deepEqual(values, ['session-1', 'session-1']);
    assert.deepEqual(f.calls, ['credential_identity', 'credentials']);
    assert.equal(
      f.filter.text('master-password session-1'),
      '[REDACTED] [REDACTED]',
    );
    if (apikey) assert.equal(f.filter.text('api-secret'), '[REDACTED]');
    assert.equal(
      JSON.parse(await readFile(join(f.profile, 'data.json'), 'utf8'))
        .global_environment_environment.urls.base,
      f.auth.server,
    );
    const cache = join(f.profile, '.warden-mcp-session.json');
    await assert.rejects(stat(cache), { code: 'ENOENT' });
    await f.session.revoke();
    assert.equal(await f.session.withSession(async (s) => s), 'session-2');
    assert.deepEqual(f.calls, [
      'credential_identity',
      'credentials',
      'credential_identity',
      'credentials',
    ]);
    assert.equal(f.filter.text('session-2'), '[REDACTED]');
    await assert.rejects(stat(cache), { code: 'ENOENT' });
  });
}

test('changed credential identity is rejected without returning provider details', {
  skip: process.platform === 'win32' && 'POSIX synthetic CLI fixture',
}, async (t) => {
  const f = await fixture(t);
  f.auth.email = 'changed@example.test';
  await assert.rejects(
    f.session.withSession(async () => {}),
    { message: 'credential_store' },
  );
  const operations = await readFile(join(f.profile, 'operations'), 'utf8');
  assert.doesNotMatch(operations, /unlock|login/);
});

for (const operation of ['credential_identity', 'credentials']) {
  test(`revoke fences an in-flight ${operation} response even after local resume`, {
    skip: process.platform === 'win32' && 'POSIX synthetic CLI fixture',
  }, async (t) => {
    const f = await fixture(t);
    const ready = deferred(),
      release = deferred();
    t.mock.method(f.worker, 'call', async (action: string) => {
      if (action === operation) {
        ready.resolve();
        await release.promise;
      }
      return action === 'credential_identity' ? f.identity : f.auth;
    });
    let ran = false;
    const pending = f.session.withSession(async () => {
      ran = true;
    });
    const rejected = assert.rejects(pending, { message: 'disabled' });
    await ready.promise;
    const revoke = f.session.revoke();
    release.resolve();
    await Promise.all([rejected, revoke]);
    assert.equal(ran, false);
    assert.equal(await f.session.withSession(async (s) => s), 'session-1');
  });
}

test('revocation errors remain sanitized and discard the old manager', {
  skip: process.platform === 'win32' && 'POSIX synthetic CLI fixture',
}, async (t) => {
  const f = await fixture(t);
  await f.session.withSession(async () => {});
  await writeFile(join(f.profile, 'fail-lock'), 'yes');
  await assert.rejects(f.session.revoke(), (error: unknown) => {
    assert.ok(error instanceof Error);
    assert.equal(error.message, 'session_cleanup');
    assert.equal(error.cause, undefined);
    return true;
  });
  await assert.rejects(f.session.status(), { message: 'login_required' });
});
