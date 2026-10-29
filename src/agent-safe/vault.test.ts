import assert from 'node:assert/strict';
import fs, {
  chmod,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  rename,
  rm,
  stat,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test, { type TestContext } from 'node:test';
import { SafeError } from './privateWorker.js';
import { AgentVault } from './vault.js';

const internals = (vault: AgentVault) =>
  vault as unknown as {
    bw: { revoke(): Promise<void> };
    sdk: { sync(): Promise<void>; getItem(id: string): Promise<unknown> };
  };

async function fixture(t: TestContext, idleMs?: number) {
  const root = await mkdtemp(join(tmpdir(), 'warden-vault-'));
  await writeFile(
    join(root, 'access.json'),
    JSON.stringify({ enabled: true, allow_all: true }),
  );
  await chmod(join(root, 'access.json'), 0o600);
  const vault = new AgentVault(
    root,
    {
      server: 'https://example.invalid',
      bw: 'unused',
      python: 'unused',
      worker: 'unused',
    },
    idleMs,
  );
  t.mock.method(internals(vault).bw, 'revoke', async () => {});
  return {
    root,
    vault,
    cleanup: async () => {
      await vault.revoke();
      await rm(root, { recursive: true, force: true });
    },
  };
}

test('production sessions remain memory-only with a ten-minute idle default', async (t) => {
  const f = await fixture(t);
  try {
    const settings = f.vault as unknown as {
      idleMs: number;
      bw: { env: { persistSession: boolean; homeDir: string } };
    };
    assert.equal(settings.idleMs, 600_000);
    assert.equal(settings.bw.env.persistSession, false);
    assert.equal(settings.bw.env.homeDir, join(f.root, 'state', 'cli'));
  } finally {
    await f.cleanup();
  }
});

test('pause stops an in-flight private operation before waiting for the vault lock', async (t) => {
  const f = await fixture(t);
  let release!: () => void, started!: () => void;
  const blocked = new Promise<void>((resolve) => {
    release = resolve;
  });
  const ready = new Promise<void>((resolve) => {
    started = resolve;
  });
  let stopped = 0;
  t.mock.method(f.vault.worker, 'call', async () => {
    started();
    await blocked;
    return {};
  });
  t.mock.method(f.vault.worker, 'stop', () => {
    stopped++;
    release();
  });
  t.mock.method(internals(f.vault).bw, 'revoke', async () => {});
  const active = f.vault.invoke('browser_close', {});
  await ready;
  const paused = f.vault.invoke('pause_access', {});
  try {
    assert.ok(stopped > 0);
    assert.equal((await active).error, 'disabled');
    assert.equal((await paused).enabled, false);
  } finally {
    release();
    await active;
    await paused;
    await f.cleanup();
  }
});

test('audit never appends through symlinks and new logs are private', async (t) => {
  const f = await fixture(t);
  t.mock.method(f.vault.worker, 'call', async () => ({ registered: false }));
  try {
    await mkdir(join(f.root, 'logs'), { mode: 0o700 });
    const name = `audit-${new Date().toISOString().slice(0, 10)}.jsonl`;
    const victim = join(f.root, 'victim');
    await writeFile(victim, 'untouched');
    await symlink(victim, join(f.root, 'logs', name));
    assert.equal((await f.vault.invoke('status', {})).ok, false);
    assert.equal(await readFile(victim, 'utf8'), 'untouched');
    await rm(join(f.root, 'logs', name));
    assert.equal((await f.vault.invoke('status', {})).ok, true);
    assert.equal((await stat(join(f.root, 'logs', name))).mode & 0o777, 0o600);
  } finally {
    await f.cleanup();
  }
});

test('pause replaces policy privately without following a predictable temporary symlink', async (t) => {
  const f = await fixture(t);
  t.mock.method(internals(f.vault).bw, 'revoke', async () => {});
  try {
    const victim = join(f.root, 'victim');
    await writeFile(victim, 'untouched');
    await symlink(victim, join(f.root, 'access.json.tmp'));
    assert.equal((await f.vault.invoke('pause_access', {})).ok, true);
    assert.equal(await readFile(victim, 'utf8'), 'untouched');
    assert.equal(
      JSON.parse(await readFile(join(f.root, 'access.json'), 'utf8')).enabled,
      false,
    );
    assert.equal((await stat(join(f.root, 'access.json'))).mode & 0o777, 0o600);
  } finally {
    await f.cleanup();
  }
});

test('failed credential-using operations still expire after inactivity', async (t) => {
  const f = await fixture(t, 20);
  let revoked = 0;
  t.mock.method(internals(f.vault).sdk, 'sync', async () => {
    throw new Error('fixture failure');
  });
  t.mock.method(f.vault.worker, 'call', async () => ({}));
  t.mock.method(f.vault.worker, 'stop', () => {});
  t.mock.method(internals(f.vault).bw, 'revoke', async () => {
    revoked++;
  });
  try {
    assert.equal((await f.vault.invoke('sync', {})).ok, false);
    await new Promise((resolve) => setTimeout(resolve, 70));
    assert.equal(revoked, 1);
  } finally {
    await f.cleanup();
  }
});

test('Linux status reports credential-provider enrollment without fetching credentials', {
  skip: process.platform !== 'linux',
}, async (t) => {
  const f = await fixture(t);
  const calls: string[] = [];
  t.mock.method(f.vault.worker, 'call', async (operation: string) => {
    calls.push(operation);
    return { registered: true, master: 'must-not-return' };
  });
  try {
    const result = await f.vault.invoke('status', {});
    assert.equal(result.credential_enrolled, true);
    assert.equal(result.storage, 'Linux root-managed credential service');
    assert.deepEqual(calls, ['credential_status']);
    assert.equal(JSON.stringify(result).includes('must-not-return'), false);
  } finally {
    await f.cleanup();
  }
});

test('error codes and audit rows cannot bypass the secret filter', async (t) => {
  const f = await fixture(t);
  const secret = 'never_return_this_secret';
  f.vault.filter.add(secret, '11111111-1111-1111-1111-111111111111');
  t.mock.method(internals(f.vault).sdk, 'sync', async () => {
    throw new SafeError(secret);
  });
  try {
    const result = await f.vault.invoke('sync', {
      item_id: '11111111-1111-1111-1111-111111111111',
    });
    assert.equal(JSON.stringify(result).includes(secret), false);
    assert.equal(result.error, 'operation_failed');
    for (const file of await readdir(join(f.root, 'logs'))) {
      const log = await readFile(join(f.root, 'logs', file), 'utf8');
      assert.equal(log.includes(secret), false);
      assert.equal(log.includes('11111111-1111-1111-1111-111111111111'), false);
    }
  } finally {
    await f.cleanup();
  }
});

test('unknown actions never reach credentials or leak their names to logs', async (t) => {
  const f = await fixture(t);
  let calls = 0;
  t.mock.method(f.vault.worker, 'call', async () => {
    calls++;
    return {};
  });
  t.mock.method(internals(f.vault).sdk, 'getItem', async (id: string) => {
    calls++;
    return { id };
  });
  try {
    const result = await f.vault.invoke('SECRET_UNKNOWN_TOOL', {
      item_id: '11111111-1111-1111-1111-111111111111',
    });
    assert.equal(result.error, 'unsupported');
    assert.equal(calls, 0);
    const files = await readdir(join(f.root, 'logs')).catch(() => []);
    for (const file of files)
      assert.equal(
        (await readFile(join(f.root, 'logs', file), 'utf8')).includes(
          'SECRET_UNKNOWN_TOOL',
        ),
        false,
      );
  } finally {
    await f.cleanup();
  }
});

// Match linux_manage.write_policy: a private temporary file atomically replaces
// access.json; no MCP call is involved in local resume.
async function waitUntil(check: () => boolean) {
  for (let attempt = 0; attempt < 100 && !check(); attempt++)
    await new Promise((resolve) => setTimeout(resolve, 10));
  assert.ok(check(), 'local policy must promptly revoke active resources');
}

test('local pause revokes an idle browser and session without another MCP call', async (t) => {
  const f = await fixture(t);
  const item = '11111111-1111-1111-1111-111111111111';
  let browser = false,
    session = false;
  const calls: string[] = [];
  t.mock.method(internals(f.vault).sdk, 'getItem', async () => {
    session = true;
    return { id: item };
  });
  t.mock.method(f.vault.worker, 'call', async (action: string) => {
    calls.push(action);
    browser = true;
    return { page_id: 'page-before-pause' };
  });
  t.mock.method(f.vault.worker, 'stop', () => {
    browser = false;
  });
  t.mock.method(internals(f.vault).bw, 'revoke', async () => {
    session = false;
  });
  try {
    assert.equal(
      (await f.vault.invoke('browser_open', { item_id: item })).ok,
      true,
    );
    assert.ok(browser && session);
    await localPolicy(f.root, false);
    await waitUntil(() => !browser && !session);
    assert.deepEqual(calls, ['browser_open']);
    assert.equal(
      (await f.vault.invoke('browser_open', { item_id: item })).error,
      'disabled',
    );
    await localPolicy(f.root, true);
    assert.equal(
      (await f.vault.invoke('browser_state', { page_id: 'page-before-pause' }))
        .error,
      'page',
    );
    assert.equal(
      (await f.vault.invoke('browser_open', { item_id: item })).ok,
      true,
    );
  } finally {
    await f.cleanup();
  }
});

test('local pause stops an in-flight worker before the operation lock is released', async (t) => {
  const f = await fixture(t);
  const item = '11111111-1111-1111-1111-111111111111';
  let release!: () => void, started!: () => void;
  const blocked = new Promise<void>((resolve) => {
    release = resolve;
  });
  const ready = new Promise<void>((resolve) => {
    started = resolve;
  });
  let stopped = false,
    session = true;
  t.mock.method(internals(f.vault).sdk, 'getItem', async () => ({ id: item }));
  t.mock.method(f.vault.worker, 'call', async () => {
    started();
    await blocked;
    return { page_id: 'in-flight-page' };
  });
  t.mock.method(f.vault.worker, 'stop', () => {
    stopped = true;
    release();
  });
  t.mock.method(internals(f.vault).bw, 'revoke', async () => {
    session = false;
  });
  const active = f.vault.invoke('browser_open', { item_id: item });
  try {
    await ready;
    await localPolicy(f.root, false);
    await waitUntil(() => stopped && !session);
    assert.equal((await active).error, 'disabled');
    await localPolicy(f.root, true);
    assert.equal(
      (await f.vault.invoke('browser_state', { page_id: 'in-flight-page' }))
        .error,
      'page',
    );
  } finally {
    release();
    await active;
    await f.cleanup();
  }
});

test('local resume cannot revive an operation that was reading credentials when paused', async (t) => {
  const f = await fixture(t);
  const item = '11111111-1111-1111-1111-111111111111';
  let release!: () => void, started!: () => void;
  const blocked = new Promise<void>((resolve) => {
    release = resolve;
  });
  const ready = new Promise<void>((resolve) => {
    started = resolve;
  });
  let revoked = false,
    calls = 0;
  t.mock.method(internals(f.vault).sdk, 'getItem', async () => {
    started();
    await blocked;
    return { id: item };
  });
  t.mock.method(f.vault.worker, 'call', async () => {
    calls++;
    return {};
  });
  t.mock.method(internals(f.vault).bw, 'revoke', async () => {
    revoked = true;
  });
  const active = f.vault.invoke('browser_open', { item_id: item });
  try {
    await ready;
    await localPolicy(f.root, false);
    await waitUntil(() => revoked);
    await localPolicy(f.root, true);
    release();
    assert.equal((await active).error, 'disabled');
    assert.equal(calls, 0);
    assert.equal(
      (await f.vault.invoke('browser_open', { item_id: item })).ok,
      true,
    );
  } finally {
    release();
    await active;
    await f.cleanup();
  }
});

test('revocation cancels an outstanding policy poll without restarting cleanup', async (t) => {
  const f = await fixture(t);
  let release!: () => void;
  const blocked = new Promise<void>((resolve) => {
    release = resolve;
  });
  let polling = false,
    revoked = 0;
  t.mock.method(f.vault.worker, 'call', async () => ({}));
  t.mock.method(internals(f.vault).bw, 'revoke', async () => {
    revoked++;
  });
  try {
    assert.equal((await f.vault.invoke('browser_close', {})).ok, true);
    const timers = f.vault as unknown as { policyTimer?: NodeJS.Timeout };
    assert.equal(timers.policyTimer?.hasRef(), false);
    t.mock.method(f.vault, 'policy', async () => {
      polling = true;
      await blocked;
      return { enabled: false };
    });
    await waitUntil(() => polling);
    await f.vault.revoke();
    release();
    await new Promise((resolve) => setTimeout(resolve, 30));
    assert.equal(revoked, 1);
    assert.equal(timers.policyTimer, undefined);
  } finally {
    release();
    await f.cleanup();
  }
});

// Use the same atomic replacement shape as the local management helper.
async function localPolicy(root: string, enabled: boolean) {
  const temporary = join(root, '.access-local-test');
  await writeFile(temporary, JSON.stringify({ enabled, allow_all: true }), {
    mode: 0o600,
    flag: 'wx',
  });
  await rename(temporary, join(root, 'access.json'));
}

test('successful MCP pause can be resumed locally in the same process repeatedly', async (t) => {
  const f = await fixture(t);
  let calls = 0;
  t.mock.method(internals(f.vault).sdk, 'sync', async () => {
    calls++;
  });
  try {
    for (let cycle = 0; cycle < 2; cycle++) {
      assert.equal((await f.vault.invoke('pause_access', {})).ok, true);
      assert.equal((await f.vault.invoke('sync', {})).error, 'disabled');
      assert.equal(
        (await f.vault.invoke('resume_access', {})).error,
        'unsupported',
      );
      await localPolicy(f.root, true);
      assert.equal((await f.vault.invoke('sync', {})).ok, true);
    }
    assert.equal(calls, 2);
  } finally {
    await f.cleanup();
  }
});

test('failed pause persistence cannot resume from the preexisting enabled policy', {
  skip: process.platform !== 'linux',
}, async (t) => {
  const f = await fixture(t);
  let calls = 0;
  t.mock.method(f.vault.worker, 'call', async () => ({ registered: true }));
  t.mock.method(internals(f.vault).sdk, 'sync', async () => {
    calls++;
  });
  const persist = t.mock.method(fs, 'writeFile', async () => {
    throw new Error('synthetic disk failure');
  });
  syncBuiltinESMExports();
  try {
    await mkdir(join(f.root, 'logs'), { mode: 0o700 });
    const original = await readFile(join(f.root, 'access.json'), 'utf8');
    assert.equal((await f.vault.invoke('pause_access', {})).ok, false);
    persist.mock.restore();
    syncBuiltinESMExports();
    assert.equal(await readFile(join(f.root, 'access.json'), 'utf8'), original);
    assert.equal((await f.vault.invoke('status', {})).enabled, false);
    assert.equal((await f.vault.invoke('sync', {})).error, 'disabled');
    // Metadata maintenance is not a local resume decision.
    await chmod(join(f.root, 'access.json'), 0o400);
    assert.equal((await f.vault.invoke('sync', {})).error, 'disabled');
    assert.equal(calls, 0);
    await localPolicy(f.root, true);
    assert.equal((await f.vault.invoke('status', {})).enabled, true);
    assert.equal((await f.vault.invoke('sync', {})).ok, true);
    assert.equal(calls, 1);
  } finally {
    persist.mock.restore();
    syncBuiltinESMExports();
    await f.cleanup();
  }
});

test('a local policy replacement resumes the same vault after failed pause persistence', async (t) => {
  const f = await fixture(t);
  let stopped = 0,
    revoked = 0;
  t.mock.method(f.vault.worker, 'call', async () => ({}));
  t.mock.method(f.vault.worker, 'stop', () => {
    stopped++;
  });
  t.mock.method(internals(f.vault).bw, 'revoke', async () => {
    revoked++;
  });
  try {
    await rm(join(f.root, 'access.json'));
    await mkdir(join(f.root, 'access.json'));
    const result = await f.vault.invoke('pause_access', {});
    assert.equal(result.ok, false);
    assert.ok(stopped > 0);
    assert.equal(revoked, 1);
    assert.equal((await f.vault.invoke('sync', {})).error, 'disabled');
    await rm(join(f.root, 'access.json'), { recursive: true });
    await localPolicy(f.root, true);
    t.mock.method(internals(f.vault).sdk, 'sync', async () => {});
    assert.equal((await f.vault.invoke('sync', {})).ok, true);
  } finally {
    await f.cleanup();
  }
});
