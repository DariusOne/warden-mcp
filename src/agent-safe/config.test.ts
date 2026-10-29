import assert from 'node:assert/strict';
import {
  chmod,
  mkdir,
  mkdtemp,
  realpath,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

async function loader() {
  const modulePath = import.meta.url.endsWith('.ts')
    ? './config.ts'
    : './config.js';
  return ((await import(modulePath)) as typeof import('./config.js'))
    .loadAgentConfig;
}

async function fixture() {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'warden-config-')));
  const config = {
    server: 'https://example.invalid/vault',
    bw: join(root, 'bw'),
    python: join(root, 'python'),
    worker: join(root, 'worker.py'),
    browser_executable: join(root, 'chromium'),
  };
  for (const file of [
    config.bw,
    config.python,
    config.worker,
    config.browser_executable,
  ])
    await writeFile(file, 'fixture', { mode: 0o700 });
  await writeFile(join(root, 'config.json'), JSON.stringify(config), {
    mode: 0o600,
  });
  await chmod(join(root, 'config.json'), 0o600);
  return {
    root,
    config,
    cleanup: () => rm(root, { recursive: true, force: true }),
  };
}

test('Linux validates private runtime state and root-managed credential socket', async () => {
  const load = await loader(),
    f = await fixture();
  try {
    for (const credential_socket of [
      join(f.root, 'bw'),
      '/tmp/credentials.sock',
      '/run/warden-hermes-credentials/../credentials.sock',
      '',
      42,
    ]) {
      await writeFile(
        join(f.root, 'config.json'),
        JSON.stringify({ ...f.config, credential_socket }),
      );
      await assert.rejects(load(f.root, 'linux'), /^Error: agent_safe_config$/);
    }
    await writeFile(join(f.root, 'config.json'), JSON.stringify(f.config));
    for (const name of ['state', 'logs']) {
      await mkdir(join(f.root, name), { mode: 0o700 });
      await chmod(join(f.root, name), 0o755);
      await assert.rejects(load(f.root, 'linux'), /^Error: agent_safe_config$/);
      await chmod(join(f.root, name), 0o700);
    }
    await writeFile(join(f.root, 'access.json'), '{}');
    await chmod(join(f.root, 'access.json'), 0o644);
    await assert.rejects(load(f.root, 'linux'), /^Error: agent_safe_config$/);
    await chmod(join(f.root, 'access.json'), 0o600);
    assert.deepEqual(await load(f.root, 'linux'), f.config);
  } finally {
    await f.cleanup();
  }
});

test('Linux rejects noncanonical, nonprivate, missing, or nonexecutable paths', async () => {
  const load = await loader(),
    f = await fixture();
  try {
    for (const root of [
      `${f.root}/.`,
      `${f.root}/`,
      'relative',
      `${f.root}/absent`,
    ])
      await assert.rejects(load(root, 'linux'), /^Error: agent_safe_config$/);
    await chmod(f.root, 0o755);
    await assert.rejects(load(f.root, 'linux'), /^Error: agent_safe_config$/);
    await chmod(f.root, 0o700);
    await chmod(join(f.root, 'config.json'), 0o644);
    await assert.rejects(load(f.root, 'linux'), /^Error: agent_safe_config$/);
    await chmod(join(f.root, 'config.json'), 0o600);
    await symlink(f.config.bw, join(f.root, 'alias'));
    for (const key of ['bw', 'python', 'worker', 'browser_executable']) {
      for (const path of [
        'relative',
        f.root,
        join(f.root, 'absent'),
        join(f.root, 'alias'),
        `${f.config.bw}/../bw`,
        null,
      ]) {
        await writeFile(
          join(f.root, 'config.json'),
          JSON.stringify({ ...f.config, [key]: path }),
        );
        await assert.rejects(
          load(f.root, 'linux'),
          /^Error: agent_safe_config$/,
        );
      }
    }
    await writeFile(join(f.root, 'config.json'), JSON.stringify(f.config));
    await chmod(f.config.bw, 0o600);
    await assert.rejects(load(f.root, 'linux'), /^Error: agent_safe_config$/);
    await chmod(f.config.bw, 0o700);
    await chmod(f.config.worker, 0o200);
    await assert.rejects(load(f.root, 'linux'), /^Error: agent_safe_config$/);
    await chmod(f.config.worker, 0o600);
    assert.deepEqual(await load(f.root, 'linux'), f.config);
    await mkdir(join(f.root, 'node_modules'));
    const bundled = join(f.root, 'node_modules', 'bw');
    await writeFile(bundled, 'fixture', { mode: 0o700 });
    await writeFile(
      join(f.root, 'config.json'),
      JSON.stringify({ ...f.config, bw: bundled }),
    );
    await assert.rejects(load(f.root, 'linux'), /^Error: agent_safe_config$/);
  } finally {
    await f.cleanup();
  }
});

test('config rejects unsafe server URLs and malformed config without echoing values', async () => {
  const load = await loader(),
    f = await fixture();
  try {
    for (const server of [
      'http://example.invalid',
      'https://secret@example.invalid',
      'https://u:secret@example.invalid',
      'https://example.invalid?secret',
      'https://example.invalid#secret',
      'https://example.invalid?',
      'https://example.invalid#',
      ' https://example.invalid',
      'https://example.invalid/\nsecret',
      42,
      null,
    ]) {
      await writeFile(
        join(f.root, 'config.json'),
        JSON.stringify({ ...f.config, server }),
      );
      await assert.rejects(load(f.root, 'linux'), /^Error: agent_safe_config$/);
    }
    for (const value of [
      'secret',
      'null',
      '[]',
      '{',
      JSON.stringify({ ...f.config, unknown: 'secret' }),
    ]) {
      await writeFile(join(f.root, 'config.json'), value);
      await assert.rejects(load(f.root, 'linux'), /^Error: agent_safe_config$/);
    }
  } finally {
    await f.cleanup();
  }
});

test('Linux loads a canonical private config and rejects unsupported platforms', async () => {
  const f = await fixture();
  try {
    // Dynamic loading makes the first RED assert the missing feature explicitly.
    const modulePath = import.meta.url.endsWith('.ts')
      ? './config.ts'
      : './config.js';
    const mod = await import(modulePath).catch(() => ({}));
    assert.equal(
      typeof (mod as Record<string, unknown>).loadAgentConfig,
      'function',
    );
    const { loadAgentConfig } = mod as typeof import('./config.js');
    assert.deepEqual(await loadAgentConfig(f.root, 'linux'), f.config);
    await assert.rejects(
      loadAgentConfig(f.root, 'darwin'),
      /^Error: agent_safe_config$/,
    );
  } finally {
    await f.cleanup();
  }
});
