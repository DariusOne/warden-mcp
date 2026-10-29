import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import {
  chmod,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { runAgentSafe } from './server.js';

test('stdin EOF closes MCP and awaits memory/browser revocation', {
  skip: process.platform !== 'linux',
}, async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'warden-eof-')));
  try {
    const bw = join(root, 'bw');
    await writeFile(bw, '#!/bin/sh\nprintf "2026.9.1\\n"\n');
    await chmod(bw, 0o700);
    await writeFile(
      join(root, 'config.json'),
      JSON.stringify({
        server: 'https://example.invalid',
        bw,
        python: await realpath(process.env.WARDEN_TEST_PYTHON ?? '/usr/bin/python3'),
        worker: fileURLToPath(new URL('../../agent_worker/worker.py', import.meta.url)),
      }),
    );
    await chmod(join(root, 'config.json'), 0o600);
    const source = `import {runAgentSafe} from ${JSON.stringify(new URL('./server.js', import.meta.url).href)}; import {writeFile} from 'node:fs/promises'; await runAgentSafe(${JSON.stringify(root)}); await writeFile(${JSON.stringify(join(root, 'finished'))}, 'revoked');`;
    const child = spawn(
      process.execPath,
      ['--input-type=module', '--eval', source],
      { stdio: ['pipe', 'pipe', 'pipe'] },
    );
    const timer = setTimeout(() => child.kill('SIGKILL'), 5000);
    let diagnostic = '';
    child.stderr.on('data', (chunk) => {
      diagnostic += chunk;
    });
    child.stdin.end();
    const code = await new Promise<number | null>((resolve) =>
      child.on('close', resolve),
    );
    clearTimeout(timer);
    assert.equal(code, 0, diagnostic);
    assert.equal(await readFile(join(root, 'finished'), 'utf8'), 'revoked');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('Linux startup probes exact CLI version only inside isolated private CLI state', {
  skip: process.platform !== 'linux',
}, async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'warden-startup-')));
  const saved = { ...process.env };
  try {
    const bw = join(root, 'bw');
    await writeFile(
      bw,
      '#!/bin/sh\nprintf "%s" "$BITWARDENCLI_APPDATA_DIR" > "' +
        root +
        '/probe"\nprintf "2026.9.2\\n"\n',
    );
    await chmod(bw, 0o700);
    await writeFile(
      join(root, 'config.json'),
      JSON.stringify({
        server: 'https://example.invalid',
        bw,
        python: await realpath(process.env.WARDEN_TEST_PYTHON ?? '/usr/bin/python3'),
        worker: fileURLToPath(new URL('../../agent_worker/worker.py', import.meta.url)),
      }),
    );
    await chmod(join(root, 'config.json'), 0o600);
    process.env.BITWARDENCLI_APPDATA_DIR = join(
      root,
      'daily-profile-must-not-use',
    );
    await assert.rejects(runAgentSafe(root), /^Error: agent_safe_cli_version$/);
    assert.equal(
      await readFile(join(root, 'probe'), 'utf8'),
      join(root, 'state', 'cli'),
    );
  } finally {
    for (const key of Object.keys(process.env))
      if (!(key in saved)) delete process.env[key];
    Object.assign(process.env, saved);
    await rm(root, { recursive: true, force: true });
  }
});
