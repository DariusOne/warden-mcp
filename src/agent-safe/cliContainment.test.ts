import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const linux = { skip: process.platform !== 'linux', timeout: 15_000 };
const moduleUrl = new URL('../bw/bwCli.js', import.meta.url).href;
const worker = fileURLToPath(
  new URL('../../agent_worker/worker.py', import.meta.url),
);
const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

async function eventually(check: () => Promise<boolean>, message: string) {
  for (let n = 0; n < 250; n++) {
    if (await check()) return;
    await pause(20);
  }
  assert.fail(message);
}

async function fixture(body: string, operation: string) {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), 'cli-containment-')),
  );
  const python = await realpath(
    process.env.WARDEN_TEST_PYTHON ?? '/usr/bin/python3',
  );
  const bw = join(root, 'bw');
  const pids = join(root, 'pids.json');
  await writeFile(
    bw,
    `#!${python}\nimport os, sys, json, time, signal\n${body}`,
    { mode: 0o700 },
  );
  const launcher = join(root, 'launch.mjs');
  await writeFile(
    launcher,
    `
import * as cli from ${JSON.stringify(moduleUrl)};
import {writeFile} from 'node:fs/promises';
process.env.BW_BIN = ${JSON.stringify(bw)};
process.env.WARDEN_AGENT_SAFE_PROCESS = '1';
// The optional call lets the original implementation demonstrate the leak.
const python = ${JSON.stringify(python)};
await cli.configureBwCliContainment?.(python, ${JSON.stringify(worker)});
const options = {env: {BW_SESSION: 'synthetic-session-only', BW_PASSWORD: 'synthetic-master-only', PID_FILE: ${JSON.stringify(pids)}}, timeoutMs: 120_000};
${operation}
`,
  );
  const child = spawn(process.execPath, [launcher], {
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  let stdout = '',
    stderr = '';
  child.stdout.on('data', (data) => {
    stdout += data;
  });
  child.stderr.on('data', (data) => {
    stderr += data;
  });
  const closed = new Promise<number | null>((resolve) =>
    child.once('close', resolve),
  );
  return {
    root,
    child,
    closed,
    pids,
    output: () => ({ stdout, stderr }),
    async ready(): Promise<{
      cli: number;
      descendant: number;
      supervisor: number;
    }> {
      await eventually(async () => {
        try {
          JSON.parse(await readFile(pids, 'utf8'));
          return true;
        } catch {
          return false;
        }
      }, `fixture never started: ${stderr}`);
      return JSON.parse(await readFile(pids, 'utf8'));
    },
    async cleanup() {
      child.kill('SIGKILL');
      // Only exact fixture PIDs, never host groups or the test runner.
      try {
        const ids = JSON.parse(await readFile(pids, 'utf8'));
        for (const pid of [ids.cli, ids.descendant]) {
          try {
            const env = await readFile(`/proc/${pid}/environ`);
            // The original PID might already have been reaped and reused.
            if (env.includes(Buffer.from(`PID_FILE=${pids}\0`)))
              process.kill(pid, 'SIGKILL');
          } catch {}
        }
      } catch {}
      await closed;
      await rm(root, { recursive: true, force: true });
    },
  };
}

const hangingTree = `
assert os.environ['BW_SESSION'] == 'synthetic-session-only'
assert os.environ['BW_PASSWORD'] == 'synthetic-master-only'
ready_read, ready_write = os.pipe()
pid = os.fork()
if pid == 0:
    os.close(ready_read)
    os.setsid()
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    os.write(ready_write, b'1')
    os.close(ready_write)
    while True: time.sleep(1)
os.close(ready_write)
assert os.read(ready_read, 1) == b'1'
os.close(ready_read)
with open(os.environ['PID_FILE'], 'w') as f:
    json.dump({'cli': os.getpid(), 'descendant': pid, 'supervisor': os.getppid()}, f)
while True: time.sleep(1)
`;

async function absent(pid: number) {
  try {
    await readFile(`/proc/${pid}/stat`);
    return false;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === 'ENOENT';
  }
}

test(
  'invalid supervisor configuration disables execution instead of falling back',
  linux,
  async () => {
    const f = await fixture(
      hangingTree,
      `
try { await cli.configureBwCliContainment(python, options.env.PID_FILE + '/worker.py'); }
catch (error) { console.log(error.message); }
try { await cli.runBw(['status'], options); }
catch (error) { console.log(error.message); }
`,
    );
    try {
      assert.equal(await f.closed, 0, f.output().stderr);
      assert.equal(
        f.output().stdout,
        'agent_safe_cli_containment\nagent_safe_cli_containment\n',
      );
      await assert.rejects(readFile(f.pids), { code: 'ENOENT' });
    } finally {
      await f.cleanup();
    }
  },
);

test(
  'an already-cancelled request never launches a credential-bearing CLI',
  linux,
  async () => {
    const f = await fixture(
      hangingTree,
      `
try { await cli.runBw(['status'], {...options, signal: AbortSignal.abort('untrusted-reason')}); }
catch (error) { console.log(error.name + ': ' + error.message); }
`,
    );
    try {
      assert.equal(await f.closed, 0, f.output().stderr);
      assert.equal(f.output().stdout, 'AbortError: bw command cancelled\n');
      await assert.rejects(readFile(f.pids), { code: 'ENOENT' });
    } finally {
      await f.cleanup();
    }
  },
);

test(
  'Node death while the credential pipe is incomplete reaps the waiting launcher',
  linux,
  async () => {
    const f = await fixture(
      'raise RuntimeError("must not exec")\n',
      `
const {spawn} = await import('node:child_process');
const {readFile} = await import('node:fs/promises');
const supervisor = spawn(python, ['-I', '-B', ${JSON.stringify(fileURLToPath(new URL('../../agent_worker/cli_supervisor.py', import.meta.url)))}, String(process.pid), process.env.BW_BIN], {
  detached: true, env: {}, stdio: ['pipe', 'pipe', 'pipe', 'pipe', 'pipe'],
});
supervisor.stdio[3].on('error', () => {});
supervisor.stdio[3].write('{"BW_SESSION":');
let child;
for (let n = 0; n < 250 && !child; n++) {
  try { child = Number((await readFile('/proc/' + supervisor.pid + '/task/' + supervisor.pid + '/children', 'utf8')).trim()); } catch {}
  if (!child) await new Promise(resolve => setTimeout(resolve, 20));
}
if (!child) throw new Error('supervisor did not fork');
await writeFile(options.env.PID_FILE, JSON.stringify({cli: child, descendant: child, supervisor: supervisor.pid}));
`,
    );
    try {
      const ids = await f.ready();
      assert.equal(await absent(ids.cli), false);
      f.child.kill('SIGKILL');
      await f.closed;
      await eventually(
        () => absent(ids.cli),
        'launcher survived with an incomplete private payload',
      );
    } finally {
      await f.cleanup();
    }
  },
);

test(
  'missing supervisor runtime is not misreported as a missing bw executable',
  linux,
  async () => {
    const f = await fixture(
      'pass\n',
      `
const {copyFile, chmod, unlink} = await import('node:fs/promises');
const copy = options.env.PID_FILE + '.python';
await copyFile(python, copy); await chmod(copy, 0o700);
await cli.configureBwCliContainment(copy, ${JSON.stringify(worker)});
await unlink(copy);
try { await cli.runBw(['status'], options); }
catch (error) { console.log(error.name + ': ' + error.message); }
`,
    );
    try {
      assert.equal(await f.closed, 0, f.output().stderr);
      assert.equal(f.output().stdout, 'Error: agent_safe_cli_containment\n');
      assert.equal(f.output().stderr, '');
    } finally {
      await f.cleanup();
    }
  },
);

test(
  'supervisor exiting without launching a CLI fails closed',
  linux,
  async () => {
    const f = await fixture(
      'pass\n',
      `
const {dirname, join} = await import('node:path');
await writeFile(join(dirname(options.env.PID_FILE), 'cli_supervisor.py'), 'import os; os._exit(0)\\n', {mode: 0o600});
await cli.configureBwCliContainment(python, join(dirname(options.env.PID_FILE), 'worker.py'));
try { await cli.runBw(['status'], options); console.log('unexpected-success'); }
catch (error) { console.log(error.message); }
`,
    );
    try {
      assert.equal(await f.closed, 0, f.output().stderr);
      assert.match(f.output().stdout, /agent_safe_cli_containment/);
    } finally {
      await f.cleanup();
    }
  },
);

test(
  'supervisor has no credential environment, argv, or private-pipe handles',
  linux,
  async () => {
    const f = await fixture(
      hangingTree,
      `await cli.runBw(['status'], options);`,
    );
    try {
      const ids = await f.ready();
      assert.notEqual(ids.supervisor, f.child.pid);
      for (const source of [
        `/proc/${ids.supervisor}/environ`,
        `/proc/${ids.supervisor}/cmdline`,
        `/proc/${ids.cli}/cmdline`,
      ]) {
        const bytes = await readFile(source, 'utf8');
        assert.doesNotMatch(
          bytes,
          /synthetic-session-only|synthetic-master-only|BW_SESSION|BW_PASSWORD/,
        );
      }
      for (const fd of [0, 1, 2]) {
        assert.equal(
          await realpath(`/proc/${ids.supervisor}/fd/${fd}`),
          '/dev/null',
        );
      }
      for (const pid of [ids.supervisor, ids.cli]) {
        for (const fd of [3, 4]) {
          await assert.rejects(realpath(`/proc/${pid}/fd/${fd}`), {
            code: 'ENOENT',
          });
        }
      }
    } finally {
      await f.cleanup();
    }
  },
);

for (const code of [0, 7, 127, 143]) {
  test(
    `supervised CLI preserves streams and exit ${code}, reaping leftover descendants`,
    linux,
    async () => {
      const ending =
        `\ndata = sys.stdin.buffer.read()\nos.write(1, data)\nos.write(2, b'private-stderr')\n` +
        (code === 143
          ? 'os.kill(os.getpid(), signal.SIGTERM)\n'
          : `sys.exit(${code})\n`);
      const f = await fixture(
        hangingTree.replace(/while True: time.sleep\(1\)\n$/, ending),
        `
try {
  const result = await cli.runBw(['status'], {...options, stdin: 'private-stdin'});
  console.log(JSON.stringify({code: 0, stdout: result.stdout, stderr: result.stderr, bytes: result.stdoutBuffer.toString()}));
} catch (error) {
  console.log(JSON.stringify({code: error.exitCode, stdout: error.stdout, stderr: error.stderr}));
}
`,
      );
      try {
        assert.equal(await f.closed, 0, f.output().stderr);
        const result = JSON.parse(f.output().stdout);
        assert.equal(result.code, code);
        assert.equal(result.stdout, 'private-stdin');
        assert.equal(result.stderr, 'private-stderr');
        if (code === 0) assert.equal(result.bytes, 'private-stdin');
        const ids = await f.ready();
        assert.equal(await absent(ids.cli), true);
        assert.equal(await absent(ids.descendant), true);
      } finally {
        await f.cleanup();
      }
    },
  );
}

test(
  'early stdin close is handled without an unhandled pipe error',
  linux,
  async () => {
    const f = await fixture(
      'os.close(0)\nsys.exit(23)\n',
      `
try { await cli.runBw(['status'], {...options, stdin: 'private-input'.repeat(100000)}); }
catch (error) { console.log(JSON.stringify({type: error.constructor.name, code: error.exitCode})); }
`,
    );
    try {
      assert.equal(await f.closed, 0, f.output().stderr);
      assert.deepEqual(JSON.parse(f.output().stdout), {
        type: 'BwCliError',
        code: 23,
      });
      assert.equal(f.output().stderr, '');
    } finally {
      await f.cleanup();
    }
  },
);

test(
  'supervised exec failure preserves missing-binary error semantics',
  linux,
  async () => {
    const f = await fixture(
      'pass\n',
      `
process.env.BW_BIN += '.missing';
try { await cli.runBw(['status'], options); }
catch (error) { console.log(error.constructor.name + ': ' + error.message); }
`,
    );
    try {
      assert.equal(await f.closed, 0, f.output().stderr);
      assert.match(
        f.output().stdout,
        /^Error: bw CLI not available.*Install @bitwarden\/cli.*BW_BIN/s,
      );
    } finally {
      await f.cleanup();
    }
  },
);

test(
  'MCP request cancellation reaches CLI calls through session/auth layers',
  linux,
  async () => {
    const f = await fixture(
      hangingTree,
      `
import {Client} from ${JSON.stringify(import.meta.resolve('@modelcontextprotocol/sdk/client/index.js'))};
import {McpServer} from ${JSON.stringify(import.meta.resolve('@modelcontextprotocol/sdk/server/mcp.js'))};
import {InMemoryTransport} from ${JSON.stringify(import.meta.resolve('@modelcontextprotocol/sdk/inMemory.js'))};
import {registerAgentTools} from ${JSON.stringify(new URL('./server.js', import.meta.url).href)};
const server = new McpServer({name: 'test', version: 'test'});
registerAgentTools(server, {async invoke() {
  try { await cli.runBw(['status'], options); return {}; }
  catch (error) { await writeFile(options.env.PID_FILE + '.result', error.name); throw error; }
}});
const client = new Client({name: 'test', version: 'test'});
const [a, b] = InMemoryTransport.createLinkedPair();
await server.connect(a); await client.connect(b);
const controller = new AbortController();
process.stdin.once('data', () => controller.abort());
try { await client.callTool({name: 'sync', arguments: {}}, undefined, {signal: controller.signal}); } catch {}
await client.close(); await server.close(); process.stdin.destroy();
`,
    );
    try {
      const ids = await f.ready();
      f.child.stdin.write('cancel');
      await eventually(async () => {
        try {
          return (await readFile(`${f.pids}.result`, 'utf8')) === 'AbortError';
        } catch {
          return false;
        }
      }, 'MCP cancellation did not reach the active CLI');
      assert.equal(await absent(ids.cli), true);
      assert.equal(await absent(ids.descendant), true);
    } finally {
      await f.cleanup();
    }
  },
);

test(
  'cancellation waits for the detached CLI tree to be killed and reaped',
  linux,
  async () => {
    const f = await fixture(
      hangingTree,
      `
const controller = new AbortController();
setTimeout(() => controller.abort(), 500);
try { await cli.runBw(['status'], {...options, signal: controller.signal}); }
catch (error) { await writeFile(options.env.PID_FILE + '.result', error.name + ': ' + error.message); }
`,
    );
    try {
      const ids = await f.ready();
      await eventually(async () => {
        try {
          return (await readFile(`${f.pids}.result`)).length > 0;
        } catch {
          return false;
        }
      }, 'cancellation never settled');
      assert.match(
        await readFile(`${f.pids}.result`, 'utf8'),
        /^AbortError: bw command cancelled$/,
      );
      assert.equal(await absent(ids.cli), true);
      assert.equal(await absent(ids.descendant), true);
    } finally {
      await f.cleanup();
    }
  },
);

test(
  'timeout waits for the detached CLI tree to be killed and reaped',
  linux,
  async () => {
    const f = await fixture(
      hangingTree,
      `
try { await cli.runBw(['status'], {...options, timeoutMs: 500}); }
catch (error) { await writeFile(options.env.PID_FILE + '.result', error.message); }
`,
    );
    try {
      const ids = await f.ready();
      await eventually(async () => {
        try {
          return (await readFile(`${f.pids}.result`)).length > 0;
        } catch {
          return false;
        }
      }, 'timeout never settled');
      assert.match(
        await readFile(`${f.pids}.result`, 'utf8'),
        /timed out after 500ms/,
      );
      assert.equal(
        await absent(ids.cli),
        true,
        'CLI survived timeout settlement',
      );
      assert.equal(
        await absent(ids.descendant),
        true,
        'detached descendant survived timeout settlement',
      );
    } finally {
      await f.cleanup();
    }
  },
);

test(
  'agent-safe CLI and detached descendants are reaped after Node SIGKILL',
  linux,
  async () => {
    const f = await fixture(
      hangingTree,
      `await cli.runBw(['status'], options);`,
    );
    try {
      const ids = await f.ready();
      f.child.kill('SIGKILL');
      await f.closed;
      await eventually(
        async () => (await absent(ids.cli)) && (await absent(ids.descendant)),
        'credential-bearing CLI tree survived Node SIGKILL',
      );
    } finally {
      await f.cleanup();
    }
  },
);
