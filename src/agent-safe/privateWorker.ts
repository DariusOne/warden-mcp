import { type ChildProcessWithoutNullStreams, spawn } from 'node:child_process';
import { createInterface } from 'node:readline';

export class SafeError extends Error {
  constructor(readonly code: string) {
    super(code);
  }
}

export function childEnvironment(): NodeJS.ProcessEnv {
  const keep = new Set([
    'systemroot',
    'windir',
    'path',
    'temp',
    'tmp',
    'userprofile',
    'appdata',
    'localappdata',
    'home',
    'node_extra_ca_certs',
  ]);
  return Object.fromEntries(
    Object.entries(process.env).filter(([key]) => keep.has(key.toLowerCase())),
  );
}

/** Private protocol. stdout is captured by Node, never forwarded to MCP. */
export class PrivateWorker {
  private child: ChildProcessWithoutNullStreams | undefined;
  private sequence = 0;
  private pending = new Map<
    number,
    {
      resolve: (value: unknown) => void;
      reject: (error: Error) => void;
      timer: NodeJS.Timeout;
      cleanup: () => void;
    }
  >();
  constructor(
    private readonly python: string,
    private readonly script: string,
    private readonly root: string,
  ) {}
  private start(): ChildProcessWithoutNullStreams {
    if (this.child) return this.child;
    const child = spawn(this.python, ['-B', '-u', this.script, this.root], {
      env: {
        ...childEnvironment(),
        PYTHONIOENCODING: 'utf-8',
        PYTHONDONTWRITEBYTECODE: '1',
        WARDEN_PARENT_PID: String(process.pid),
      },
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
      // Linux contain_children turns this leader into a watchdog/subreaper;
      // the actual worker runs in its own session, never Hermes' group.
      detached: process.platform === 'linux',
    });
    this.child = child;
    // Discard raw library diagnostics, including potentially sensitive exceptions.
    child.stderr.on('data', () => {});
    const lines = createInterface({ input: child.stdout });
    lines.on('line', (line) => {
      if (this.child !== child) return;
      try {
        if (line.length > 16 * 1024 * 1024) throw new Error();
        const response = JSON.parse(line);
        const p = this.pending.get(response.id);
        if (!p) return;
        this.pending.delete(response.id);
        clearTimeout(p.timer);
        p.cleanup();
        if (response.ok) p.resolve(response.value);
        else
          p.reject(
            new SafeError(
              typeof response.code === 'string' &&
                /^[a-z_]{1,40}$/.test(response.code)
                ? response.code
                : 'worker_failed',
            ),
          );
        // The browser thread cannot be cancelled safely inside Python. Its
        // timeout must dispose the entire worker, not leave a fill running.
        if (!response.ok && response.code === 'browser_timeout') this.stop();
      } catch {
        this.stop();
      }
    });
    const stopThisChild = () => {
      if (this.child === child) this.stop();
    };
    child.on('error', stopThisChild);
    child.on('exit', stopThisChild);
    child.stdin.on('error', stopThisChild);
    return child;
  }
  async call(
    operation: string,
    payload: unknown = {},
    signal?: AbortSignal,
  ): Promise<unknown> {
    if (signal?.aborted) throw new SafeError('worker_cancelled');
    const child = this.start(),
      id = ++this.sequence;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        if (this.child === child) this.stop();
      }, 75_000);
      const abort = () => {
        if (this.child === child) this.stop();
      };
      const cleanup = () => signal?.removeEventListener('abort', abort);
      this.pending.set(id, { resolve, reject, timer, cleanup });
      signal?.addEventListener('abort', abort, { once: true });
      child.stdin.write(`${JSON.stringify({ id, operation, payload })}\n`);
    });
  }
  stop(): void {
    const child = this.child;
    this.child = undefined;
    // On Linux this signals the watchdog, which SIGKILLs/reaps its worker and
    // adopted descendants. Do not killpg/SIGKILL the watchdog itself: it must
    // survive long enough to reap Chromium's detached process groups.
    // On Windows termination closes the worker's kill-on-close Job Object.
    child?.kill();
    for (const p of this.pending.values()) {
      clearTimeout(p.timer);
      p.cleanup();
      p.reject(new SafeError('worker_failed'));
    }
    this.pending.clear();
  }
}
