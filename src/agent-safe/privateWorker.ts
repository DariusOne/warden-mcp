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
      },
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    });
    this.child = child;
    // Discard raw library diagnostics, including potentially sensitive exceptions.
    child.stderr.on('data', () => {});
    const lines = createInterface({ input: child.stdout });
    lines.on('line', (line) => {
      try {
        if (line.length > 16 * 1024 * 1024) throw new Error();
        const response = JSON.parse(line);
        const p = this.pending.get(response.id);
        if (!p) return;
        this.pending.delete(response.id);
        clearTimeout(p.timer);
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
      } catch {
        this.stop();
      }
    });
    child.on('error', () => this.stop());
    child.on('exit', () => {
      if (this.child === child) this.stop();
    });
    child.stdin.on('error', () => this.stop());
    return child;
  }
  async call(operation: string, payload: unknown = {}): Promise<unknown> {
    const child = this.start(),
      id = ++this.sequence;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => this.stop(), 75_000);
      this.pending.set(id, { resolve, reject, timer });
      child.stdin.write(`${JSON.stringify({ id, operation, payload })}\n`);
    });
  }
  stop(): void {
    const child = this.child;
    this.child = undefined;
    child?.kill();
    for (const p of this.pending.values()) {
      clearTimeout(p.timer);
      p.reject(new SafeError('worker_failed'));
    }
    this.pending.clear();
  }
}
