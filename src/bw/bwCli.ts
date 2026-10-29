// src/bw/bwCli.ts

import { AsyncLocalStorage } from 'node:async_hooks';
import { type ChildProcessWithoutNullStreams, spawn } from 'node:child_process';
import { constants } from 'node:fs';
import { access, lstat, realpath } from 'node:fs/promises';
import { dirname, isAbsolute, join, normalize } from 'node:path';
import type { Readable, Writable } from 'node:stream';
import { childEnvironment } from '../agent-safe/privateWorker.js';
import { renderSafeBwCommand } from './bwCommandDisplay.js';
import { resolveBundledBwBin } from './resolveBwBin.js';

let containment: { python: string; script: string } | undefined;
const cancellation = new AsyncLocalStorage<AbortSignal>();

/** Carry MCP cancellation through SDK/auth calls without global cross-talk. */
export function withBwCancellation<T>(
  signal: AbortSignal,
  operation: () => T,
): T {
  return cancellation.run(signal, operation);
}

/** Configure only from the validated local agent config, never from tool input. */
export async function configureBwCliContainment(
  python: string,
  worker: string,
): Promise<void> {
  containment = undefined;
  if (process.platform !== 'linux') return;
  const script = join(dirname(worker), 'cli_supervisor.py');
  try {
    for (const path of [python, script]) {
      if (
        !isAbsolute(path) ||
        normalize(path) !== path ||
        (await realpath(path)) !== path
      )
        throw new Error();
      const info = await lstat(path);
      if (!info.isFile() || (info.mode & 0o022) !== 0) throw new Error();
      await access(
        path,
        constants.R_OK | (path === python ? constants.X_OK : 0),
      );
    }
    containment = { python, script };
  } catch {
    throw new Error('agent_safe_cli_containment');
  }
}

export interface BwRunOptions {
  env?: NodeJS.ProcessEnv;
  stdin?: string;
  timeoutMs?: number;
  noInteraction?: boolean;
  signal?: AbortSignal;
}

export interface BwRunResult {
  stdout: string;
  stdoutBuffer?: Buffer;
  stderr: string;
}

type BwCliDiagnosticCode = 'VAULTWARDEN_POLICY_REVISION_DATE';

export class BwCliError extends Error {
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
  readonly diagnosticCode: BwCliDiagnosticCode | null;

  constructor(
    message: string,
    opts: {
      exitCode: number;
      stdout: string;
      stderr: string;
      diagnosticCode?: BwCliDiagnosticCode;
    },
  ) {
    super(message);
    this.name = 'BwCliError';
    this.exitCode = opts.exitCode;
    this.stdout = opts.stdout;
    this.stderr = opts.stderr;
    Object.defineProperties(this, {
      stdout: { enumerable: false },
      stderr: { enumerable: false },
    });
    this.diagnosticCode = opts.diagnosticCode ?? null;
  }
}

function diagnoseBwCliFailure(stderr: string): BwCliDiagnosticCode | null {
  if (
    stderr.includes(
      'Error getting vault timeout: RangeError: Invalid time value',
    ) &&
    stderr.includes('no elements in sequence')
  ) {
    return 'VAULTWARDEN_POLICY_REVISION_DATE';
  }
  return null;
}

export function isBwAuthSessionInvalidError(error: unknown): boolean {
  if (!(error instanceof BwCliError)) return false;

  const combined = [error.stderr, error.stdout, error.message]
    .join('\n')
    .toLowerCase();

  if (
    /not found/.test(combined) ||
    /more than one result/.test(combined) ||
    /multiple results/.test(combined) ||
    /ambiguous/.test(combined) ||
    /invalid search/.test(combined) ||
    /could not connect/.test(combined) ||
    /connection/.test(combined) ||
    /network/.test(combined) ||
    /timeout/.test(combined) ||
    /timed out/.test(combined) ||
    /server error/.test(combined)
  ) {
    return false;
  }

  return (
    /invalid\s+(bw\s+)?session/.test(combined) ||
    /(bw\s+)?session\s+(is\s+)?invalid/.test(combined) ||
    /expired\s+(bw\s+)?session/.test(combined) ||
    /(bw\s+)?session\s+(has\s+)?expired/.test(combined) ||
    /not logged in/.test(combined) ||
    /not authenticated/.test(combined) ||
    /you are not authenticated/.test(combined) ||
    /vault is locked/.test(combined) ||
    /please unlock/.test(combined) ||
    /unlock your vault/.test(combined) ||
    /requires an unlocked vault/.test(combined)
  );
}

export async function runBw(
  args: string[],
  opts: BwRunOptions = {},
): Promise<BwRunResult> {
  const signal = opts.signal ?? cancellation.getStore();
  const cancelled = () =>
    new DOMException('bw command cancelled', 'AbortError');
  if (signal?.aborted) throw cancelled();
  const bwBin = process.env.BW_BIN ?? resolveBundledBwBin() ?? 'bw';
  // Ensure the CLI never blocks waiting for a prompt (e.g. master password).
  // This is critical for running as an MCP server / in test automation.
  const injectNoInteraction = opts.noInteraction ?? true;
  const finalArgs =
    injectNoInteraction && !args.includes('--nointeraction')
      ? ['--nointeraction', ...args]
      : args;
  const safeMode = process.env.WARDEN_AGENT_SAFE_PROCESS === '1';
  const env: NodeJS.ProcessEnv = {
    ...(safeMode ? childEnvironment() : process.env),
    ...(opts.env ?? {}),
  };
  const debug =
    !safeMode &&
    (process.env.KEYCHAIN_DEBUG_BW ?? 'false').toLowerCase() === 'true';
  const startedAt = Date.now();

  if (debug) {
    console.log(`[bw] start: ${renderSafeBwCommand(bwBin, finalArgs)}`);
  }

  const supervised = safeMode && process.platform === 'linux';
  const supervisor = supervised ? containment : undefined;
  if (supervised && !supervisor) throw new Error('agent_safe_cli_containment');
  const detached = process.platform !== 'win32';
  const child = spawn(
    supervisor ? supervisor.python : bwBin,
    supervisor
      ? [
          '-I',
          '-B',
          supervisor.script,
          String(process.pid),
          bwBin,
          ...finalArgs,
        ]
      : finalArgs,
    {
      env: supervised ? childEnvironment() : env,
      stdio: supervised
        ? ['pipe', 'pipe', 'pipe', 'pipe', 'pipe']
        : ['pipe', 'pipe', 'pipe'],
      detached,
      windowsHide: true,
    },
  ) as ChildProcessWithoutNullStreams;
  let supervisorStatus = '';
  if (supervised) {
    (child.stdio[4] as Readable).on('data', (data: Buffer) => {
      supervisorStatus = (supervisorStatus + data.toString('ascii')).slice(
        0,
        128,
      );
    });
    const secretPipe = child.stdio[3] as Writable;
    secretPipe.on('error', () => {});
    secretPipe.end(JSON.stringify(env));
  }

  const stdoutChunks: Buffer[] = [];
  const stderrChunks: Buffer[] = [];

  child.stdout.on('data', (d: Buffer) => stdoutChunks.push(d));
  child.stderr.on('data', (d: Buffer) => stderrChunks.push(d));

  // A CLI may reject/close stdin before consuming it. Preserve its actual exit
  // status rather than allowing EPIPE to crash the credential-owning parent.
  child.stdin.on('error', () => {});
  if (opts.stdin !== undefined) {
    child.stdin.write(opts.stdin);
  }
  child.stdin.end();

  const timeoutMs = opts.timeoutMs ?? 60_000;

  const killChildProcessTree = () => {
    if (supervised) {
      // Keep the subreaper alive until it has killed and reaped the CLI tree.
      child.kill('SIGTERM');
      return;
    }
    if (typeof child.pid === 'number' && detached) {
      try {
        process.kill(-child.pid, 'SIGKILL');
        return;
      } catch (error) {
        if (!(error instanceof Error)) throw error;
        // Fallback to direct child kill below.
      }
    }

    try {
      child.kill('SIGKILL');
    } catch (error) {
      if (!(error instanceof Error)) throw error;
      // ignore
    }
  };

  return new Promise<BwRunResult>((resolve, reject) => {
    let settled = false;
    let terminationError: Error | undefined;
    const settle = (fn: () => void) => {
      if (settled) return;
      settled = true;
      if (timeout) clearTimeout(timeout);
      signal?.removeEventListener('abort', abort);
      fn();
    };

    const abort = () => {
      if (settled || terminationError) return;
      terminationError = cancelled();
      killChildProcessTree();
      if (!supervised) settle(() => reject(terminationError));
    };

    const timeout = setTimeout(() => {
      if (terminationError) return;
      terminationError = new Error(`bw command timed out after ${timeoutMs}ms`);
      killChildProcessTree();
      if (debug) {
        console.log(`[bw] timeout after ${timeoutMs}ms`);
      }
      if (!supervised) settle(() => reject(terminationError));
    }, timeoutMs);

    child.on('error', (error: NodeJS.ErrnoException) => {
      settle(() => {
        if (supervised) {
          reject(new Error('agent_safe_cli_containment'));
          return;
        }
        const safeCmd = renderSafeBwCommand(bwBin, finalArgs);
        if (error.code === 'ENOENT') {
          reject(
            new Error(
              `bw CLI not available for ${safeCmd}. Install @bitwarden/cli or set BW_BIN to a valid bw binary.`,
            ),
          );
          return;
        }
        reject(new Error(`Failed to start ${safeCmd}: ${error.message}`));
      });
    });
    child.on('close', (code) => {
      settle(() => {
        if (terminationError) {
          reject(terminationError);
          return;
        }
        if (supervised && supervisorStatus !== 'READY\n') {
          const safeCmd = renderSafeBwCommand(bwBin, finalArgs);
          reject(
            new Error(
              supervisorStatus === 'READY\nENOENT\n'
                ? `bw CLI not available for ${safeCmd}. Install @bitwarden/cli or set BW_BIN to a valid bw binary.`
                : `Failed to start ${safeCmd}: agent_safe_cli_containment`,
            ),
          );
          return;
        }
        const stdout = Buffer.concat(stdoutChunks).toString('utf8');
        const stderr = Buffer.concat(stderrChunks).toString('utf8');
        const exitCode = code ?? 1;
        if (exitCode !== 0) {
          if (debug) {
            console.log(
              `[bw] fail: exit=${exitCode} ms=${Date.now() - startedAt}`,
            );
          }
          const safeCmd = renderSafeBwCommand(bwBin, finalArgs);
          const diagnosticCode = diagnoseBwCliFailure(stderr);
          const diagnostic = diagnosticCode
            ? ` [${diagnosticCode}: Vaultwarden policy data is missing revisionDate]`
            : '';
          reject(
            new BwCliError(
              `${safeCmd} failed with exit code ${exitCode}${diagnostic}`,
              {
                exitCode,
                stdout,
                stderr,
                ...(diagnosticCode ? { diagnosticCode } : {}),
              },
            ),
          );
          return;
        }
        if (debug) {
          console.log(`[bw] ok: ms=${Date.now() - startedAt}`);
        }
        resolve({ stdout, stdoutBuffer: Buffer.concat(stdoutChunks), stderr });
      });
    });
    signal?.addEventListener('abort', abort, { once: true });
    if (signal?.aborted) abort();
  });
}
