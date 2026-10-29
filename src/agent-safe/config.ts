import { constants } from 'node:fs';
import { access, lstat, readFile, realpath } from 'node:fs/promises';
import { isAbsolute, join, normalize } from 'node:path';

export interface AgentConfig {
  server: string;
  bw: string;
  python: string;
  worker: string;
  credential_socket?: string;
  browser_executable?: string;
}

export async function loadAgentConfig(
  root: string,
  platform: NodeJS.Platform = process.platform,
): Promise<AgentConfig> {
  try {
    if (platform !== 'linux' && platform !== 'win32') throw new Error();
    const checkPath = async (
      path: unknown,
      directory = false,
      privateMode = false,
      executable = false,
    ) => {
      if (
        typeof path !== 'string' ||
        !isAbsolute(path) ||
        normalize(path) !== path ||
        (await realpath(path)) !== path
      )
        throw new Error();
      const info = await lstat(path);
      if (directory ? !info.isDirectory() : !info.isFile()) throw new Error();
      if (platform === 'linux') {
        if (
          privateMode &&
          (info.uid !== process.getuid?.() ||
            (info.mode & 0o777) !== (directory ? 0o700 : 0o600))
        )
          throw new Error();
        if ((info.mode & 0o022) !== 0 || (info.mode & 0o444) === 0)
          throw new Error();
        await access(
          path,
          constants.R_OK | (executable || directory ? constants.X_OK : 0),
        );
      }
    };
    await checkPath(root, true, true);
    await checkPath(join(root, 'config.json'), false, true);
    const value: unknown = JSON.parse(
      await readFile(join(root, 'config.json'), 'utf8'),
    );
    if (!value || typeof value !== 'object' || Array.isArray(value))
      throw new Error();
    const config = value as AgentConfig;
    const keys = new Set([
      'server',
      'bw',
      'python',
      'worker',
      'credential_socket',
      'browser_executable',
    ]);
    if (Object.keys(config).some((key) => !keys.has(key))) throw new Error();
    if (typeof config.server !== 'string' || /[\s?#\\\\]/.test(config.server))
      throw new Error();
    const url = new URL(config.server);
    if (
      url.protocol !== 'https:' ||
      url.username ||
      url.password ||
      !url.hostname
    )
      throw new Error();
    await checkPath(config.bw, false, false, true);
    await checkPath(config.python, false, false, true);
    await checkPath(config.worker);
    if (/(^|[\\/])node_modules([\\/]|$)/i.test(config.bw)) throw new Error();
    if (config.browser_executable !== undefined)
      await checkPath(config.browser_executable, false, false, true);
    if (config.credential_socket !== undefined) {
      if (
        platform !== 'linux' ||
        config.credential_socket !==
          '/run/warden-hermes-credentials/credentials.sock'
      )
        throw new Error();
      const socket = await lstat(config.credential_socket);
      const parent = await lstat('/run/warden-hermes-credentials');
      if (
        (await realpath(config.credential_socket)) !==
          config.credential_socket ||
        !socket.isSocket() ||
        socket.uid !== 0 ||
        (socket.mode & 0o007) !== 0 ||
        !parent.isDirectory() ||
        parent.uid !== 0 ||
        (parent.mode & 0o022) !== 0
      )
        throw new Error();
    }
    if (platform === 'linux') {
      for (const [name, directory] of [
        ['state', true],
        ['state/cli', true],
        ['logs', true],
        ['access.json', false],
      ] as const) {
        const path = join(root, name);
        const exists = await lstat(path).then(
          () => true,
          (error) => {
            if (error.code === 'ENOENT') return false;
            throw error;
          },
        );
        if (exists) await checkPath(path, directory, true);
      }
    }
    return config;
  } catch {
    throw new Error('agent_safe_config');
  }
}
