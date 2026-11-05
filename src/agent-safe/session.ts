import { join } from 'node:path';
import type { BwRunOptions, BwRunResult } from '../bw/bwCli.js';
import {
  BwCredentialError,
  type BwEnv,
  type BwSessionConfig,
  BwSessionManager,
} from '../bw/bwSession.js';
import { Mutex } from '../bw/mutex.js';
import type { KeychainSession } from '../sdk/keychainSdk.js';
import { record, type SecretFilter } from './filter.js';
import { type PrivateWorker, SafeError } from './privateWorker.js';

/** No credentials are loaded until an authorized vault operation needs them. */
export class AgentSession implements KeychainSession {
  private readonly lock = new Mutex();
  private manager: BwSessionManager | undefined;
  private generation = 0;

  constructor(
    private readonly root: string,
    private readonly server: string,
    private readonly worker: PrivateWorker,
    private readonly filter: SecretFilter,
    private readonly enabled: () => Promise<void>,
  ) {}

  private async check(generation: number): Promise<void> {
    await this.enabled();
    if (generation !== this.generation) throw new SafeError('disabled');
  }

  private async initialize(generation: number): Promise<BwSessionManager> {
    await this.check(generation);
    if (this.manager) return this.manager;
    const identity = record(await this.worker.call('credential_identity'));
    await this.check(generation);
    const login = record(identity.login);
    if (
      identity.server !== this.server ||
      !(login.method === 'apikey'
        ? typeof login.clientId === 'string' && login.clientId.length > 0
        : login.method === 'userpass' &&
          typeof login.user === 'string' &&
          login.user.length > 0)
    )
      throw new SafeError('credential_store');
    const config: BwSessionConfig = {
      host: this.server,
      login:
        login.method === 'apikey'
          ? { method: 'apikey', clientId: String(login.clientId) }
          : { method: 'userpass', user: String(login.user) },
      homeDir: join(this.root, 'state', 'cli'),
      unlockIntervalSeconds: 600,
    };
    this.manager = new BwSessionManager(config, {
      persistSession: false,
      onSecret: (value) => this.filter.add(value),
      credentialProvider: async (): Promise<BwEnv> => {
        await this.check(generation);
        const auth = record(await this.worker.call('credentials'));
        await this.check(generation);
        this.filter.add(auth.master, auth.client_secret);
        if (
          auth.server !== config.host ||
          typeof auth.master !== 'string' ||
          typeof auth.email !== 'string'
        )
          throw new SafeError('credential_store');
        return {
          ...config,
          password: auth.master,
          login:
            typeof auth.client_id === 'string' &&
            auth.client_id &&
            typeof auth.client_secret === 'string' &&
            auth.client_secret
              ? {
                  method: 'apikey',
                  clientId: auth.client_id,
                  clientSecret: auth.client_secret,
                }
              : { method: 'userpass', user: auth.email },
        };
      },
    });
    return this.manager;
  }

  async withSession<T>(fn: (session: string) => Promise<T>): Promise<T> {
    const generation = this.generation;
    return this.lock.runExclusive(async () => {
      try {
        const manager = await this.initialize(generation);
        return await manager.withSession(async (session) => {
          await this.check(generation);
          return fn(session);
        });
      } catch (error) {
        await this.check(generation);
        if (error instanceof BwCredentialError)
          throw new SafeError('credential_store');
        throw error;
      }
    });
  }

  private current(): BwSessionManager {
    if (!this.manager) throw new SafeError('login_required');
    return this.manager;
  }

  runForSession(
    session: string,
    args: string[],
    opts?: BwRunOptions,
  ): Promise<BwRunResult> {
    return this.current().runForSession(session, args, opts);
  }

  getTemplateItemForSession(session: string): Promise<unknown> {
    return this.current().getTemplateItemForSession(session);
  }

  async status(): Promise<unknown> {
    return this.lock.runExclusive(() => this.current().status());
  }

  async revoke(): Promise<void> {
    this.generation++;
    await this.lock.runExclusive(async () => {
      try {
        await this.manager?.revoke();
      } catch {
        throw new SafeError('session_cleanup');
      } finally {
        this.manager = undefined;
      }
    });
  }
}
