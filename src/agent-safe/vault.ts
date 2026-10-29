import { randomUUID } from 'node:crypto';
import { type BigIntStats, constants, statSync } from 'node:fs';
import {
  chmod,
  mkdir,
  open,
  readdir,
  rename,
  stat,
  unlink,
  writeFile,
} from 'node:fs/promises';
import { join } from 'node:path';
import { BwSessionManager } from '../bw/bwSession.js';
import { Mutex } from '../bw/mutex.js';
import { KeychainSdk } from '../sdk/keychainSdk.js';
import type { AgentConfig } from './config.js';
import { metadata, record, SecretFilter } from './filter.js';
import { PrivateWorker, SafeError } from './privateWorker.js';

export type { AgentConfig } from './config.js';
export const ID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const ACTIONS = new Set([
  'status',
  'search',
  'sync',
  'browser_open',
  'browser_state',
  'browser_fill_login',
  'browser_fill_totp',
  'browser_action',
  'mysql_query',
  'ssh_exec',
  'browser_close',
  'pause_access',
]);

const SAFE_CODES = new Set([
  'action',
  'browser_failed',
  'browser_timeout',
  'command',
  'credential_store',
  'disabled',
  'form_origin',
  'host_required',
  'https_required',
  'item',
  'key',
  'login_required',
  'mysql_failed',
  'not_allowed',
  'origin_denied',
  'otp_field',
  'output_limit',
  'page',
  'password_field',
  'password_missing',
  'port',
  'readonly_sql',
  'ref',
  'ssh_failed',
  'ssh_host_key',
  'ssh_timeout',
  'target',
  'text_limit',
  'totp',
  'unsupported',
  'use_secret_fill',
  'vault_ui_denied',
  'worker_failed',
  'worker_containment',
]);

export class AgentVault {
  readonly filter = new SecretFilter();
  readonly worker: PrivateWorker;
  private readonly bw: BwSessionManager;
  private readonly sdk: KeychainSdk;
  private readonly lock = new Mutex();
  private readonly pages = new Map<string, string>();
  private timer: NodeJS.Timeout | undefined;
  private policyTimer: NodeJS.Timeout | undefined;
  private lastSync = 0;
  private paused = false;
  private generation = 0;
  private pausePending = 0;
  private pauseRevision: string | undefined;
  constructor(
    readonly root: string,
    readonly config: AgentConfig,
    private readonly idleMs = 600_000,
  ) {
    this.worker = new PrivateWorker(config.python, config.worker, root);
    this.bw = new BwSessionManager({
      host: config.server,
      password: '',
      login: { method: 'userpass', user: 'agent-safe' },
      unlockIntervalSeconds: 600,
      homeDir: join(root, 'state', 'cli'),
      persistSession: false,
      onSecret: (value) => this.filter.add(value),
      credentialProvider: async () => {
        await this.enabled();
        const auth = record(await this.worker.call('credentials'));
        if (
          auth.server !== config.server ||
          typeof auth.master !== 'string' ||
          typeof auth.email !== 'string'
        )
          throw new SafeError('credential_store');
        this.filter.add(auth.master, auth.client_secret);
        return {
          password: auth.master,
          login:
            typeof auth.client_id === 'string' &&
            auth.client_id &&
            typeof auth.client_secret === 'string' &&
            auth.client_secret
              ? {
                  method: 'apikey' as const,
                  clientId: auth.client_id,
                  clientSecret: auth.client_secret,
                }
              : { method: 'userpass' as const, user: auth.email },
        };
      },
    });
    this.sdk = new KeychainSdk(this.bw);
  }
  async policy(): Promise<Record<string, unknown>> {
    const pending = this.pausePending;
    const generation = this.generation;
    try {
      const file = await open(join(this.root, 'access.json'), 'r');
      try {
        const revision = this.revision(await file.stat({ bigint: true }));
        const policy = record(JSON.parse(await file.readFile('utf8')));
        // Only a later local write may release a failed-persistence latch.
        // An unchanged enabled file is not evidence of local consent.
        if (
          this.paused &&
          !pending &&
          !this.pausePending &&
          generation === this.generation &&
          this.pauseRevision !== undefined &&
          revision !== this.pauseRevision &&
          policy.enabled === true
        )
          this.paused = false;
        return policy;
      } finally {
        await file.close();
      }
    } catch {
      return { enabled: false };
    }
  }
  private revision(info: BigIntStats): string {
    // Local management resumes by atomic replacement. Metadata-only changes to
    // an old enabled file must not count as consent after a failed pause write.
    return `${info.dev}:${info.ino}:${info.birthtimeNs}`;
  }
  async enabled(itemId?: string, generation = this.generation): Promise<void> {
    const p = await this.policy();
    if (generation !== this.generation || this.paused || p.enabled !== true)
      throw new SafeError('disabled');
    if (
      itemId &&
      (!ID.test(itemId) ||
        (p.allow_all !== true &&
          !(Array.isArray(p.items) && p.items.includes(itemId))))
    )
      throw new SafeError('not_allowed');
  }
  private async item(itemId: string): Promise<unknown> {
    await this.enabled(itemId);
    const item = await this.sdk.getItem(itemId, { reveal: true });
    if (record(item).id !== itemId) throw new SafeError('item');
    this.filter.item(item);
    return item;
  }
  private touch(): void {
    this.watchPolicy();
    if (this.timer) clearTimeout(this.timer);
    this.timer = setTimeout(() => {
      void this.lock.runExclusive(() => this.revoke()).catch(() => {});
    }, this.idleMs);
    this.timer.unref();
  }
  private watchPolicy(): void {
    if (this.policyTimer) return;
    const timer = setTimeout(() => {
      void this.enabled()
        .catch(() => {
          // A poll already reading when revoke ran no longer owns cleanup.
          if (this.policyTimer === timer) return this.revoke();
        })
        .catch(() => {})
        .finally(() => {
          if (this.policyTimer !== timer) return;
          this.policyTimer = undefined;
          this.watchPolicy();
        });
    }, 100);
    this.policyTimer = timer;
    timer.unref();
  }
  async revoke(): Promise<void> {
    this.generation++;
    if (this.policyTimer) clearTimeout(this.policyTimer);
    this.policyTimer = undefined;
    if (this.timer) clearTimeout(this.timer);
    this.timer = undefined;
    this.pages.clear();
    // Containment tears down browser descendants with their private worker.
    // Never start a new worker merely to close an already revoked session.
    this.worker.stop();
    await this.bw.revoke();
  }
  async invoke(
    action: string,
    args: Record<string, unknown>,
    signal?: AbortSignal,
  ): Promise<Record<string, unknown>> {
    if (!ACTIONS.has(action))
      return {
        ok: false,
        error: 'unsupported',
        message: 'Local operation unavailable.',
      };
    // The flag takes effect even if another operation is already in flight.
    if (action === 'pause_access') {
      this.paused = true;
      this.generation++;
      this.pausePending++;
      try {
        this.pauseRevision = this.revision(
          statSync(join(this.root, 'access.json'), { bigint: true }),
        );
      } catch {
        this.pauseRevision = undefined;
      }
      this.worker.stop();
    }
    return this.lock.runExclusive(async () => {
      const generation = this.generation;
      const abort = () => this.worker.stop();
      signal?.addEventListener('abort', abort, { once: true });
      try {
        signal?.throwIfAborted();
        if (action !== 'status' && action !== 'pause_access') {
          await this.enabled();
          this.watchPolicy();
        }
        signal?.throwIfAborted();
        const result = await this.run(action, args, signal, generation);
        signal?.throwIfAborted();
        if (action !== 'status' && action !== 'pause_access')
          await this.enabled(undefined, generation);
        await this.audit(action, 'success', args.item_id);
        return record(this.filter.clean({ ok: true, ...record(result) }));
      } catch (error) {
        const code =
          error instanceof SafeError && SAFE_CODES.has(error.code)
            ? error.code
            : 'operation_failed';
        await this.audit(action, code, args.item_id).catch(() => {});
        return record(
          this.filter.clean({
            ok: false,
            error: code,
            message:
              code === 'disabled'
                ? '接入已暂停，请通过本机管理窗口恢复。'
                : '本机操作未完成；原始错误已隐藏，请检查本机凭据、目标配置或连接。',
          }),
        );
      } finally {
        if (action === 'pause_access') this.pausePending--;
        signal?.removeEventListener('abort', abort);
        if (
          signal?.aborted ||
          (action !== 'pause_access' && generation !== this.generation)
        )
          await this.revoke().catch(() => {});
        else if (action !== 'status' && action !== 'pause_access') this.touch();
      }
    });
  }
  private async run(
    action: string,
    args: Record<string, unknown>,
    signal?: AbortSignal,
    generation = this.generation,
  ): Promise<unknown> {
    if (action === 'status') {
      const p = await this.policy();
      return {
        server: this.config.server,
        credential_enrolled:
          process.platform === 'linux'
            ? await this.worker.call('credential_status').then(
                (value) => record(value).registered === true,
                () => false,
              )
            : await stat(join(this.root, 'state', 'auth.dpapi')).then(
                (info) => info.isFile(),
                () => false,
              ),
        enabled: p.enabled === true && !this.paused,
        access_scope: p.allow_all ? 'all_account_items' : 'selected_items',
        allowed_items: p.allow_all
          ? 'all'
          : Array.isArray(p.items)
            ? p.items.length
            : 0,
        storage:
          process.platform === 'linux'
            ? 'Linux root-managed credential service'
            : 'Windows DPAPI CurrentUser',
        secrets_returned: false,
        cli_version: '2026.9.1',
      };
    }
    if (action === 'pause_access') {
      const p = await this.policy();
      p.enabled = false;
      let persisted = false;
      const temporary = join(this.root, `access-${randomUUID()}.tmp`);
      try {
        await writeFile(temporary, JSON.stringify(p), {
          mode: 0o600,
          flag: 'wx',
        });
        if (process.platform === 'linux') await chmod(temporary, 0o600);
        await rename(temporary, join(this.root, 'access.json'));
        persisted = true;
      } finally {
        await unlink(temporary).catch(() => {});
        // A failed disk write must never leave the current browser/session alive.
        await this.revoke();
        if (persisted) this.paused = false;
      }
      return { enabled: false, resume: '使用本机管理窗口恢复' };
    }
    if (action === 'sync') {
      await this.sdk.sync();
      this.lastSync = Date.now();
      return { synced: true };
    }
    if (action === 'search') {
      if (Date.now() - this.lastSync > 120_000) {
        await this.sdk.sync();
        this.lastSync = Date.now();
      }
      const items = await this.sdk.searchItems({});
      const p = await this.policy();
      // Register every item's secrets before producing any metadata.
      for (const item of items) this.filter.item(item);
      const query = String(args.query ?? '').toLocaleLowerCase();
      const selected = items.filter(
        (item) =>
          (p.allow_all === true ||
            (Array.isArray(p.items) && p.items.includes(record(item).id))) &&
          String(record(item).name ?? '')
            .toLocaleLowerCase()
            .includes(query),
      );
      return { items: selected.map(metadata), count: selected.length };
    }
    if (action === 'browser_close') {
      this.pages.clear();
      return this.worker.call(action);
    }
    const pageId = String(args.page_id ?? '');
    const itemId =
      typeof args.item_id === 'string' ? args.item_id : this.pages.get(pageId);
    if (!itemId) throw new SafeError('page');
    const item = await this.item(itemId);
    let otp: string | undefined;
    if (action === 'browser_fill_totp') {
      const result = await this.sdk.getTotp({ term: itemId }, { reveal: true });
      if (!result.value || !/^\d{6,8}$/.test(result.value))
        throw new SafeError('totp');
      otp = result.value;
      this.filter.add(otp);
    }
    // Recheck policy after asynchronous reads, before using credentials.
    await this.enabled(itemId, generation);
    signal?.throwIfAborted();
    const result = await this.worker.call(action, { args, item, otp });
    await this.enabled(itemId, generation);
    if (action === 'browser_open' && typeof record(result).page_id === 'string')
      this.pages.set(String(record(result).page_id), itemId);
    return result;
  }
  private async audit(
    action: string,
    outcome: string,
    itemId: unknown,
  ): Promise<void> {
    const folder = join(this.root, 'logs'),
      now = new Date();
    await mkdir(folder, { recursive: true, mode: 0o700 });
    const row = {
      time: now.toISOString(),
      action,
      outcome,
      ...(typeof itemId === 'string' && ID.test(itemId)
        ? { item_id: itemId }
        : {}),
    };
    const log = await open(
      join(folder, `audit-${now.toISOString().slice(0, 10)}.jsonl`),
      constants.O_WRONLY |
        constants.O_APPEND |
        constants.O_CREAT |
        (process.platform === 'linux' ? constants.O_NOFOLLOW : 0),
      0o600,
    );
    try {
      const info = await log.stat();
      if (!info.isFile() || info.nlink !== 1)
        throw new SafeError('operation_failed');
      if (process.platform === 'linux') {
        if (info.uid !== process.getuid?.())
          throw new SafeError('operation_failed');
        await log.chmod(0o600);
      }
      await log.appendFile(`${JSON.stringify(this.filter.clean(row))}\n`);
    } finally {
      await log.close();
    }
    for (const name of await readdir(folder))
      if (/^audit-\d{4}-\d{2}-\d{2}\.jsonl$/.test(name)) {
        const path = join(folder, name);
        if (Date.now() - (await stat(path)).mtimeMs > 30 * 86400_000)
          await unlink(path);
      }
  }
}
