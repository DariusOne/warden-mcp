import {
  appendFile,
  mkdir,
  readdir,
  readFile,
  rename,
  stat,
  unlink,
  writeFile,
} from 'node:fs/promises';
import { join } from 'node:path';
import { BwSessionManager } from '../bw/bwSession.js';
import { Mutex } from '../bw/mutex.js';
import { KeychainSdk } from '../sdk/keychainSdk.js';
import { metadata, record, SecretFilter } from './filter.js';
import { PrivateWorker, SafeError } from './privateWorker.js';

export interface AgentConfig {
  server: string;
  bw: string;
  python: string;
  worker: string;
}
export const ID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export class AgentVault {
  readonly filter = new SecretFilter();
  readonly worker: PrivateWorker;
  private readonly bw: BwSessionManager;
  private readonly sdk: KeychainSdk;
  private readonly lock = new Mutex();
  private readonly pages = new Map<string, string>();
  private timer: NodeJS.Timeout | undefined;
  private lastSync = 0;
  private paused = false;
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
    try {
      return record(
        JSON.parse(await readFile(join(this.root, 'access.json'), 'utf8')),
      );
    } catch {
      return { enabled: false };
    }
  }
  async enabled(itemId?: string): Promise<void> {
    const p = await this.policy();
    if (this.paused || p.enabled !== true) throw new SafeError('disabled');
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
    if (this.timer) clearTimeout(this.timer);
    this.timer = setTimeout(() => {
      void this.lock.runExclusive(() => this.revoke()).catch(() => {});
    }, this.idleMs);
    this.timer.unref();
  }
  async revoke(): Promise<void> {
    if (this.timer) clearTimeout(this.timer);
    this.timer = undefined;
    this.pages.clear();
    try {
      await this.worker.call('browser_close');
    } finally {
      this.worker.stop();
      await this.bw.revoke();
    }
  }
  async invoke(
    action: string,
    args: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    // The flag takes effect even if another operation is already in flight.
    if (action === 'pause_access') this.paused = true;
    return this.lock.runExclusive(async () => {
      try {
        if (action !== 'status' && action !== 'pause_access')
          await this.enabled();
        const result = await this.run(action, args);
        if (action !== 'status' && action !== 'pause_access') {
          await this.enabled();
          this.touch();
        }
        await this.audit(action, 'success', args.item_id);
        return record(this.filter.clean({ ok: true, ...record(result) }));
      } catch (error) {
        const code =
          error instanceof SafeError ? error.code : 'operation_failed';
        await this.audit(action, code, args.item_id).catch(() => {});
        return {
          ok: false,
          error: code,
          message:
            code === 'disabled'
              ? '接入已暂停，请通过本机管理窗口恢复。'
              : '本机操作未完成；原始错误已隐藏，请检查本机凭据、目标配置或连接。',
        };
      }
    });
  }
  private async run(
    action: string,
    args: Record<string, unknown>,
  ): Promise<unknown> {
    if (action === 'status') {
      const p = await this.policy();
      return {
        server: this.config.server,
        credential_enrolled: await stat(
          join(this.root, 'state', 'auth.dpapi'),
        ).then(
          () => true,
          () => false,
        ),
        enabled: p.enabled === true && !this.paused,
        access_scope: p.allow_all ? 'all_account_items' : 'selected_items',
        allowed_items: p.allow_all
          ? 'all'
          : Array.isArray(p.items)
            ? p.items.length
            : 0,
        storage: 'Windows DPAPI CurrentUser',
        secrets_returned: false,
        cli_version: '2026.9.1',
      };
    }
    if (action === 'pause_access') {
      const p = await this.policy();
      p.enabled = false;
      await writeFile(join(this.root, 'access.json.tmp'), JSON.stringify(p), {
        mode: 0o600,
      });
      await rename(
        join(this.root, 'access.json.tmp'),
        join(this.root, 'access.json'),
      );
      try {
        await this.revoke();
      } finally {
        this.paused = false;
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
    await this.enabled(itemId);
    const result = await this.worker.call(action, { args, item, otp });
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
    await appendFile(
      join(folder, `audit-${now.toISOString().slice(0, 10)}.jsonl`),
      `${JSON.stringify(row)}\n`,
      { mode: 0o600 },
    );
    for (const name of await readdir(folder))
      if (/^audit-\d{4}-\d{2}-\d{2}\.jsonl$/.test(name)) {
        const path = join(folder, name);
        if (Date.now() - (await stat(path)).mtimeMs > 30 * 86400_000)
          await unlink(path);
      }
  }
}
