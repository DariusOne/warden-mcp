import { createHash } from 'node:crypto';

export function record(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

const digest = (s: string) => createHash('sha256').update(s).digest('hex');
function isConnectionField(field: Record<string, unknown>): boolean {
  if ((field.type ?? 0) !== 0 || typeof field.value !== 'string') return false;
  const name = String(field.name ?? '')
    .trim()
    .toLocaleLowerCase();
  const value = field.value.trim();
  if (['port', '端口', 'ssh端口', 'mysql端口'].includes(name))
    return (
      /^\d{1,5}$/.test(value) && Number(value) > 0 && Number(value) <= 65535
    );
  if (
    [
      'host',
      'hostname',
      'ip',
      'server',
      '主机',
      '服务器',
      '服务器ip',
      'ip地址',
      '地址',
    ].includes(name)
  )
    return /^[A-Za-z0-9._:\-[\]]{1,255}$/.test(value);
  if (['database', 'dbname', '数据库', '数据库名'].includes(name))
    return /^[A-Za-z0-9_$.-]{1,64}$/.test(value);
  return false;
}
const rolling = (s: string) => {
  let h = 0;
  for (let i = 0; i < s.length; i++)
    h = (Math.imul(h, 31) + s.charCodeAt(i)) >>> 0;
  return h;
};

/** Store fingerprints, not plaintext master passwords or session keys.
 * The rolling hash only prefilters candidates; SHA-256 confirms matches.
 * This handles known values/encodings, not arbitrary remote transformations.
 */
export class SecretFilter {
  private readonly fingerprints = new Map<number, Map<number, Set<string>>>();

  add(...values: unknown[]): void {
    for (const value of values) {
      if (typeof value !== 'string' || !value) continue;
      const bytes = Buffer.from(value);
      const variants = new Set([
        value,
        encodeURIComponent(value),
        JSON.stringify(value).slice(1, -1),
        bytes.toString('base64'),
        bytes.toString('base64url'),
        bytes.toString('hex'),
        value.replace(
          /[&<>"']/g,
          (c) =>
            ({
              '&': '&amp;',
              '<': '&lt;',
              '>': '&gt;',
              '"': '&quot;',
              "'": '&#39;',
            })[c] ?? c,
        ),
      ]);
      for (const text of variants) {
        let lengths = this.fingerprints.get(text.length);
        if (!lengths) {
          lengths = new Map();
          this.fingerprints.set(text.length, lengths);
        }
        const hash = rolling(text);
        let hashes = lengths.get(hash);
        if (!hashes) {
          hashes = new Set();
          lengths.set(hash, hashes);
        }
        hashes.add(digest(text));
      }
    }
  }

  text(value: string): string {
    const ranges: [number, number][] = [];
    for (const [length, hashes] of this.fingerprints) {
      if (length > value.length) continue;
      let power = 1;
      for (let i = 1; i < length; i++) power = Math.imul(power, 31) >>> 0;
      let hash = rolling(value.slice(0, length));
      for (let start = 0; start <= value.length - length; start++) {
        if (hashes.get(hash)?.has(digest(value.slice(start, start + length))))
          ranges.push([start, start + length]);
        if (start < value.length - length)
          hash =
            (Math.imul(
              (hash - Math.imul(value.charCodeAt(start), power)) >>> 0,
              31,
            ) +
              value.charCodeAt(start + length)) >>>
            0;
      }
    }
    ranges.sort((a, b) => a[0] - b[0] || b[1] - a[1]);
    let result = '',
      end = 0;
    for (let i = 0; i < ranges.length; i++) {
      const range = ranges[i];
      if (!range || range[0] < end) continue;
      let stop = range[1];
      while (i + 1 < ranges.length && (ranges[i + 1]?.[0] ?? Infinity) < stop) {
        i++;
        stop = Math.max(stop, ranges[i]?.[1] ?? stop);
      }
      result += `${value.slice(end, range[0])}[REDACTED]`;
      end = stop;
    }
    return result + value.slice(end);
  }

  clean(value: unknown): unknown {
    if (typeof value === 'string') return this.text(value);
    if (Array.isArray(value)) return value.map((v) => this.clean(v));
    if (value && typeof value === 'object')
      return Object.fromEntries(
        Object.entries(value).map(([k, v]) => [this.text(k), this.clean(v)]),
      );
    // Numeric OTP/password echoes must not evade string matching.
    if (typeof value === 'number' && this.text(String(value)) !== String(value))
      return '[REDACTED]';
    return value;
  }

  item(value: unknown): void {
    const item = record(value),
      login = record(item.login);
    this.add(
      login.password,
      login.totp,
      item.notes,
      record(item.sshKey).privateKey,
    );
    for (const f of Array.isArray(item.fields) ? item.fields : []) {
      // Routing metadata is not a secret. Registering a port such as "22"
      // would corrupt unrelated UUIDs and make valid entries unusable.
      if (!isConnectionField(record(f))) this.add(record(f).value);
    }
    for (const h of Array.isArray(item.passwordHistory)
      ? item.passwordHistory
      : [])
      this.add(record(h).password);
    for (const part of ['card', 'identity'])
      this.add(...Object.values(record(item[part])));
    for (const a of Array.isArray(item.attachments) ? item.attachments : [])
      this.add(record(a).url, record(a).key);
    for (const u of Array.isArray(login.uris) ? login.uris : []) {
      try {
        const url = new URL(String(record(u).uri));
        this.add(
          url.username,
          url.password,
          decodeURIComponent(url.username),
          decodeURIComponent(url.password),
          url.hash.slice(1),
        );
        for (const v of url.searchParams.values()) this.add(v);
      } catch {
        /* Malformed URLs are never returned. */
      }
    }
  }
}

export function metadata(value: unknown): Record<string, unknown> {
  const item = record(value),
    login = record(item.login);
  const origins: string[] = [];
  for (const u of Array.isArray(login.uris) ? login.uris : []) {
    try {
      if (record(u).match === 5) continue;
      const url = new URL(String(record(u).uri));
      if (!['http:', 'https:'].includes(url.protocol)) continue;
      origins.push(
        `${url.protocol}//${url.hostname}:${url.port || (url.protocol === 'https:' ? 443 : 80)}`,
      );
    } catch {
      /* Omit invalid origins. */
    }
  }
  return {
    id: item.id,
    name: item.name ?? '',
    type: item.type,
    username: login.username ?? null,
    website_origins: origins,
    has_password: Boolean(login.password),
    has_totp: Boolean(login.totp),
  };
}
