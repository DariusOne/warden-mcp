import { createHash } from 'node:crypto';
import { record, type SecretFilter } from './filter.js';

export const HOST_CONFIRMATION_MS = 300_000;
export type HostDecision =
  | 'accept'
  | 'decline'
  | 'cancel'
  | 'timeout'
  | 'unavailable';
export type ConfirmHostKey = (
  message: string,
  signal: AbortSignal,
) => Promise<HostDecision>;
export type HostKeyInfo = {
  host: string;
  port: number;
  key_type: string;
  fingerprint: string;
  public_key: string;
  binding: string;
  previous_fingerprints: string[];
};
const fingerprint = /^SHA256:[A-Za-z0-9+/]{43}$/;
const keyTypes = new Set([
  'ssh-ed25519',
  'ssh-rsa',
  'ecdsa-sha2-nistp256',
  'ecdsa-sha2-nistp384',
  'ecdsa-sha2-nistp521',
]);

/** Validate the private response; never forward the original object or exception. */
export function parseHostKey(value: unknown): HostKeyInfo | undefined {
  const v = record(value);
  if (
    typeof v.host !== 'string' ||
    !/^[A-Za-z0-9._:-]{1,255}$/.test(v.host) ||
    !Number.isInteger(v.port) ||
    Number(v.port) < 1 ||
    Number(v.port) > 65535 ||
    typeof v.key_type !== 'string' ||
    !keyTypes.has(v.key_type) ||
    typeof v.public_key !== 'string' ||
    !/^[A-Za-z0-9+/]{32,16384}={0,2}$/.test(v.public_key) ||
    typeof v.fingerprint !== 'string' ||
    !fingerprint.test(v.fingerprint) ||
    typeof v.binding !== 'string' ||
    !/^[a-f0-9]{64}$/.test(v.binding) ||
    !Array.isArray(v.previous_fingerprints) ||
    v.previous_fingerprints.length > 16 ||
    !v.previous_fingerprints.every(
      (x) => typeof x === 'string' && fingerprint.test(x),
    )
  )
    return undefined;
  const bytes = Buffer.from(v.public_key, 'base64');
  if (
    bytes.toString('base64') !== v.public_key ||
    `SHA256:${createHash('sha256').update(bytes).digest('base64').replace(/=+$/, '')}` !==
      v.fingerprint
  )
    return undefined;
  return {
    host: v.host,
    port: Number(v.port),
    key_type: v.key_type,
    fingerprint: v.fingerprint,
    public_key: v.public_key,
    binding: v.binding,
    previous_fingerprints: [...v.previous_fingerprints] as string[],
  };
}

export function publicHostKey(info: HostKeyInfo): Record<string, unknown> {
  return {
    host: info.host,
    port: info.port,
    key_type: info.key_type,
    fingerprint: info.fingerprint,
    previous_fingerprints: info.previous_fingerprints,
  };
}

export function confirmationMessage(
  info: HostKeyInfo,
  item: unknown,
  filter: SecretFilter,
): string | undefined {
  const summary = publicHostKey(info);
  // Never bypass filtering to make a fingerprint/endpoint readable. An overlap
  // with a real secret makes this confirmation unavailable, not silently wrong.
  if (JSON.stringify(filter.clean(summary)) !== JSON.stringify(summary))
    return undefined;
  const name = filter
    .text(String(record(item).name ?? 'SSH'))
    .replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, ' ')
    .slice(0, 160);
  return [
    '首次信任 SSH 服务器',
    `条目：${name}`,
    `目标：${info.host}:${info.port}`,
    `密钥类型：${info.key_type}`,
    `SHA256 指纹：${info.fingerprint}`,
    '请通过已有可信记录或服务商控制台核对这把公开主机密钥。扫描结果本身不是身份认证。',
    '接受将仅在本机保存这把密钥，并继续本次已授权的 SSH 命令；拒绝则不发送密码、不执行命令。',
    '此确认仅限本次指纹，不是对未来陌生主机的永久批准。',
  ].join('\n');
}

export const SSH_MESSAGES: Record<string, string> = {
  ssh_host_unknown:
    '首次 SSH 连接需要确认具体主机指纹，尚未发送密码或执行命令。',
  ssh_host_changed:
    'SSH 主机密钥变化，连接已阻止；请人工核对新旧指纹，不自动覆盖。',
  ssh_host_conflict: '用户级与 MCP 信任记录存在冲突，连接已阻止。',
  ssh_trust_store: 'SSH 信任记录读取或保存失败，连接已阻止。',
  ssh_confirmation_required:
    '客户端没有可用的指纹确认交互，尚未发送密码或执行命令。',
  ssh_confirmation_denied: '用户拒绝信任这把 SSH 主机密钥，未执行远端命令。',
  ssh_confirmation_cancelled: 'SSH 指纹确认已取消，未执行远端命令。',
  ssh_confirmation_timeout: 'SSH 指纹确认已过期，未执行远端命令。',
  ssh_target_changed: '确认期间 SSH 条目或目标发生变化，连接已阻止。',
  ssh_auth_failed: 'SSH 主机身份校验通过，但账号认证失败；未执行远端命令。',
};
