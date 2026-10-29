import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { record } from './filter.js';

export const AGENT_VERSION = 'agent-v0.2.0';

export async function buildIdentity(worker: string) {
  let commit: string | null = null;
  try {
    const text = await readFile(
      resolve(dirname(worker), '..', 'BUILD.json'),
      'utf8',
    );
    if (text.length <= 8192) {
      const value = record(JSON.parse(text)).source_commit;
      if (typeof value === 'string' && /^[a-f0-9]{40}$/.test(value))
        commit = value;
    }
  } catch {
    /* Development/fixture builds have no production manifest. */
  }
  return {
    mcp_version: AGENT_VERSION,
    source_commit: commit,
    ssh_trust_mode: 'confirm_once',
  };
}
