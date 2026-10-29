# Linux agent-safe deployment and rollback

This branch starts at `agent-v0.1.0` / `8ae950b0fecaa09e2fbb63bc5491decf69877b9b`.
It is a Linux port, not a replacement Vaultwarden deployment. Do not alter the
vault's Compose project, database, registration policy, proxy, certificates, mail
or backups. Do not register a personal daily-use account. Do not connect this
server to Codex. No npm/GHCR publication or automatic upgrades are part of this
procedure.

## Threat boundary

The root helper encrypts enrollment using systemd's host key, stored separately
from its ciphertext. This provides encrypted-at-rest storage and OS permission
controls, **not isolation from the authorized UID, root, or Docker administrators**.
Any process running as the authorized UID can use the helper. A process with
Docker socket access can effectively obtain host administration rights. It can
bypass these controls and read process memory. No same-UID isolation is claimed.
The output filter covers normal tool use, known secrets and recognized encodings;
it does not recognize every possible malicious encoding, fragmentation or covert
channel. Python/JavaScript memory cannot be guaranteed zeroized.

No HTTP MCP listener is added. Hermes starts Node through stdio. Node retains
vault/session logic; a Python private worker obtains credentials over a bounded,
peer-authenticated local UNIX socket and performs browser/SSH/MySQL actions.
The root service is not a shell/command broker and cannot receive arbitrary paths.
The master password and session are never command arguments. CLI child environment
contains secrets only when required; same-UID/root process inspection remains in
scope of the above limitation. Sessions remain in memory and idle expiry defaults
to 600 seconds. Encrypted CLI cache is separate from browser data.

## Prerequisites and version pinning

- Linux with Python `pidfd_open`, `/proc`, and subreaper support (tested on x86_64).
- Node 22.23.4; standalone official Bitwarden CLI 2026.9.1. Do not confuse the npm
  `@bitwarden/cli` dependency with the executable used in agent-safe mode.
- Verify downloaded archives against official published SHA-256 values before
  extraction. Record provenance, architecture and digest in the private deployment
  manifest. Do not silently replace the pinned CLI version.
- Python dependencies from `agent_worker/requirements.txt`, in a private venv.
- Dedicated Playwright Chromium installation. `chromium_sandbox=True` is required;
  a failed sandbox launch is an installation blocker, not a reason to add
  `--no-sandbox`. A fresh headless AI context is used; no daily browser, CDP port,
  cookies, password extension or existing profile may be attached/copied.
- systemd 252 host-key credentials were selected for the assessed headless system.
  No TPM protection is claimed. Secret Service was not available. Root provisioning
  is a separate human-authorized installation step, never Docker-based elevation.

**Every CLI command, including `bw --version`, must set a dedicated
`BITWARDENCLI_APPDATA_DIR`.** Otherwise even version inspection can initialize a
user-default CLI profile. Never use or inspect a daily account's cache.

## Layout and permissions

Use separate source and runtime roots, e.g. `/srv/warden-src` and `/srv/warden`.
The runtime belongs to the Hermes service UID; directories are 0700 and private
JSON/data files 0600. Explicitly chmod after creation: NAS default ACLs can produce
unexpected file modes despite umask. No production configuration belongs in Git.

```
warden-src/                         reviewed Git branch, source/tests/examples
warden/
  config.json                       exact HTTPS server and canonical file paths
  access.json                       enabled, allow_all, items; initially disabled
  state/cli/                        isolated encrypted Bitwarden CLI cache
  state/browser/                    dedicated ephemeral AI browser profiles
  state/known_hosts                 only manually verified target SSH keys
  logs/                             filtered metadata audit only
  runtime/                          verified pinned Node, standalone bw, Chromium
  .venv/                            private Python environment
  versions/<reviewed-version>/      dist, node_modules, agent_worker, package.json
  current -> versions/<version>     release selection, not a config path shortcut
  backups/<timestamp>/              private Hermes config and runtime config backups
```

Configuration validates canonical absolute regular-file paths. In particular a
venv Python symlink or `current/agent_worker/worker.py` symlink path is not accepted:
use a copied venv interpreter and the concrete version directory. `current` is for
operator selection/rollback only. The Linux example is
`examples/agent-safe/config.linux.example.json`.

Root-managed files are **outside the user-writable source/runtime trees**:

```
/usr/local/libexec/warden-hermes-credentials/linux_credentials_service.py
/etc/warden-hermes-credentials/registration.json
/var/lib/systemd/credential.secret                 root-owned host key
/var/lib/warden-hermes-credentials/auth.cred        root-only ciphertext
/run/warden-hermes-credentials/credentials.sock    authorized UID via SO_PEERCRED
/etc/systemd/system/warden-hermes-credentials.service
```

Do not copy Windows `auth.dpapi`. Do not put the host key alongside ciphertext or
copy it into the Hermes runtime. Backing up the key and ciphertext together changes
the theft boundary; handle host-key disaster recovery under an independent root
backup policy. Loss of the host key requires fresh enrollment.

## Root-helper installation gate

Review `agent_worker/linux_credentials_service.py` and the service example before
installation. Copy only the reviewed helper into a root-owned directory, and
verify the installed digest against the reviewed artifact **before starting it**.
Do not execute user-writable source Python/scripts as root. Use `/usr/bin/python3
-I` for the installed helper. The root registration contains only the exact HTTPS
server, service UID and GID, never email/master/API credentials.

The deployment-specific private instructions must give the exact hashes and
paths. Root actions are limited to creating those new helper directories, copying
the reviewed files, `systemd-creds setup`, and enabling/starting the new helper.
Never change the existing Hermes unit, Docker group, other MCPs, or approvals.
Installing this helper does not require restarting Hermes or fnOS.

Before real enrollment, validate with synthetic data through the root helper as
the actual Hermes service identity, restart only the new helper, and verify the
same ciphertext decrypts. Container UID-1000 tests are useful evidence but are
**not a substitute for the actual host service identity or a host reboot test**.
Do not reboot fnOS for this task. Validate boot configuration without claiming an
actual host reboot passed; arrange an operator-observed reboot test separately.

## Private local enrollment, pause, resume

Run these yourself in a direct local/SSH terminal, as the Hermes service user.
Do not enter any secret through a model tool, chat, captured terminal session,
recording, screenshot or shell argument. The manager requires a controlling TTY
and uses no-echo prompts, including email and optional API credentials.

```sh
ROOT=/srv/warden
PY="$ROOT/.venv/bin/python3.11"   # use the verified installed interpreter path
MANAGER="$ROOT/versions/<reviewed-version>/agent_worker/linux_manage.py"
"$PY" "$MANAGER" "$ROOT" status
"$PY" "$MANAGER" "$ROOT" enroll
"$PY" "$MANAGER" "$ROOT" resume
"$PY" "$MANAGER" "$ROOT" pause
```

Enroll only the dedicated AI account. Enrollment leaves access paused until the
explicit local resume command. An account requiring login 2FA can use its personal
API client ID/secret plus master password; do not enter Vaultwarden installation
ID/key. No raw password/TOTP retrieval or vault write tool is exposed.

Resume is never an MCP operation. Pause must reject new work, revoke session and
close controlled browsers; local pause/resume in a live MCP process is a separate
regression gate from restart persistence.

## Hermes activation gate

Back up the actual active Hermes config privately before any change. Preserve all
other values, especially existing MCPs, model, local terminal/Docker rights and
approval settings. Use the supported Hermes configuration/MCP CLI, not a hand
rewrite of YAML. Confirm the installed CLI help rather than assuming flags.

The new `vaultwarden` entry is stdio with:

- command: concrete pinned Node executable;
- args: concrete version `dist/server.js`, `--agent-safe`, `--agent-root`, runtime;
- connect_timeout: 30 seconds; timeout: 120 seconds;
- exactly the 12-tool include list below;
- explicitly `trust: untrusted`, no global approval change; disable sampling for
  this server. The inspected Hermes version defaults **missing trust to full**,
  so omitting this setting would bypass write-tool approval and is not acceptable.

```
status search sync browser_open browser_state browser_fill_login
browser_fill_totp browser_action mysql_query ssh_exec browser_close pause_access
```

SSH and browser actions retain their non-read-only annotations. Do not weaken
approval to avoid timeout. Read back the resulting config and compare every
pre-existing non-vaultwarden setting with the backup. A discovered tool list does
not prove the running gateway loaded the change. If a gateway restart is needed,
first identify affected conversations and obtain an explicit maintenance window.
Never restart fnOS.

Production acceptance starts with status/search/sync only. Then obtain explicit
item IDs and targets authorized by the owner for SSH, MySQL, HTTPS login and TOTP.
Do not sweep all targets just because all AI-account items are allowed. SSH host
keys require independent user fingerprint verification before adding to the
runtime's dedicated known_hosts. Do not auto-accept missing/changed fingerprints.
MySQL should use server-side least-privilege SELECT credentials; MCP enforces
read-only transactions, syntax restrictions, timeout and at most 500 rows.

## Isolated verification

Run the Node suite with the pinned Node on PATH and isolated CLI appdata. Run
Python helper, browser and process tests using the dedicated venv. Run
`agent_tests/isolated.py` with `WARDEN_TEST_NODE`, `WARDEN_TEST_BW` and
`WARDEN_TEST_BROWSER`. It creates only labeled disposable loopback fixtures with
synthetic accounts and tmpfs data. Its Linux credential helper is deliberately a
test-only same-UID in-memory fixture; it does not validate production root storage.
The production source never imports this fixture or accepts its trust overrides.

Read the ignored private `agent_tests/.runs/audit-results.json`, verify every
required check and cleanup, and record separate gates for:

1. TypeScript build/unit/protocol tests and Python tests;
2. all twelve tools against isolated Vaultwarden/SSH/MySQL/HTTPS;
3. real systemd-creds encryption and root helper restart in an isolated container;
4. actual host root service, service-identity decrypt and restart;
5. private AI-account enrollment and authorized production targets;
6. running Hermes discovery/approvals and operator-observed reboot behavior.

Do not commit result logs, fixtures, credentials, browser state, backups or real
configuration. A skip is not a pass, and a simulated short idle timeout is not a
600-second wall-clock soak.

## Rollback

Before activation record the concrete prior version and whether `vaultwarden`
already existed. This first installation has no previous Warden runtime.

1. Locally pause access and close/disconnect the new MCP. If changing gateway
   state needs a restart, obtain the maintenance window first.
2. Restore only the previous `vaultwarden` MCP entry via the supported CLI, or
   `hermes mcp remove vaultwarden` for a first install. Verify all unrelated
   config equals the private pre-change snapshot. A whole-file restore is only
   appropriate after checking no unrelated changes occurred since the backup.
3. Restore the prior private `config.json` (concrete worker paths) and prior
   `current` symlink selection. Keep versioned artifacts for review; never
   automatically download a replacement during rollback.
4. If the new helper is unused, the owner may run
   `sudo systemctl disable --now warden-hermes-credentials.service`. Retain its
   encrypted credential and the system host key. **Never delete the host key**;
   other services can depend on it.
5. Read back config and process state, confirm the failed runtime is gone, and
   verify the restored version. Do not roll back/delete Vaultwarden data, its
   Compose services, production volumes, database, or backups.

The deployment handoff must state exact branch/commit, artifact hashes and paths,
actual pass/fail/skip evidence, remaining operator gates, and rollback commands.
A prepared release is not an activated integration.
