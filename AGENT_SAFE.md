# Agent-safe Windows stdio mode

This fork keeps upstream 0.2.60 and adds a local credential-use interface.
It does not require changes to Vaultwarden, its database, proxy or certificates.
The full HTTPS URL, including a port and subpath, is passed to the Bitwarden CLI.
HTTP mode keeps upstream's origin-only constraint.

## Runtime

Use Node 22.23.4, the standalone Windows Bitwarden CLI **2026.9.1**, Python 3.13
and `agent_worker/requirements.txt`. Edge must already be installed. Safe mode
checks the CLI version at startup and never falls back to the bundled CLI.
Keep build output and dependencies in a versioned runtime directory, independent
of the source checkout. Configure an ACL granting only the deployment user,
SYSTEM and administrators access to the runtime root and its descendants.

Create `config.json` in the private runtime root, following
`examples/agent-safe/config.example.json`. Paths must be absolute. The root holds:

```text
config.json
access.json                  {"enabled":true,"allow_all":true,"items":[]}
state/auth.dpapi              Windows CurrentUser DPAPI ciphertext
state/known_hosts             explicitly verified SSH host keys
state/cli/.bitwarden-cli/     separate encrypted CLI profile
logs/                        metadata-only audit log, 30-day retention
versions/<version>/          dist/, node_modules/, agent_worker/
runtime/                     pinned node.exe and bw.exe
.venv/                       private Python environment
```

The encrypted enrollment format is JSON containing `server`, `email`, `master`,
`client_id` and `client_secret`, encrypted using Windows DPAPI CurrentUser with
no optional entropy. Existing compatible enrollment can be copied as ciphertext
and compared by SHA-256. Never print or export its decrypted contents. For an
account using login 2FA, enroll a personal API credential locally as well as the
master password; it is not a Vaultwarden installation ID/key.

Start `node.exe <version>/dist/server.js --agent-safe --agent-root <root>`.
`--agent-safe --http` is rejected. No listener is opened.
Use `agent_worker/manage.py <root>` through a local launcher to resume access.
No service, scheduled task or remote management interface is installed.

## Interface

The MCP name stays `vaultwarden`. Exactly twelve tools are registered:
`status`, `search`, `sync`, `browser_open`, `browser_state`,
`browser_fill_login`, `browser_fill_totp`, `browser_action`, `mysql_query`,
`ssh_exec`, `browser_close`, `pause_access`.

Names, arguments, defaults and result fields match the prior local bridge.
Both MCP text and structured content contain the same filtered object.
Search returns only ID, name, type, username, website origins and password/TOTP
presence flags. Custom fields, notes and full URLs are not returned.
Unknown tools, including upstream password/export/attachment/Send tools and
private worker operations, are rejected at the server.

SSH uses password authentication and strict known-host validation. Add a host
key only after independently verifying its fingerprint. MySQL permits bounded
read-only statements in a read-only transaction, with a query timeout and at
most 500 returned rows. Neither a password-vault read nor an SSH command implies
that the external operation is read-only. Existing destructive/open-world hints
are retained for SSH and browser actions.

Browser fill uses a separate Edge context. Only the item's exact HTTPS origins
are allowed, including form targets and requests. Filling and submitting are
separate calls. State excludes input values, cookies, HTML and URL parameters.
The private worker and descendant Edge processes are contained in a Windows job.

## Credential and output controls

Node owns the upstream SDK/session manager. A Python child decrypts enrollment
on demand and implements SSH, MySQL and browser operations. Communication uses
inherited anonymous pipes, never model-visible MCP messages or an HTTP listener.
Master passwords are passed to CLI children through a controlled environment;
sessions use `BW_SESSION`, not command arguments. Safe mode never persists the
upstream plaintext session JSON. Inactivity for ten minutes revokes the session
and closes browser contexts; the next authorized operation unlocks on demand.
Pause persists a disabled flag, blocks new operations, clears the session and
closes browsers. A local GUI is the supported resume path.

Known secrets are represented in the output filter by rolling-hash prefilters
and SHA-256 confirmation, not stored plaintext copies of master/session values.
Password, TOTP, notes, custom fields, private keys, URL tokens and common base64,
URL, JSON, hex and HTML encodings are checked in text, structures and keys.
Raw exceptions and child stderr are not forwarded. Audit logs contain only
time, action, outcome and a validated item ID.

Recognized, validated host/port/database routing fields are nonsecret connection
metadata and are not added as secret fingerprints; their raw custom fields are
still omitted from search. This prevents a port such as `22` from corrupting
stable item IDs. All other ordinary custom fields remain filtered by default.

This controls normal tool use and known-secret outputs. It does **not** isolate
credentials from programs with full rights as the same Windows user, guarantee
memory zeroization in garbage-collected runtimes, or recognize every arbitrary
remote encoding or fragmented secret echo. Separate OS identities and stronger
isolation would be a distinct deployment design.

Regular mode additionally fails closed for attachment and Send operations when
`NOREVEAL` is true; these opaque payloads cannot be safely inferred as metadata.
Ordinary upstream mode is not a replacement for `--agent-safe`.

## Validation and maintenance

Run the TypeScript build, relevant Node unit tests and
`agent_tests/isolated.py` on Windows with `WARDEN_TEST_NODE` and `WARDEN_TEST_BW`
pointing to the pinned executables. The test uses ephemeral labeled Docker
containers, synthetic accounts, DPAPI ciphertext and a temporary test CA.
The browser fixture pins only its ephemeral certificate in a test-only worker;
production never imports that worker or disables certificate validation.
Test resources are removed after the run. Nothing is written to a real vault.

Update upstream manually on `main`; merge reviewed upstream changes into
`codex/agent-safe-credentials` and repeat tests before selecting a new runtime.
Fork workflows remain disabled, release jobs also check the upstream repository,
and `package.json` is private to prevent accidental npm publication.

Back up only the existing Codex `mcp_servers.vaultwarden` block before switching.
The example sets 30-second startup and 120-second tool timeouts and an explicit
tool allowlist; retain the user's approval settings. Rollback restores only
that block and stops the new runtime. Keep the old bridge and encrypted data.
Vaultwarden data and other Codex MCP entries are outside this migration.
