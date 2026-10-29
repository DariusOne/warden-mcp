# SSH first-use confirmation

The agent-safe API keeps all twelve tool names and their argument schemas.
`ssh_exec` still accepts only an item ID, command and execution timeout. The
password remains inside the credential/worker pipeline. No vault write access
or additional MCP tool is introduced.

## Identity flow

1. Read the item privately. Connect and negotiate a public server key before
   password authentication. Check both the user's `~/.ssh/known_hosts` and the
   runtime's `state/known_hosts`; conflicting entries fail closed.
2. If the key is unknown, close that connection and send a standard MCP **form
   elicitation**. It displays the filtered item name, endpoint, key type and
   SHA256 fingerprint. The schema has no input fields: only the client's
   accept/decline/cancel response authorizes this pending operation.
3. After accept, sync and reread the item, reconnect, and compare the entire key
   and the bound item/host/port/username again. Write the exact key atomically
   under a process-safe file lock, then authenticate on that same connection.
4. Subsequent calls, including after restart, use the saved record. Records are
   local to each deployment, never written back to the vault or synchronized.

The confirmation expires after five minutes. Pause, request cancellation and
process exit invalidate pending approvals. Unsupported clients and unattended
calls return `ssh_confirmation_required` with safe public identity information;
they do not send the password. Approving the SSH tool permanently does not
approve unfamiliar server keys. A model-supplied `confirmed` argument is
rejected by the unchanged strict input schema. Executed commands are never
automatically retried.

First-use approval records the user's trust decision; a scanned key alone does
not prove identity. Compare the displayed fingerprint with a previously trusted
record or the provider console before accepting. Host keys are public data.

## Errors and key changes

Safe errors distinguish confirmation required/denied/cancelled/timeout,
target changed, key changed, conflicting records, persistence failure and
authentication failure. Where available, `host_key` contains bounded `host`,
`port`, `key_type`, `fingerprint`, `previous_fingerprints`. Raw exceptions,
passwords, master secrets, TOTP and sessions are never returned. Public key
bytes and the private binding are not returned through MCP. All public fields
still pass through the existing secret filter; an identity that overlaps a
known secret cannot be confirmed by revealing that secret.

A changed key is refused without an elicitation. This release has no chat-based
key replacement function. For legitimate rotation, an operator must independently
verify the new fingerprint, back up both trust files, and update only the exact
host/port record using local administration. Do not delete the whole store, use
AutoAddPolicy, or turn off host verification. If stores disagree, resolve the
conflict explicitly rather than relying on file load order.

## Build and deployment

- Keep upstream `main` unchanged. Linux portability was imported as reviewed
  source from commit `fe7035d7621f130354b52923a0d1aedcea065187`; deployment files
  and enrolled credentials are not part of that import.
- Build with TypeScript and run the native agent tests on both OSes. The full
  upstream Node suite uses Unix executable fixtures, so run it on Linux. The
  Windows agent suite and real standalone CLI integration cover Windows paths.
- `agent_tests/isolated.py` provisions temporary loopback Vaultwarden, SSH,
  MySQL and HTTPS services using synthetic credentials. Set `WARDEN_TEST_NODE`,
  `WARDEN_TEST_BW`, and on Linux `WARDEN_TEST_BROWSER`/`WARDEN_TEST_PYTHON`.
  Never use production enrollment with this fixture. Process tests also use
  these explicit binaries; synthetic credentials and profiles are reclaimed.
- Stage with `agent_tools/stage_release.py --source <source> --root <root>
  --dependencies <old-version> --version <candidate> --commit <commit>
  --tree <tree>`. It requires an identical dependency lock and a new version
  directory. Rebuild from the checked source first. `BUILD.json` identifies the
  source; `ARTIFACTS.json` records artifact checksums. Nothing activates yet.
- Back up the MCP block, runtime `config.json`, current version reference and
  trust file; retain existing encrypted enrollment in place. Switch fnOS first,
  then Windows. Update only this MCP to 480-second calls / 30-second startup;
  Hermes form elicitation uses a 300-second confirmation window. Preserve
  untrusted-server/tool approvals and the explicit twelve-tool allowlist.
- Restart the Hermes gateway only with no active calls. Reload the Codex MCP
  connection, or restart Codex when no per-server reload is available. No NAS
  reboot or Vaultwarden restart is required.
- Check `status.mcp_version`, `source_commit`, `ssh_trust_mode=confirm_once`,
  tool count, and **actual Codex and Telegram** prompts. Mock or in-memory MCP
  clients do not satisfy the interactive acceptance requirement. First-use
  tests must include rejection, acceptance, and a repeat call without a prompt.
- Push the feature branch after isolated tests; merge into the maintenance
  branch and tag `agent-v0.2.0` only after both clients pass human acceptance.

## Rollback

Restore only the affected MCP block and runtime config/current reference, then
restart that MCP. Preserve newly approved valid host records in normal rollback;
restore a backed-up trust file only if it is itself incorrect. Keep old version
directories and never copy enrollment from another OS or vault. Do not roll back
other MCP settings, approval policy, Docker permissions or Vaultwarden data.

The protection covers normal tool operations and known-secret output control.
It does not isolate secrets from another process with full rights as the same
user or a host administrator, nor identify all arbitrary encodings of a secret.
