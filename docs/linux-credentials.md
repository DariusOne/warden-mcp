# Linux credentials: local root-managed helper

## Scope and security boundary

This is an **optional new system service**, not a change to Hermes startup. The
worker remains Python behind Node's inherited private pipe. Windows continues to
use CurrentUser DPAPI; Linux never opens `state/auth.dpapi` and has no plaintext,
environment-variable, keyring, HTTP, TCP, or DPAPI fallback.

The helper is a standalone stdlib-only Python file installed under
`/usr/local/libexec/warden-hermes-credentials/`, root-owned and not writable by
UID 1000. Its service uses `/usr/bin/python3 -I`, not the user venv or source tree.
Do not run user-writable Python, shell installers, or a user venv as host root.

| Object | Fixed production location | Owner / mode |
|---|---|---|
| Helper code | `/usr/local/libexec/warden-hermes-credentials/linux_credentials_service.py` | root:root 0644; directory 0755 |
| Registration | `/etc/warden-hermes-credentials/registration.json` | root:root 0600; directory 0700 |
| Host encryption key | `/var/lib/systemd/credential.secret` | root:root **0400** (native systemd mode) |
| Ciphertext | `/var/lib/warden-hermes-credentials/auth.cred` | root:root 0600; directory 0700 |
| UNIX socket | `/run/warden-hermes-credentials/credentials.sock` | root:registered GID 0660; directory root:root 0755 |

`systemd-creds --with-key=host` encrypts/decrypts over stdin/stdout pipes. Only
ciphertext is written to the credential directory; the host key is NOT stored
beside it. **Do not chmod the systemd host key to 0600:** systemd 252 rejects a
host key with that mode. All private files created here use explicit chmod/fchmod;
fnOS inherited ACLs can otherwise leave execute bits even with a restrictive umask.

The helper verifies `SO_PEERCRED` UID on every connection and checks the request
server against the root-owned registration **before reading/decrypting credentials**.
The decrypted payload must match that exact server too: trailing slashes, scheme,
port and path are not normalized. The client verifies the server's peer UID is 0
before sending even enrollment data. Requests are single 4-byte big-endian length
frames, at most 65536 bytes; receives have a 5-second total deadline, cryptographic
subprocesses have a 4-second timeout, and sends are bounded. Errors return only
`{"ok":false,"code":"credential_store"}`; no raw exception, stderr or credential
logging. No caller-selected filename, command, executable, or server destination is
used by the helper. The helper never contacts the vault server.

**This is encryption at rest and a root-managed broker, not isolation from the
agent's UID.** Any process with the registered UID can request or replace the
credentials via this socket; a TTY is a local enrollment UI rule, not authentication
against another same-UID process. Same-UID processes may inspect consumer memory,
replace user-owned worker code, or change `access.json`. Root, or a user with Docker
control, can bypass the boundary. Python does not guarantee zeroization or prevent
swap. The helper disables core dumps; enrollment does too. Use host disk/swap
protection if those are threats. Losing the host key prevents decryption; copying
both key and ciphertext defeats host-only at-rest protection.

## Manual installation gate — do not execute automatically

Installation is an explicit operator gate. A local administrator must authorize
this new helper separately from the source implementation. No Docker host mount,
privileged container, passwordless-sudo assumption, or Hermes service replacement
is an installation path.

1. Obtain a local authenticated root login (for example, enter `sudo -i` yourself
   in a terminal). Never put the password in chat, a command argument, a file, or an
   environment variable. Use a trusted root shell/environment; the commands below
   assume standard system tools, not aliases or user shell initialization. Check
   `/root`, `/usr/local/libexec`, `/etc`, `/var/lib`, and their ancestors are real
   root-owned directories, without symlinks or non-root write access. The helper
   deliberately refuses untrusted/symlinked paths. Stop on any discrepancy.
2. Copy files **as data** into a fresh root-only staging directory. This does not
   execute anything from the user tree. Refuse an existing staging directory and
   do not follow a pre-existing destination symlink:

   ```sh
   /usr/bin/test ! -e /root/warden-hermes-credentials-stage
   /usr/bin/test ! -L /root/warden-hermes-credentials-stage
   # Proceed only if both tests succeeded.
   /usr/bin/install -d -o root -g root -m 0700 /root/warden-hermes-credentials-stage
   /usr/bin/install -T -o root -g root -m 0644 /opt/hermes/warden-mcp-src/agent_worker/linux_credentials_service.py /root/warden-hermes-credentials-stage/linux_credentials_service.py
   /usr/bin/install -T -o root -g root -m 0644 /opt/hermes/warden-mcp-src/examples/linux-credentials/warden-hermes-credentials.service /root/warden-hermes-credentials-stage/warden-hermes-credentials.service
   /usr/bin/install -T -o root -g root -m 0600 /opt/hermes/warden-mcp-src/examples/linux-credentials/registration.json /root/warden-hermes-credentials-stage/registration.json
   ```

3. **Review these root-owned staged copies**, not the now-mutable source versions.
   Compare the helper and unit with the reviewed change. Record their staged
   `sha256sum` values locally. Do not execute the staged helper during review.
   Using a trusted local editor, set the staged registration's exact server URL,
   the runtime user UID and primary GID (`id -u agentuser` and `id -g agentuser`).
   This JSON has no secret fields. Do not copy a Windows DPAPI blob. Reject the
   `example.invalid` template URL. Do not modify staged code after review without
   reviewing it again.
4. Check all destination paths are absent (new installation), or stop for a
   separately reviewed upgrade. Do not overwrite existing credentials, helper
   registration, or unit. Create the destinations and copy only the reviewed
   root-owned snapshot. These commands require the preceding checks:

   ```sh
   /usr/bin/install -d -o root -g root -m 0755 /usr/local/libexec/warden-hermes-credentials
   /usr/bin/install -d -o root -g root -m 0700 /etc/warden-hermes-credentials /var/lib/warden-hermes-credentials
   /usr/bin/install -T -o root -g root -m 0644 /root/warden-hermes-credentials-stage/linux_credentials_service.py /usr/local/libexec/warden-hermes-credentials/linux_credentials_service.py
   /usr/bin/install -T -o root -g root -m 0600 /root/warden-hermes-credentials-stage/registration.json /etc/warden-hermes-credentials/registration.json
   /usr/bin/install -T -o root -g root -m 0644 /root/warden-hermes-credentials-stage/warden-hermes-credentials.service /etc/systemd/system/warden-hermes-credentials.service
   ```

   Compare installed hashes against the reviewed staged copies, and inspect owner,
   mode and ancestor permissions with `stat`/`namei -l`. Group/other write permissions
   or ACL grants to UID 1000 on code/registration/ancestors are unacceptable.
5. If `/var/lib/systemd/credential.secret` already exists, do **not** replace it or
   chmod it speculatively: verify it is a regular root-owned 0400 file and its
   ancestors are trusted. If absent, create it with the trusted system tool:

   ```sh
   /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C /usr/bin/systemd-creds setup
   ```

   Verify root:root 0400. Keep this key out of the credential directory, user home,
   source tree and runtime. Backups of the key require separate root-controlled
   handling; this implementation does not create one.
6. Check and enable **only the new helper**, using a sanitized environment:

   ```sh
   /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C /usr/bin/systemd-analyze verify /etc/systemd/system/warden-hermes-credentials.service
   /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C /usr/bin/systemctl daemon-reload
   /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C /usr/bin/systemctl enable --now warden-hermes-credentials.service
   /usr/bin/systemctl is-enabled warden-hermes-credentials.service
   /usr/bin/systemctl is-active warden-hermes-credentials.service
   ```

   Inspect the unit's effective User, ExecStart, MainPID and installed file ownership.
   Check the new socket is root-owned 0660 with the registered group. This does not
   edit, restart, or replace Hermes's user service or its linger setting. Do not
   print the host key, ciphertext plaintext, or helper response to `get`.

## Worker configuration and local management

As the configured runtime user, merge the nonsecret fields from `config.fragment.json` into the existing
runtime `config.json`, preserving all other settings. The existing `server` must
exactly match the root registration. `credential_socket` must be explicitly set to
`/run/warden-hermes-credentials/credentials.sock`; missing/relative paths fail
closed. There is no default provider fallback. Keep runtime directories 0700 and
configuration/access files 0600 with explicit chmod. Do not replace production
configuration merely to test this feature.

Run these yourself from a local terminal with both stdin and stdout attached;
`ROOT` below means the existing runtime directory, not the source checkout:

```sh
ROOT=/srv/warden
MANAGER="$ROOT/versions/REVIEWED_VERSION/agent_worker/linux_manage.py"
"$ROOT/.venv/bin/python3.11" "$MANAGER" "$ROOT" status
"$ROOT/.venv/bin/python3.11" "$MANAGER" "$ROOT" enroll
"$ROOT/.venv/bin/python3.11" "$MANAGER" "$ROOT" resume
"$ROOT/.venv/bin/python3.11" "$MANAGER" "$ROOT" pause
```

- `enroll`: first pauses policy, probes the helper, then reads email, master password,
  API client ID and API client secret using `getpass` on `/dev/tty`. Leave both API
  fields blank for password login. Master+email are always required. No secret
  command arguments, environment variables, plaintext file, clipboard, or chat.
  Non-TTY input/output is rejected, and getpass echo fallback is an error. The
  registered payload is the Windows-compatible five-field object:
  `server`, `email`, `master`, `client_id`, `client_secret`. Enrollment ends paused;
  explicitly resume after reviewing the scope. If replacement fails, policy stays
  paused and the prior ciphertext is preserved unless replacement already completed.
- `resume`: requires a local TTY and a successful registered status probe. Sets
  `enabled:true`. Existing `allow_all`, `items`, and other policy fields are
  preserved. A new policy defaults to `allow_all:true, items:[]`; this is full-account
  scope, not selected items. No resume MCP operation is added.
- `pause`: requires a local TTY; writes `enabled:false` atomically. It does not
  erase enrollment or stop the root helper. New MCP operations fail closed. While
  managed resources are active, a 100 ms policy poll revokes the session, stops
  the private worker and invalidates page IDs without waiting for another tool
  call. This is bounded polling, not an instantaneous OS-level revocation barrier.
  A later atomic local `resume` replacement allows new operations in the same MCP
  process; old page IDs and revoked in-flight operations do not resume. If policy
  persistence fails during MCP pause, an unchanged enabled file cannot release
  the in-memory pause latch.
- `status`: safe without a TTY. Successful `registered:false` means the helper is
  reachable and the ciphertext is absent. Transport/permission/registration errors
  return `credential_store`, not an unregistered success. `registered:true` means
  a ciphertext file exists, not a successful remote login/decrypt test.

The private worker operation `credential_status` returns only `{registered:bool}`;
`credentials` returns the compatible payload only on the inherited private pipe to
Node. The public MCP layer must not expose a raw `credentials` operation. Rotation
uses local `enroll` again, then explicit `resume`; a server change also requires a
reviewed root registration update, helper restart and re-enrollment.

## Validation and limitations

Host-side tests (synthetic values only):

```sh
/opt/hermes/warden-mcp/.venv/bin/python -m unittest agent_tests.test_linux_credentials -v
```

The unprivileged systemd 252 test exercises **real encryption** into an isolated
scratch tree. Its protocol round-trip uses an explicitly named decrypt test double:
systemd 252 refuses to read a non-root-owned host key. This is not presented as
proof of production decryption.

The separately gated container test runs the real root helper with a root-owned
host key and invokes the client as **UID 1000/GID 1001**. It exercises real host-key
encryption/decryption, denies UID 1002 even with the socket group, verifies direct
key/ciphertext reads and helper/registration writes are denied to UID 1000, then
restarts the helper and decrypts again. It uses no host mounts, no Docker socket,
no privileged container, no production state and no container network at test time:

```sh
docker build -t warden-creds-synthetic-test -f examples/linux-credentials/Dockerfile.synthetic examples/linux-credentials
tar -cf - agent_worker/credentials.py agent_worker/linux_credentials_service.py agent_tests/test_linux_credentials.py | docker run --rm -i --network none -e WARDEN_SYNTHETIC_CONTAINER=1 warden-creds-synthetic-test /bin/sh -c 'mkdir /test && tar --no-same-owner -xf - -C /test && chmod -R a+rX /test && cd /test && python3 -m unittest agent_tests.test_linux_credentials.ContainerTests -v'
```

This is disposable synthetic validation, **not Docker-based host installation or
host privilege escalation**. Container root is never given host system paths.

**Not yet verified:** the new system unit running under fnOS systemd hardening, the
actual Hermes service consuming enrolled credentials, or host reboot recovery.
The container restart test is not a reboot test. After locally authorized install,
verify as UID 1000 that status reports unregistered, enroll locally, confirm status,
restart only the helper and confirm a nonsecret authenticated MCP operation. A real
reboot/startup test needs explicit user authorization. Do not label these acceptance
criteria passed before exercising them on the installed service.
