# Linux validation evidence

## Scope

Baseline: `agent-v0.1.0` (`8ae950b0fecaa09e2fbb63bc5491decf69877b9b`).
Runtime: Linux x86_64, systemd 252, Node 22.23.4, standalone official Bitwarden
CLI 2026.9.1, Python 3.11 and isolated sandboxed Chromium. This document is a
nonsecret test summary, not raw logs or fixture data.

## Executed checks

- TypeScript build: passed.
- Full compiled Node suite: **451 tests, 446 passed, 5 skipped, 0 failed**.
  The skipped tests are upstream integration cases requiring their separate
  environment; they are not counted as successful production tests.
- Python discovery: **65 tests, 64 passed, 1 skipped, 0 failed** with the dedicated
  browser executable supplied. The skip is the explicitly root-container-only
  test; it was run and passed separately in a disposable isolated container.
- Test-only bootstrap environment regression: passed.
- Final isolated Vaultwarden/SSH/MySQL/HTTPS audit: **20 check groups passed**
  (6 fixture/CLI checks and 14 MCP checks), all 12 tools succeeded and all 12
  strict-schema error paths were exercised. Audit reports completed=true and
  confirms temporary service/credential/TLS fixtures, container and CLI profile
  removal.
- Sandbox was enabled for real Chromium tests. No daily profile, debug port,
  password extension, cookies or daily account were used.
- A staged versioned runtime was exercised through the real production stdio
  entrypoint (not the test bootstrap), using canonical copied venv Python and the
  actual root-managed socket. Exact 12-tool discovery, status, matching text and
  structured results, paused search denial, clean stderr and shutdown passed.
  No vault login or real account data access occurred.
- Final independent re-review passed with no remaining blocking findings; it
  reran 42 focused Node regressions and 26 real process/browser tests.
- Source diff whitespace/syntax checks: passed at test execution.

The isolated MCP checks include metadata redaction; password, TOTP, ordinary and
hidden custom fields, notes, URI tokens, attachment and Send canaries; matching
text/structuredContent; unexposed-tool rejection; generic validation/errors;
strict SSH unknown/changed key rejection; MySQL read-only transaction and 500-row
cap; HTTPS login/TOTP filling separate from submit; persisted pause/restart;
**same-process local pause/resume**; idle revocation and re-unlock; sampled argv
safety; process teardown; and owned browser profile removal.

Additional real subprocess regressions cover Node/worker SIGKILL, detached
children, stop, timeout and cancellation. CLI watchdogs receive no credentials;
the contained child alone reads the inherited environment pipe before exec.
Browser cleanup uses pinned directory descriptors and runs after process reaping,
including ancestor replacement/symlink and concurrent worker cases.

## Credential-provider evidence

The isolated root-helper test used real systemd host-key encryption, a root-owned
host key, an authorized UID1000/GID1001 consumer, unauthorized UID1002 rejection,
private key/ciphertext filesystem permissions, and helper restart persistence.
No host-root mount, host Docker socket or privileged test container was used.

After operator installation of the reviewed root helper on the actual host,
service metadata and installed file hashes matched. A request issued by the
actual Hermes service identity (UID1000/GID1001) successfully encrypted and
retrieved a generated synthetic preflight value through the hardened service.
No Vaultwarden network login was made for this check. The fixture's plaintext was
not printed or written to a plaintext file; only a verification hash was retained
privately outside Git for the subsequent restart check.

## Separate remaining gates

At the time of this summary these are **not claimed passed**:

- Actual host helper restart persistence (operator restart and comparison pending).
- Actual host reboot behavior. The unit may be enabled, but the host was not
  rebooted and must not be rebooted automatically for this task.
- Real AI-account hidden-input enrollment and status/search/sync.
- User-authorized production SSH, MySQL, HTTPS login and TOTP targets.
- Running Hermes gateway discovery and live approval behavior after activation.
- Native Windows execution (Windows paths are preserved, not runtime-tested here).
- A literal ten-minute wall-clock idle soak: production default is asserted as
  600,000 ms and behavioral tests accelerate timeouts.

Passing the test-only same-UID credential fixture does not validate production
root provisioning; these were deliberately tested and reported separately.
A process that deliberately kills the guardian itself, host shutdown/power loss,
or hostile root/Docker access is not an unbreakable cleanup guarantee. Unknown
stale profiles are never broadly deleted. This mechanism is not a same-UID
security sandbox or a general encoded-secret-exfiltration detector.

## Re-run

Use the pinned Node on PATH, isolated `BITWARDENCLI_APPDATA_DIR` for every CLI
invocation, and the dedicated Python venv. Set `WARDEN_TEST_NODE`, `WARDEN_TEST_BW`
and `WARDEN_TEST_BROWSER` to the private verified runtimes, then:

```sh
npm run build
node --test 'dist/**/*.test.js'
node --test agent_tests/test_fixture_server.mjs
<venv-python> -m unittest discover -s agent_tests -p 'test_*.py' -v
<venv-python> agent_tests/isolated.py
```

The EOF test is a **compiled** test; invoke from `dist` after building, not through
`tsx` on its TypeScript source. Root-container instructions are in
`docs/linux-credentials.md`. Audit JSON and raw test output stay ignored/private;
do not add them to commits.
