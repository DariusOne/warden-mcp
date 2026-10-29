"""SSH server identity checks. Only the private worker may supply an approval.

Public tools never accept host keys, approval flags or trust-store paths.
An unknown key is returned before password authentication; a confirmed key is
verified again on the connection that will authenticate and execute the command.
"""
from contextlib import contextmanager
import base64
import csv
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import time

import paramiko
from bridge_core import BridgeError


def fingerprint(key):
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")


def endpoint(target):
    host = target["host"].strip("[]").lower().rstrip(".")
    port = int(target["port"])
    return host, port, host if port == 22 else f"[{host}]:{port}"


def binding(target, item_id):
    host, port, _ = endpoint(target)
    value = json.dumps([item_id, host, port, target["user"]], separators=(",", ":"))
    return hashlib.sha256(value.encode()).hexdigest()


def public_key_info(target, item_id, key, previous=()):
    host, port, _ = endpoint(target)
    return {"host": host, "port": port, "key_type": key.get_name(),
            "fingerprint": fingerprint(key), "public_key": key.get_base64(),
            "binding": binding(target, item_id),
            "previous_fingerprints": sorted(set(fingerprint(k) for k in previous))}


def _checked_info(path, directory=False):
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise BridgeError("ssh_trust_store", "Trust store links are not allowed.")
    if directory:
        valid = stat.S_ISDIR(info.st_mode)
    else:
        valid = stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 1024 * 1024
    if not valid:
        raise BridgeError("ssh_trust_store", "Invalid trust store.")
    return info


def _read(path):
    try:
        _checked_info(path)
    except FileNotFoundError:
        return b""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise BridgeError("ssh_trust_store", "Invalid trust store.")
        data = source.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise BridgeError("ssh_trust_store", "Trust store exceeds limit.")
    return data


def _matches(name, candidate):
    if name.startswith("|1|"):
        return hmac.compare_digest(paramiko.HostKeys.hash_host(candidate, name), name)
    return name == candidate


def trusted_keys(root, target):
    """Read both stores without silently replacing conflicting entries."""
    _, _, name = endpoint(target)
    keys = {}
    paths = [Path.home() / ".ssh" / "known_hosts", Path(root) / "state" / "known_hosts"]
    try:
        for path in paths:
            for number, line in enumerate(_read(path).decode("utf-8-sig").splitlines(), 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                entry = paramiko.hostkeys.HostKeyEntry.from_line(line, number)
                if not entry or not entry.key:
                    raise ValueError()
                if not any(_matches(n, name) for n in entry.hostnames):
                    continue
                kind = entry.key.get_name()
                if kind in keys and keys[kind] != entry.key:
                    raise BridgeError("ssh_host_conflict", "Conflicting trusted host keys.")
                keys[kind] = entry.key
        return keys
    except BridgeError:
        raise
    except Exception:
        raise BridgeError("ssh_trust_store", "Trust store could not be read.") from None


def _private_file(path, fd):
    if os.name != "nt":
        if os.fstat(fd).st_uid != os.getuid():
            raise BridgeError("ssh_trust_store", "Trust store owner mismatch.")
        os.fchmod(fd, 0o600)
        return
    result = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"],
                            capture_output=True, text=True, timeout=5,
                            creationflags=subprocess.CREATE_NO_WINDOW, check=True)
    sid = next(csv.reader(io.StringIO(result.stdout)))[-1]
    if not sid.startswith("S-1-"):
        raise BridgeError("ssh_trust_store", "Cannot determine file owner.")
    subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r", f"*{sid}:F",
                    "*S-1-5-18:F", "*S-1-5-32-544:F"], check=True, timeout=5,
                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)


@contextmanager
def _store_lock(root):
    state = Path(root) / "state"
    _checked_info(Path(root), directory=True)
    state.mkdir(mode=0o700, exist_ok=True)
    _checked_info(state, directory=True)
    path = state / ".known_hosts.lock"
    try:
        _checked_info(path)
    except FileNotFoundError:
        pass
    fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    locked = False
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise BridgeError("ssh_trust_store", "Invalid lock file.")
        _private_file(path, fd)
        deadline = time.monotonic() + 5
        while not locked:
            try:
                os.lseek(fd, 0, os.SEEK_SET)
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
            except OSError:
                if time.monotonic() >= deadline:
                    raise BridgeError("ssh_trust_store", "Trust store is busy.") from None
                time.sleep(0.05)
        if os.fstat(fd).st_size == 0:
            os.write(fd, b"\0")
        yield state
    finally:
        if locked:
            os.lseek(fd, 0, os.SEEK_SET)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def save_confirmed(root, target, item_id, key, expires_at):
    temporary = None
    try:
        with _store_lock(root) as state:
            if time.time() * 1000 >= expires_at:
                raise BridgeError("ssh_confirmation_timeout", "Host key confirmation expired.")
            existing = trusted_keys(root, target)
            if existing:
                if existing.get(key.get_name()) == key:
                    return
                raise BridgeError("ssh_host_changed", "Host key changed.",
                                  public_key_info(target, item_id, key, existing.values()))
            destination = state / "known_hosts"
            original = _read(destination)
            parent_identity = (state.stat().st_dev, state.stat().st_ino)
            _, _, name = endpoint(target)
            line = f"{name} {key.get_name()} {key.get_base64()}\n".encode("ascii")
            data = original + (b"\n" if original and not original.endswith(b"\n") else b"") + line
            fd, temporary = tempfile.mkstemp(prefix=".known-hosts-", dir=state)
            with os.fdopen(fd, "wb") as output:
                _private_file(Path(temporary), output.fileno())
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
            _checked_info(state, directory=True)
            if parent_identity != (state.stat().st_dev, state.stat().st_ino) or _read(destination) != original:
                raise BridgeError("ssh_trust_store", "Trust store changed during confirmation.")
            if time.time() * 1000 >= expires_at:
                raise BridgeError("ssh_confirmation_timeout", "Host key confirmation expired.")
            os.replace(temporary, destination)
            temporary = None
    except BridgeError:
        raise
    except Exception:
        raise BridgeError("ssh_trust_store", "Trust store could not be updated.") from None
    finally:
        if temporary:
            try:
                os.unlink(temporary)
            except OSError:
                pass


def connect(root, target, item_id, approval=None):
    host, port, name = endpoint(target)
    existing = trusted_keys(root, target)
    if approval is not None:
        if not isinstance(approval, dict) or approval.get("binding") != binding(target, item_id):
            raise BridgeError("ssh_target_changed", "SSH target changed during confirmation.")
        expires = approval.get("expires_at")
        if not isinstance(expires, (float, int)) or not time.time() * 1000 < expires <= time.time() * 1000 + 300_000:
            raise BridgeError("ssh_confirmation_timeout", "Host key confirmation expired.")
    client = paramiko.SSHClient()
    if approval is None:
        for kind, key in existing.items():
            client.get_host_keys().add(name, kind, key)

    class ConfirmedKeyPolicy(paramiko.MissingHostKeyPolicy):
        def missing_host_key(self, ssh, hostname, key):
            info = public_key_info(target, item_id, key, existing.values())
            if approval is None:
                raise BridgeError("ssh_host_unknown", "SSH host key needs confirmation.", info)
            if (approval.get("public_key") != key.get_base64() or
                    approval.get("key_type") != key.get_name() or
                    approval.get("fingerprint") != fingerprint(key)):
                info["previous_fingerprints"] = sorted(set(info["previous_fingerprints"] + [approval["fingerprint"]]))
                raise BridgeError("ssh_host_changed", "Host key changed after confirmation.", info)
            if time.time() * 1000 >= approval["expires_at"]:
                raise BridgeError("ssh_confirmation_timeout", "Host key confirmation expired.")
            save_confirmed(root, target, item_id, key, approval["expires_at"])
            ssh.get_host_keys().add(hostname, key.get_name(), key)

    def transport_factory(sock, **kwargs):
        transport = paramiko.Transport(sock, **kwargs)
        if approval:
            preferred = [approval.get("key_type")]
            if preferred == ["ssh-rsa"]:
                preferred = ["rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"]
            options = transport.get_security_options()
            options.key_types = tuple(k for k in preferred if k in options.key_types)
        return transport

    client.set_missing_host_key_policy(ConfirmedKeyPolicy())
    try:
        client.connect(host, port=port, username=target["user"], password=target["password"],
                       timeout=10, auth_timeout=10, banner_timeout=10, allow_agent=False,
                       look_for_keys=False, transport_factory=transport_factory)
        return client
    except paramiko.BadHostKeyException as error:
        client.close()
        raise BridgeError("ssh_host_changed", "SSH host key changed.",
                          public_key_info(target, item_id, error.key, existing.values())) from None
    except paramiko.AuthenticationException:
        client.close()
        raise BridgeError("ssh_auth_failed", "SSH authentication failed.") from None
    except BaseException:
        client.close()
        raise
