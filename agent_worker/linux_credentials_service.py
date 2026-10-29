"""Root-owned standalone UNIX credential helper. Uses only Python stdlib.

Install a reviewed immutable copy, never execute this user-writable source as root.
No HTTP, TCP, shell, user-specified paths, imports from the worker, or secret logs.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import socket
import struct
import time
import stat
import resource
from urllib.parse import urlsplit

REGISTRATION = Path('/etc/warden-hermes-credentials/registration.json')
STATE = Path('/var/lib/warden-hermes-credentials')
HOST_KEY = Path('/var/lib/systemd/credential.secret')
SOCKET_PATH = Path('/run/warden-hermes-credentials/credentials.sock')

MAX_FRAME = 65536
TIMEOUT = 5.0
ERROR = {'ok': False, 'code': 'credential_store'}
SAFE_ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}


def validate(value, server):
    fields = {'server', 'email', 'master', 'client_id', 'client_secret'}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError()
    if any(not isinstance(value[k], str) or len(value[k]) > 8192 or '\0' in value[k] for k in fields):
        raise ValueError()
    if value['server'] != server or not value['master'] or not value['email']:
        raise ValueError()
    if bool(value['client_id']) != bool(value['client_secret']):
        raise ValueError()
    return value


def receive(conn, count, deadline):
    data = bytearray()
    while len(data) < count:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError()
        conn.settimeout(remaining)
        chunk = conn.recv(count - len(data))
        if not chunk:
            raise ValueError()
        data.extend(chunk)
    return bytes(data)


class Store:
    def __init__(self, path):
        self.path = Path(path)

    def registered(self):
        return self.path.is_file()

    def crypt(self, action, data):
        result = subprocess.run(
            ['/usr/bin/systemd-creds', '--name=warden-hermes-auth', '--with-key=host', action, '-', '-'],
            input=data, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=SAFE_ENV, timeout=4, check=False, close_fds=True)
        if result.returncode or not result.stdout or len(result.stdout) > MAX_FRAME:
            raise ValueError()
        return result.stdout

    def save(self, value):
        encrypted = self.crypt('encrypt', json.dumps(value, ensure_ascii=True).encode())
        fd, temporary = tempfile.mkstemp(prefix='.auth-', dir=self.path.parent)
        try:
            with os.fdopen(fd, 'wb') as output:
                os.fchmod(output.fileno(), 0o600)
                output.write(encrypted)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, self.path)
            directory = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def load(self):
        with self.path.open('rb') as source:
            encrypted = source.read(MAX_FRAME + 1)
        if len(encrypted) > MAX_FRAME:
            raise ValueError()
        return json.loads(self.crypt('decrypt', encrypted))


def handle(conn, registration, store):
    try:
        deadline = time.monotonic() + TIMEOUT
        _, uid, _ = struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid != registration['uid']:
            raise ValueError()
        size = struct.unpack('!I', receive(conn, 4, deadline))[0]
        if not 0 < size <= MAX_FRAME:
            raise ValueError()
        request = json.loads(receive(conn, size, deadline))
        if request.get('server') != registration['server']:
            raise ValueError()
        operation = request.get('operation')
        expected = {'operation', 'server', 'value'} if operation == 'enroll' else {'operation', 'server'}
        if set(request) != expected:
            raise ValueError()
        if operation == 'status':
            value = {'registered': store.registered()}
        elif operation == 'get':
            value = validate(store.load(), registration['server'])
        elif operation == 'enroll':
            store.save(validate(request['value'], registration['server']))
            value = {'registered': True}
        else:
            raise ValueError()
        result = {'ok': True, 'value': value}
    except Exception:
        result = ERROR
    try:
        data = json.dumps(result, ensure_ascii=True).encode()
        conn.settimeout(TIMEOUT)
        conn.sendall(struct.pack('!I', len(data)) + data)
    except Exception:
        pass


def trusted_path(path, private=False):
    """Reject symlinks and any component writable by a non-root identity."""
    path = Path(path)
    if not path.is_absolute():
        raise ValueError()
    for component in (path, *path.parents):
        info = component.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            raise ValueError()
    if private and path.stat().st_mode & 0o077:
        raise ValueError()


def load_registration(path=REGISTRATION):
    trusted_path(path, private=True)
    with path.open('rb') as source:
        raw = source.read(8193)
    if len(raw) > 8192:
        raise ValueError()
    value = json.loads(raw)
    if set(value) != {'uid', 'gid', 'server'}:
        raise ValueError()
    if any(type(value[k]) is not int or not 0 < value[k] < 2**31 for k in ('uid', 'gid')):
        raise ValueError()
    server = value['server']
    if not isinstance(server, str) or not server or len(server) > 2048 or any(ord(c) < 33 for c in server):
        raise ValueError()
    parsed = urlsplit(server)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError()
    return value


def remove_stale_socket(path):
    # Parent was checked separately. Socket group-write is intentional.
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if info.st_uid != 0 or not stat.S_ISSOCK(info.st_mode):
        raise ValueError()
    path.unlink()


def main():
    if os.geteuid() != 0:
        raise ValueError()
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    trusted_path(Path(__file__))
    registration = load_registration()
    trusted_path(STATE, private=True)
    trusted_path(HOST_KEY, private=True)
    trusted_path(SOCKET_PATH.parent)
    store = Store(STATE / 'auth.cred')
    if store.path.exists():
        trusted_path(store.path, private=True)
    remove_stale_socket(SOCKET_PATH)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(SOCKET_PATH))
        os.chown(SOCKET_PATH, 0, registration['gid'])
        os.chmod(SOCKET_PATH, 0o660)
        listener.listen(8)
        while True:
            conn, _ = listener.accept()
            with conn:
                handle(conn, registration, store)


if __name__ == '__main__':
    try:
        main()
    except BaseException:
        # Journald receives neither Python exception text nor secret-bearing data.
        raise SystemExit(1) from None
