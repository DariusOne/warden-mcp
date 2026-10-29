"""Private worker credential provider; Linux never reads Windows DPAPI files."""
import json
import os
import socket
import struct
import sys
import time

ROOT_UID = 0
MAX_FRAME = 65536
TIMEOUT = 5.0
SOCKET_PATH = '/run/warden-hermes-credentials/credentials.sock'


class CredentialError(Exception):
    def __init__(self):
        super().__init__('Credential provider unavailable')
        self.code = 'credential_store'


def _receive(conn, count, deadline):
    data = bytearray()
    while len(data) < count:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise CredentialError()
        conn.settimeout(remaining)
        chunk = conn.recv(count - len(data))
        if not chunk:
            raise CredentialError()
        data.extend(chunk)
    return bytes(data)


def request(config, operation, value=None):
    """One bounded request, authenticated root peer, no fallback transport."""
    try:
        path = config['credential_socket']
        if not isinstance(path, str) or not os.path.isabs(path) or '\0' in path:
            raise CredentialError()
        payload = {'operation': operation, 'server': config['server']}
        if value is not None:
            payload['value'] = value
        data = json.dumps(payload, ensure_ascii=True).encode()
        if len(data) > MAX_FRAME:
            raise CredentialError()
        deadline = time.monotonic() + TIMEOUT
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(TIMEOUT)
            conn.connect(path)
            _, uid, _ = struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != ROOT_UID:
                raise CredentialError()
            conn.sendall(struct.pack('!I', len(data)) + data)
            size = struct.unpack('!I', _receive(conn, 4, deadline))[0]
            if not 0 < size <= MAX_FRAME:
                raise CredentialError()
            result = json.loads(_receive(conn, size, deadline))
            if result.get('ok') is not True:
                raise CredentialError()
            return result['value']
    except Exception:
        raise CredentialError() from None


def credential_status(root, config):
    if sys.platform == 'win32':
        return {'registered': (root / 'state' / 'auth.dpapi').is_file()}
    if sys.platform.startswith('linux'):
        value = request(config, 'status')
        if isinstance(value, dict) and set(value) == {'registered'} and type(value['registered']) is bool:
            return value
    raise CredentialError()


def load_credentials(root, config):
    try:
        if sys.platform == 'win32':
            from bridge_core import dpapi
            value = json.loads(dpapi((root / 'state' / 'auth.dpapi').read_bytes(), decrypt=True))
        elif sys.platform.startswith('linux'):
            value = request(config, 'get')
        else:
            raise CredentialError()
        if value.get('server') == config['server']:
            return value
    except Exception:
        pass
    raise CredentialError() from None
