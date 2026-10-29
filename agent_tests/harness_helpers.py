"""Portability helpers used only by the isolated synthetic audit."""
import os
import sys


def docker_command(executable, platform=None, environ=None):
    platform = sys.platform if platform is None else platform
    environ = os.environ if environ is None else environ
    context = environ.get('WARDEN_TEST_DOCKER_CONTEXT', 'desktop-linux' if platform == 'win32' else 'default')
    return [executable, '--context', context]


def isolated_environment(environ):
    return {k:v for k,v in environ.items() if not k.upper().startswith(('BW_', 'BITWARDEN', 'KEYCHAIN_')) and k.upper() not in ('NODE_OPTIONS','NODE_TLS_REJECT_UNAUTHORIZED')}


def write_private(path, data):
    path.write_bytes(data.encode('utf-8') if isinstance(data,str) else data)
    path.chmod(0o600)


class SyntheticCredentials:
    """Test-only same-UID socket; NOT encrypted/root credential validation."""
    def __init__(self, path, auth):
        from pathlib import Path
        self.path, self.auth = Path(path), auth
        self.closed = False

    def __enter__(self):
        import socket, threading
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.bind(str(self.path))
        self.path.chmod(0o600)
        self.sock.listen(4)
        self.sock.settimeout(0.2)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()
        return self

    def _serve(self):
        import json, socket, struct
        def receive(conn, size):
            data = b''
            while len(data) < size:
                chunk = conn.recv(size-len(data))
                if not chunk: raise ValueError('short frame')
                data += chunk
            return data
        while not self.closed:
            try: conn, _ = self.sock.accept()
            except (socket.timeout, OSError): continue
            with conn:
                try:
                    conn.settimeout(2)
                    _, uid, _ = struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                    if uid != os.getuid(): raise ValueError('peer')
                    size = struct.unpack('!I', receive(conn, 4))[0]
                    if not 0 < size <= 65536: raise ValueError('frame')
                    request = json.loads(receive(conn, size))
                    if set(request) != {'operation','server'} or request['server'] != self.auth['server']: raise ValueError('request')
                    if request['operation'] == 'get': result = {'ok':True,'value':self.auth}
                    elif request['operation'] == 'status': result = {'ok':True,'value':{'registered':True}}
                    else: raise ValueError('operation')
                except Exception: result = {'ok':False,'code':'credential_store'}
                try:
                    data = json.dumps(result).encode()
                    conn.sendall(struct.pack('!I',len(data))+data)
                except OSError: pass

    def __exit__(self, *_):
        self.closed = True
        self.sock.close()
        self.thread.join(timeout=3)
        self.path.unlink(missing_ok=True)
        self.auth = {}


def _process(pid):
    from pathlib import Path
    try:
        path = Path('/proc') / str(pid)
        stat = (path/'stat').read_text().rsplit(')', 1)[1].split()
        return {'pid':int(pid), 'ppid':int(stat[1]), 'start':stat[19], 'state':stat[0]}
    except (OSError, ValueError, IndexError):
        return None


def probe_processes(root_pid, markers):
    from pathlib import Path
    rows = [p for entry in Path('/proc').iterdir() if entry.name.isdigit() and (p := _process(entry.name))]
    ids = {int(root_pid)}
    while True:
        more = {p['pid'] for p in rows if p['ppid'] in ids} - ids
        if not more: break
        ids.update(more)
    children = [p for p in rows if p['pid'] in ids]
    for p in children:
        try: p['argv'] = (Path('/proc')/str(p['pid'])/'cmdline').read_bytes().decode(errors='replace').split('\0')
        except OSError: p['argv'] = []
    return {'secret_args':any(s and s in arg for p in children for arg in p['argv'] for s in markers),
            'session_argument':any(arg == '--session' or arg.startswith('--session=') for p in children for arg in p['argv']),
            'unsafe_browser_argument':any(arg in ('--no-sandbox','--disable-setuid-sandbox','--ignore-certificate-errors') or arg.startswith('--remote-debugging-port=') for p in children for arg in p['argv']),
            'children_observed':sum(p['pid'] != int(root_pid) for p in children),
            'identities':[{'pid':p['pid'],'start':p['start']} for p in children]}


def valid_totp(seed, value, now=None):
    import base64, hashlib, hmac, struct, time
    if len(value) != 6 or not value.isascii() or not value.isdigit(): return False
    counter = int(time.time() if now is None else now) // 30
    key = base64.b32decode(seed + '=' * (-len(seed) % 8))
    for shift in (-1,0,1):
        if counter + shift < 0: continue
        digest = hmac.new(key, struct.pack('!Q',counter+shift), hashlib.sha1).digest()
        offset = digest[-1] & 15
        expected = str((int.from_bytes(digest[offset:offset+4], 'big') & 0x7fffffff) % 1000000).zfill(6)
        if hmac.compare_digest(expected, value): return True
    return False


def alive_identities(identities):
    return [identity for identity in identities if (p := _process(identity['pid'])) and p['start'] == identity['start'] and p['state'] != 'Z']
