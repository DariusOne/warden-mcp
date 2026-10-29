"""Isolated warden-mcp / Vaultwarden interoperability and redaction audit.

Only synthetic credentials and an ephemeral container are used. This script
never reads the production Vaultwarden profile, DPAPI blob or container data.
"""
import base64
import hashlib
import hmac
import http.client
import http.server
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from harness_helpers import docker_command, SyntheticCredentials, write_private, isolated_environment

from cryptography import x509
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

REPO = Path(__file__).resolve().parents[1]
ROOT = REPO / 'agent_tests' / '.runs'
ROOT.mkdir(exist_ok=True)
services = None
DOCKER = os.environ.get('WARDEN_TEST_DOCKER') or (r'C:\Program Files\Docker\Docker\resources\bin\docker.exe' if sys.platform == 'win32' else shutil.which('docker'))
NODE = os.environ['WARDEN_TEST_NODE']
BW = os.environ['WARDEN_TEST_BW']
IMAGE = 'vaultwarden/server@sha256:2bb2e0344616c62a6d76ea10558497499f8ed3f731400e143dc7bf17b757b5b9'
RUN = uuid.uuid4().hex
NAME = 'vw-mcp-audit-' + RUN
LABEL = 'local.codex.audit=' + RUN
PROFILE = ROOT / ('test-profile-' + RUN)
FIXTURES = ROOT / ('fixtures-' + RUN)
REDACTIONS = []
RESULT = {
    'started_utc': datetime.now(timezone.utc).isoformat(),
    'warden_mcp_release': '0.2.60',
    'cli_version': None,
    'vaultwarden_version': '1.37.4',
    'vaultwarden_image': IMAGE,
    'subpath': '/bitwarden',
    'scope': 'loopback HTTPS with ephemeral trusted test CA, isolated container, synthetic account only',
    'production_credentials_accessed': False,
    'production_configuration_modified': False,
    'checks': {},
}
STAGE = 'initialization'
TLS_CONTEXT = None
PROXY = None
PROXY_THREAD = None
CREDENTIALS = None
credential_dir = None


def safe(text):
    for value in sorted(REDACTIONS, key=len, reverse=True):
        if value:
            text = text.replace(value, '[synthetic-secret-redacted]')
    return text[:900]


def run(args, *, env=None, data=None, timeout=120):
    p = subprocess.run(args, input=data, capture_output=True, text=True,
                       encoding='utf-8', errors='replace', env=env, timeout=timeout)
    if p.returncode:
        # stdout can contain full vault objects; never report it on failure.
        raise RuntimeError(f'{STAGE}: subprocess exit {p.returncode} (details suppressed)')
    return p.stdout.strip()


def docker(*args):
    return run([*docker_command(DOCKER), *args])


def post(url, body):
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={'Content-Type': 'application/json', 'Accept': 'application/json'})
    with urllib.request.urlopen(req, timeout=20, context=TLS_CONTEXT) as response:
        raw = response.read()
        return json.loads(raw) if raw else None


def enc(data, key):
    iv = secrets.token_bytes(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key[:32]), modes.CBC(iv)).encryptor()
    cipher = encryptor.update(padded) + encryptor.finalize()
    mac = hmac.new(key[32:], iv + cipher, hashlib.sha256).digest()
    return '2.' + '|'.join(base64.b64encode(x).decode() for x in (iv, cipher, mac))


def clean_test_dir(path):
    resolved = path.resolve()
    if resolved.parent != ROOT or not (resolved.name.startswith('test-profile-') or resolved.name.startswith('fixtures-')):
        raise RuntimeError('Unsafe test cleanup target')
    if resolved.exists():
        shutil.rmtree(resolved)


def start_tls_proxy(upstream_port):
    """Preserve subpath/Host behind a loopback-only, ephemeral TLS proxy."""
    global TLS_CONTEXT, PROXY, PROXY_THREAD
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    ca_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'Isolated MCP audit CA')])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
          .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                      key_encipherment=False, data_encipherment=False, key_agreement=False,
                                      key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
          .sign(ca_key, hashes.SHA256()))
    leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'localhost')]))
            .issuer_name(ca_name).public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'),
                                                       x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    ca_path = FIXTURES / 'test-ca.pem'
    cert_path = FIXTURES / 'test-server.pem'
    key_path = FIXTURES / 'test-server-key.pem'
    write_private(ca_path, ca.public_bytes(serialization.Encoding.PEM))
    write_private(cert_path, leaf.public_bytes(serialization.Encoding.PEM))
    write_private(key_path, leaf_key.private_bytes(serialization.Encoding.PEM,
                                              serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    TLS_CONTEXT = ssl.create_default_context(cafile=str(ca_path))

    class ProxyHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def forward(self):
            body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
            headers = {k: v for k, v in self.headers.items() if k.lower() not in ('connection', 'transfer-encoding')}
            headers['X-Forwarded-Proto'] = 'https'
            upstream = http.client.HTTPConnection('127.0.0.1', upstream_port, timeout=30)
            try:
                upstream.request(self.command, self.path, body=body, headers=headers)
                response = upstream.getresponse()
                content = response.read()
                self.send_response(response.status)
                for k, v in response.getheaders():
                    if k.lower() not in ('connection', 'transfer-encoding', 'content-length'):
                        self.send_header(k, v)
                self.send_header('Content-Length', str(len(content)))
                self.end_headers()
                self.wfile.write(content)
            except (ConnectionError, OSError, http.client.HTTPException):
                self.send_error(502)
            finally:
                upstream.close()

        do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = forward

    PROXY = http.server.ThreadingHTTPServer(('127.0.0.1', 0), ProxyHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert_path), str(key_path))
    PROXY.socket = ctx.wrap_socket(PROXY.socket, server_side=True)
    PROXY_THREAD = threading.Thread(target=PROXY.serve_forever, daemon=True)
    PROXY_THREAD.start()
    return PROXY.server_address[1], ca_path


try:
    PROFILE.mkdir(mode=0o700)
    FIXTURES.mkdir(mode=0o700)
    (FIXTURES / "state").mkdir(mode=0o700)
    # NAS shared-directory ACLs may override mkdir's requested mode. Apply and
    # verify private modes explicitly; never weaken the production check.
    for directory in (PROFILE, FIXTURES, FIXTURES / 'state'):
        directory.chmod(0o700)
    env = isolated_environment(os.environ)
    env['BITWARDENCLI_APPDATA_DIR'] = str(PROFILE)
    env['NO_PROXY'] = '127.0.0.1,localhost'
    env['no_proxy'] = env['NO_PROXY']
    STAGE = 'cli-version'
    RESULT['cli_version'] = run([BW, '--version'], env=env)
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
    tls_port, ca_path = start_tls_proxy(port)
    env['NODE_EXTRA_CA_CERTS'] = str(ca_path)
    base = f'https://127.0.0.1:{tls_port}/bitwarden'
    STAGE = 'start-ephemeral-container'
    docker('run', '--detach', '--pull=never', '--name', NAME, '--label', LABEL,
           '--publish', f'127.0.0.1:{port}:80', '--tmpfs', '/data:rw,size=128m',
           '--env', 'DOMAIN=' + base, '--env', 'SIGNUPS_ALLOWED=true',
           '--env', 'SIGNUPS_VERIFY=false', '--env', 'PUSH_ENABLED=false',
           '--env', 'DISABLE_ICON_DOWNLOAD=true', '--env', 'WEB_VAULT_ENABLED=false',
           '--env', 'LOG_LEVEL=error', IMAGE)
    STAGE = 'wait-for-isolated-server'
    ready = False
    readiness_error = None
    for _ in range(40):
        try:
            with urllib.request.urlopen(base + '/api/config', timeout=2, context=TLS_CONTEXT) as response:
                config = json.load(response)
            ready = True
            break
        except Exception as exc:
            readiness_error = str(exc)
            time.sleep(0.5)
    if not ready:
        raise RuntimeError('Isolated Vaultwarden did not become ready: ' + safe(readiness_error or 'unknown'))
    RESULT['checks']['subpath_api_config'] = True

    STAGE = 'register-synthetic-account'
    email = 'mcp-audit-' + RUN + '@example.invalid'
    master = secrets.token_urlsafe(36)
    REDACTIONS.append(master)
    master_key = hashlib.pbkdf2_hmac('sha256', master.encode(), email.encode(), 600000, 32)
    auth_hash = base64.b64encode(hashlib.pbkdf2_hmac('sha256', master_key, master.encode(), 1, 32)).decode()
    stretched = b''.join(HKDFExpand(algorithm=hashes.SHA256(), length=32, info=info).derive(master_key)
                         for info in (b'enc', b'mac'))
    user_key = secrets.token_bytes(64)
    keypair = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = base64.b64encode(keypair.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
    private_key = keypair.private_bytes(serialization.Encoding.DER,
                                       serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    token = post(base + '/identity/accounts/register/send-verification-email',
                 {'email': email, 'name': 'Synthetic MCP audit', 'receiveMarketingEmails': False})
    REDACTIONS.extend([token, auth_hash])
    post(base + '/identity/accounts/register/finish', {
        'email': email, 'emailVerificationToken': token,
        'masterPasswordHash': auth_hash, 'key': enc(user_key, stretched),
        'kdf': 0, 'kdfIterations': 600000,
        'keys': {'publicKey': public_key, 'encryptedPrivateKey': enc(private_key, user_key)},
        'masterPasswordHint': None,
    })
    RESULT['checks']['synthetic_registration'] = True
    STAGE = 'isolated-cli-login'
    run([BW, 'config', 'server', base], env=env)
    login_env = dict(env, MCP_AUDIT_MASTER=master)
    session = run([BW, 'login', email, '--passwordenv', 'MCP_AUDIT_MASTER', '--raw'], env=login_env)
    if not session or '\n' in session:
        raise RuntimeError('Synthetic session was not returned in expected format')
    REDACTIONS.append(session)
    env['BW_SESSION'] = session
    RESULT['checks']['cli_login_subpath'] = True
    STAGE = 'seed-synthetic-entry'
    markers = {
        'password': secrets.token_urlsafe(28),
        'totp': base64.b32encode(secrets.token_bytes(20)).decode().rstrip('='),
        'hidden': 'hidden-' + secrets.token_urlsafe(20),
        'notes': 'notes-' + secrets.token_urlsafe(20),
        'ordinary': 'ordinary-' + secrets.token_urlsafe(20),
        'uri_token': 'uri-' + secrets.token_urlsafe(20),
        'ssh_private': 'ssh-private-' + secrets.token_urlsafe(20),
        'attachment': 'attachment-' + secrets.token_urlsafe(20),
        'send': 'send-' + secrets.token_urlsafe(20),
    }
    REDACTIONS.extend(markers.values())
    seed = {'type': 1, 'name': 'Synthetic audit ' + markers['hidden'] + ' ' + base64.b64encode(markers['password'].encode()).decode(), 'notes': markers['notes'],
            'login': {'username': 'synthetic-user-' + markers['ordinary'], 'password': markers['password'], 'totp': markers['totp'],
                      'uris': [{'uri': 'https://example.invalid/login?token=' + markers['uri_token'], 'match': None}]},
            'fields': [{'name': 'Synthetic hidden value', 'value': markers['hidden'], 'type': 1},
                       {'name': 'password', 'value': markers['ordinary'], 'type': 0},
                       {'name': 'private_key', 'value': markers['ssh_private'], 'type': 0}]}
    payload = base64.b64encode(json.dumps(seed).encode()).decode()
    created = json.loads(run([BW, 'create', 'item', payload], env=env))
    RESULT['checks']['cli_seed_entry'] = bool(created.get('id'))
    upload = FIXTURES / 'synthetic-attachment.txt'
    write_private(upload, markers['attachment'])
    download = FIXTURES / 'download'
    download.mkdir()
    STAGE = 'seed-synthetic-attachment-and-send'
    attached = json.loads(run([BW, 'create', 'attachment', '--file', str(upload), '--itemid', created['id']], env=env))
    attachment_id = attached['attachments'][0]['id']
    send = json.loads(run([BW, 'send', '--name', 'Synthetic audit Send', '--deleteInDays', '1', '--fullObject', '--raw', '--', markers['send']], env=env))
    RESULT['checks']['synthetic_attachment_and_send'] = bool(attachment_id and send.get('id'))
    STAGE = 'agent-safe-protocol-tests'
    from services import Services
    services = Services(FIXTURES, markers, DOCKER, RUN)
    services.start()
    ids = {}
    for kind, uri in [('ssh', f'ssh://127.0.0.1:{services.ssh_port}'), ('mysql', f'mysql://127.0.0.1:{services.mysql_port}/agent_test'), ('web', services.web_url)]:
        new_item = dict(seed, name='Synthetic ' + kind, login=dict(seed['login'],username='tester',uris=[{'uri':uri,'match':None}]))
        encoded = base64.b64encode(json.dumps(new_item).encode()).decode()
        ids[kind] = json.loads(run([BW, 'create', 'item', encoded], env=env))['id']
    sys.path.insert(0,str(REPO / 'agent_worker'))
    auth = {'email':email,'master':master,'server':base,'client_id':'','client_secret':''}
    cfg = {'server':base,'bw':BW,'python':sys.executable,'worker':str(REPO/'agent_tests/fixture_worker.py')}
    if sys.platform == 'win32':
        from bridge_core import dpapi
        write_private(FIXTURES/'state/auth.dpapi', dpapi(json.dumps(auth).encode()))
        RESULT['credential_fixture'] = 'Windows DPAPI'
    else:
        import tempfile
        credential_dir = Path(tempfile.mkdtemp(prefix='wcred-', dir=os.environ.get('TMPDIR')))
        credential_dir.chmod(0o700)
        cfg['credential_socket'] = str(credential_dir/'c.sock')
        cfg['browser_executable'] = os.environ['WARDEN_TEST_BROWSER']
        CREDENTIALS = SyntheticCredentials(cfg['credential_socket'], auth)
        CREDENTIALS.__enter__()
        RESULT['credential_fixture'] = 'test-only same-UID in-memory UNIX socket'
        RESULT['root_encrypted_service_validation'] = 'not covered by this synthetic fixture'
    write_private(FIXTURES/'config.json', json.dumps(cfg))
    write_private(FIXTURES/'access.json', json.dumps({'enabled':True,'allow_all':True,'items':[]}))
    if sys.platform == 'linux':
        (FIXTURES/'state/cli').mkdir(mode=0o700,exist_ok=True)
        (FIXTURES/'state/cli').chmod(0o700)
    client_env = isolated_environment(env)
    proc = subprocess.run([NODE,str(REPO/'agent_tests/client.mjs')],input=json.dumps({'root':str(FIXTURES),'base':base,'bw':BW,'python':sys.executable,'email':email,'master':master,'itemId':created['id'],'ids':ids,'markers':markers,'attachmentId':attachment_id,'sendId':send['id'],'webUrl':services.web_url}),capture_output=True,text=True,encoding='utf-8',errors='replace',env=client_env,timeout=900)
    if proc.returncode:
        raise RuntimeError('Protocol harness failed (details suppressed)')
    RESULT['mcp'] = json.loads(proc.stdout)
    RESULT['checks']['web_received_correct_password_and_totp'] = bool(services.web_received and all(x['password_ok'] and x['totp_valid'] for x in services.web_received))
    if not RESULT['mcp'].get('completed') or not RESULT['checks']['web_received_correct_password_and_totp']:
        raise RuntimeError('Protocol validation incomplete')
    RESULT['completed'] = True
except Exception as exc:
    RESULT['completed'] = False
    RESULT['failure_stage'] = STAGE
    RESULT['error'] = safe(str(exc))
finally:
    if services is not None:
        try:
            services.close()
            RESULT['temporary_service_fixtures_stopped'] = True
        except Exception as exc:
            RESULT['temporary_service_fixtures_stopped'] = False
            RESULT['cleanup_error'] = safe(str(exc))
    if CREDENTIALS is not None:
        try:
            CREDENTIALS.__exit__()
            if credential_dir is not None: credential_dir.rmdir()
            RESULT['temporary_credential_fixture_stopped'] = True
        except Exception as exc:
            RESULT['cleanup_error'] = safe(str(exc))
    if PROXY is not None:
        PROXY.shutdown()
        PROXY.server_close()
        if PROXY_THREAD is not None:
            PROXY_THREAD.join(timeout=5)
        RESULT['temporary_tls_proxy_stopped'] = True
    try:
        found = docker('ps', '-a', '--filter', 'name=^/' + NAME + '$', '--filter', 'label=' + LABEL,
                       '--format', '{{.Names}}')
        if found:
            if found != NAME:
                raise RuntimeError('Unexpected container cleanup identity')
            docker('rm', '-f', NAME)
        if docker('ps', '-a', '--filter', 'name=^/' + NAME + '$', '--filter', 'label=' + LABEL, '--format', '{{.Names}}'):
            raise RuntimeError('Isolated container still present after removal')
        RESULT['temporary_container_removed'] = True
    except Exception as exc:
        RESULT['temporary_container_removed'] = False
        RESULT['cleanup_error'] = safe(str(exc))
    for directory in (PROFILE, FIXTURES):
        try:
            clean_test_dir(directory)
        except Exception as exc:
            RESULT['cleanup_error'] = safe(str(exc))
    RESULT['temporary_cli_profile_removed'] = not PROFILE.exists()
    RESULT['finished_utc'] = datetime.now(timezone.utc).isoformat()
    write_private(ROOT / 'audit-results.json', json.dumps(RESULT, ensure_ascii=False, indent=2))
    print(json.dumps(RESULT, ensure_ascii=False, indent=2))

sys.exit(0 if RESULT.get('completed') and RESULT.get('temporary_container_removed') and not RESULT.get('cleanup_error') else 1)
