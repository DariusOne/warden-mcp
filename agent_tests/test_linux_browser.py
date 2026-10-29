"""Isolated browser tests: synthetic vault items, no host browser or secrets."""
import contextlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'agent_worker'))
from browser_worker import BrowserWorker
from bridge_core import BridgeError, Redactor


@contextlib.contextmanager
def synthetic_https_fixture(root):
    """Local pinned HTTPS, synthetic persistent cookie and no external traffic."""
    import base64
    from datetime import datetime, timedelta, timezone
    import http.server
    import ipaddress
    import ssl
    import threading
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Synthetic cleanup fixture')])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), False)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = root / 'test-cert.pem', root / 'test-key.pem'
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    key_path.chmod(0o600)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
    pin = base64.b64encode(digest.finalize()).decode()

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass
        def do_GET(self):
            body = b'<title>Synthetic cleanup fixture</title><body>fixture</body>'
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Set-Cookie', 'synthetic_cookie=synthetic-value; Max-Age=3600; Secure; HttpOnly; SameSite=Strict')
            self.end_headers()
            self.wfile.write(body)

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert_path, key_path)
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'https://127.0.0.1:{server.server_port}/login', pin
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@unittest.skipUnless(sys.platform == 'linux', 'Linux browser')
class LinuxBrowserTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='warden-browser-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.executable = self.root / 'dedicated-chromium'
        self.executable.write_text('#!/bin/false\n')
        self.executable.chmod(0o700)
        self.config(browser_executable=str(self.executable))
        self.item = {'id': 'synthetic', 'login': {'uris': [{'uri': 'https://allowed.invalid/login'}]}}
        self.broker = SimpleNamespace(root=self.root, redactor=Redactor(), get_item=lambda _: self.item)
        self.worker = BrowserWorker(self.broker)
        self.chromium = Mock()
        self.worker.pw = SimpleNamespace(chromium=self.chromium)
        self.worker.do_state = lambda page_id: {'page_id': page_id}
        self.addCleanup(lambda: self.worker.do_close_all())

    def config(self, **values):
        path = self.root / 'config.json'
        path.write_text(json.dumps(values))
        path.chmod(0o600)

    def test_invalid_executable_fails_closed(self):
        linked = self.root / 'linked-chromium'
        linked.symlink_to(self.executable)
        for executable in (None, '', 'chromium', str(self.root / 'absent'), str(linked), str(self.root)):
            with self.subTest(executable=executable):
                self.config(browser_executable=executable)
                with self.assertRaises(BridgeError) as caught:
                    self.worker.do_open('synthetic')
                self.assertEqual(caught.exception.code, 'browser_config')
        self.chromium.launch_persistent_context.assert_not_called()

    def test_symlink_profile_parent_is_rejected_without_touching_target(self):
        outside = self.root / 'not-a-browser-profile'
        outside.mkdir(mode=0o755)
        outside.chmod(0o755)
        (self.root / 'state').symlink_to(outside, target_is_directory=True)
        with self.assertRaises(BridgeError) as caught:
            self.worker.do_open('synthetic')
        self.assertEqual(caught.exception.code, 'browser_config')
        self.assertEqual(stat.S_IMODE(outside.stat().st_mode), 0o755)
        self.assertEqual(list(outside.iterdir()), [])
        self.chromium.launch_persistent_context.assert_not_called()

    def test_sandbox_and_profile_overrides_are_never_accepted(self):
        for arg in ('--no-sandbox', '--disable-setuid-sandbox', '--user-data-dir=/home/user/daily',
                    '--remote-debugging-port=9222', '--ignore-certificate-errors'):
            with self.subTest(arg=arg):
                self.worker.test_options = {'launch_args': [arg]}
                with self.assertRaises(BridgeError) as caught:
                    self.worker.do_open('synthetic')
                self.assertEqual(caught.exception.code, 'browser_config')
        self.chromium.launch_persistent_context.assert_not_called()

    def test_profiles_are_never_reused_and_removed_on_close(self):
        contexts = [Mock(), Mock()]
        self.chromium.launch_persistent_context.side_effect = contexts
        self.worker.do_open('synthetic')
        self.worker.do_open('synthetic')
        profiles = [Path(call.kwargs['user_data_dir']) for call in self.chromium.launch_persistent_context.call_args_list]
        self.assertNotEqual(profiles[0], profiles[1])
        self.worker.do_close_all()
        for context, profile in zip(contexts, profiles):
            context.close.assert_called_once()
            self.assertFalse(profile.exists(), 'private cookies must not survive normal close')
        self.assertEqual(self.worker.pages, {})

    def test_launch_failure_removes_profile_without_sandbox_downgrade(self):
        self.chromium.launch_persistent_context.side_effect = RuntimeError('sandbox unavailable')
        with self.assertRaises(RuntimeError):
            self.worker.do_open('synthetic')
        self.chromium.launch_persistent_context.assert_called_once()
        profile = Path(self.chromium.launch_persistent_context.call_args.kwargs['user_data_dir'])
        self.assertFalse(profile.exists())

    def test_windows_keeps_edge_with_explicit_sandbox(self):
        with patch('browser_worker.sys.platform', 'win32'):
            self.worker.do_open('synthetic')
        args = self.chromium.launch.call_args.kwargs
        self.assertEqual(args['channel'], 'msedge')
        self.assertIs(args.get('chromium_sandbox'), True)
        self.chromium.launch_persistent_context.assert_not_called()

    @unittest.skipUnless(os.environ.get('WARDEN_TEST_BROWSER'), 'Set dedicated test Chromium executable')
    def test_real_sandboxed_https_browser_preserves_secret_and_origin_rules(self):
        import base64
        from datetime import datetime, timedelta, timezone
        import http.server
        import ipaddress
        import ssl
        import threading
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Synthetic browser fixture')])
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=1))
                .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), False)
                .sign(key, hashes.SHA256()))
        cert_path, key_path = self.root / 'test-cert.pem', self.root / 'test-key.pem'
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        cert_path.chmod(0o600)
        key_path.chmod(0o600)
        digest = hashes.Hash(hashes.SHA256())
        digest.update(key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
        pin = base64.b64encode(digest.finalize()).decode()
        secret = 'synthetic-password-browser-fixture'
        html = (f'<title>Fixture</title><body>{secret}'
                '<form action="/submit"><input name="username"><input name="password" type="password"></form>'
                '<form action="https://blocked.invalid/submit"><input name="bad" type="password"></form>'
                '<img src="https://blocked.invalid/pixel"></body>').encode()

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass
            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.send_header('Content-Length', str(len(html)))
                self.end_headers()
                self.wfile.write(html)

        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert_path, key_path)
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        url = f'https://127.0.0.1:{server.server_port}/login'
        self.item['login'] = {'uris': [{'uri': url}], 'username': 'synthetic-user', 'password': secret}
        self.broker.redactor.add(secret)
        self.config(browser_executable=os.environ['WARDEN_TEST_BROWSER'])
        self.worker = BrowserWorker(self.broker, test_options={'headless': True, 'launch_args': ['--ignore-certificate-errors-spki-list=' + pin]})
        try:
            state = self.worker.call('open', item_id='synthetic')
            self.assertNotIn(secret, json.dumps(state))
            self.assertEqual(state['title'], 'Fixture')
            page_id = state['page_id']
            state = self.worker.call('state', page_id=page_id)
            self.assertGreater(state['blocked_external_requests'], 0)
            refs = {control['name']: control['ref'] for control in state['controls']}
            filled = self.worker.call('fill_login', page_id=page_id, password_ref=refs['password'], username_ref=refs['username'])
            self.assertEqual(filled, {'filled': True, 'page_id': page_id, 'submitted': False})
            with self.assertRaises(BridgeError) as caught:
                self.worker.call('fill_login', page_id=page_id, password_ref=refs['bad'])
            self.assertEqual(caught.exception.code, 'form_origin')
            with self.assertRaises(BridgeError):
                self.worker.call('open', item_id='synthetic', url='http://127.0.0.1/login')
            with self.assertRaises(BridgeError):
                self.worker.call('open', item_id='synthetic', url='https://blocked.invalid/login')
            profiles = list(self.worker.profiles.values())
            self.assertTrue(profiles)
            self.worker.call('close_all')
            self.assertTrue(all(not profile.exists() for profile in profiles))
        finally:
            if self.worker.thread and self.worker.thread.is_alive():
                self.worker.call('close_all')

    def test_browser_home_and_cache_stay_inside_fresh_profile(self):
        self.worker.do_open('synthetic')
        options = self.chromium.launch_persistent_context.call_args.kwargs
        profile = Path(options['user_data_dir'])
        env = options.get('env', {})
        for key in ('HOME', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME'):
            self.assertIn(key, env)
            self.assertTrue(Path(env[key]).is_relative_to(profile), key)

    def test_launch_uses_sandbox_and_fresh_private_runtime_profile(self):
        self.worker.do_open('synthetic')
        self.chromium.launch.assert_not_called()
        self.chromium.connect_over_cdp.assert_not_called()
        self.chromium.launch_persistent_context.assert_called_once()
        args = self.chromium.launch_persistent_context.call_args.kwargs
        self.assertIs(args['chromium_sandbox'], True)
        self.assertIs(args['headless'], True)
        self.assertEqual(args['executable_path'], str(self.executable))
        self.assertNotIn('channel', args)
        self.assertNotIn('--no-sandbox', args.get('args', []))
        profile = Path(args['user_data_dir'])
        self.assertEqual(profile.parent, self.root / 'state' / 'browser')
        for directory in (profile, profile.parent, profile.parent.parent):
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        self.assertFalse(args['ignore_https_errors'])
        self.assertEqual(args['service_workers'], 'block')
        self.assertFalse(args['accept_downloads'])


if __name__ == '__main__':
    unittest.main()
