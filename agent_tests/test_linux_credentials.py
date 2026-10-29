"""Synthetic-only credential boundary tests; no production paths are modified."""
import importlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'agent_worker'))
if not sys.platform.startswith('linux'):
    raise unittest.SkipTest('Linux credential boundary tests')


def module(name):
    return importlib.import_module(name)


class ProviderTests(unittest.TestCase):
    def test_windows_retains_dpapi_payload(self):
        c = module('credentials')
        auth = {'server': 'https://example.invalid', 'email': 'test@example.invalid',
                'master': 'synthetic-master', 'client_id': '', 'client_secret': ''}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'state').mkdir()
            (root / 'state/auth.dpapi').write_bytes(b'synthetic-ciphertext')
            with patch.object(c.sys, 'platform', 'win32'), patch('bridge_core.dpapi', return_value=json.dumps(auth).encode()) as decrypt:
                self.assertEqual(c.load_credentials(root, {'server': auth['server']}), auth)
                decrypt.assert_called_once_with(b'synthetic-ciphertext', decrypt=True)

    def test_linux_socket_round_trip_and_root_peer_check(self):
        c = module('credentials')
        self.assertTrue(hasattr(c, 'request'), 'UNIX socket provider missing')
        auth = {'server': 'https://example.invalid', 'email': 'test@example.invalid',
                'master': 'synthetic-master', 'client_id': '', 'client_secret': ''}
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / 'credentials.sock')
            with socket.socket(socket.AF_UNIX) as listener:
                listener.bind(path)
                listener.listen(2)
                def serve():
                    for _ in range(2):
                        conn, _ = listener.accept()
                        with conn:
                            try:
                                size = struct.unpack('!I', conn.recv(4))[0]
                                request = json.loads(conn.recv(size))
                                self.assertEqual(request, {'operation': 'get', 'server': auth['server']})
                                data = json.dumps({'ok': True, 'value': auth}).encode()
                                conn.sendall(struct.pack('!I', len(data)) + data)
                            except (OSError, struct.error):
                                pass
                thread = threading.Thread(target=serve, daemon=True)
                thread.start()
                with patch.object(c, 'ROOT_UID', os.getuid()):
                    self.assertEqual(c.load_credentials(Path(directory), {'server': auth['server'], 'credential_socket': path}), auth)
                with patch.object(c, 'ROOT_UID', os.getuid() + 1):
                    with self.assertRaises(c.CredentialError):
                        c.load_credentials(Path(directory), {'server': auth['server'], 'credential_socket': path})
                thread.join(3)
                self.assertFalse(thread.is_alive())

    def test_worker_exposes_nonsecret_registration_probe(self):
        import io
        w = module('worker')
        self.assertTrue(hasattr(w, 'credential_status'), 'worker status probe missing')
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / 'config.json').write_text('{"server":"https://example.invalid"}')
            output = io.StringIO()
            with patch.object(w, 'contain_children', return_value=True), patch.object(w, 'credential_status', return_value={'registered': False}), patch.object(w.sys, 'argv', ['worker.py', directory]), patch.object(w.sys, 'stdin', io.StringIO('{"id":2,"operation":"credential_status"}\n')), patch.object(w.sys, 'stdout', output):
                w.main()
            self.assertEqual(json.loads(output.getvalue()), {'id': 2, 'ok': True, 'value': {'registered': False}})

    def test_worker_uses_provider_and_returns_constant_error(self):
        import io
        w = module('worker')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'config.json').write_text(json.dumps({'server': 'https://example.invalid'}))
            output = io.StringIO()
            with patch.object(w, 'contain_children', return_value=True), patch.object(w.sys, 'argv', ['worker.py', directory]), patch.object(w.sys, 'stdin', io.StringIO('{"id":1,"operation":"credentials"}\n')), patch.object(w.sys, 'stdout', output):
                w.main()
            self.assertEqual(json.loads(output.getvalue()), {'id': 1, 'ok': False, 'code': 'credential_store'})

    def test_provider_rejects_paths_mismatch_and_bad_status_without_fallback(self):
        c = module('credentials')
        for path in [None, '', 'relative.sock', 'http://localhost/', '\0bad']:
            with self.subTest(path=path), self.assertRaises(c.CredentialError):
                c.load_credentials(Path('.'), {'server': 'https://example.invalid', 'credential_socket': path})
        with patch.object(c, 'request', return_value={'server': 'https://other.invalid'}), self.assertRaises(c.CredentialError):
            c.load_credentials(Path('.'), {'server': 'https://example.invalid'})
        with patch.object(c, 'request', return_value={'registered': 'yes'}), self.assertRaises(c.CredentialError):
            c.credential_status(Path('.'), {'server': 'https://example.invalid'})

    def test_missing_linux_provider_never_reads_dpapi(self):
        self.assertIsNotNone(importlib.util.find_spec('credentials'), 'credential provider missing')
        c = module('credentials')
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(Path, 'read_bytes', side_effect=AssertionError('must not read DPAPI')):
                with self.assertRaises(c.CredentialError) as result:
                    c.load_credentials(Path(directory), {'server': 'https://example.invalid'})
        self.assertEqual(str(result.exception), 'Credential provider unavailable')


class ServiceTests(unittest.TestCase):
    def exchange(self, store, request, uid=None):
        s = module('linux_credentials_service')
        left, right = socket.socketpair()
        with left, right:
            left.settimeout(3)
            registration = {'uid': os.getuid() if uid is None else uid, 'server': 'https://example.invalid'}
            thread = threading.Thread(target=s.handle, args=(right, registration, store))
            thread.start()
            data = json.dumps(request).encode()
            left.sendall(struct.pack('!I', len(data)) + data)
            size = struct.unpack('!I', left.recv(4))[0]
            result = json.loads(left.recv(size))
            thread.join(3)
            self.assertFalse(thread.is_alive())
            return result

    def test_enroll_real_encryption_protocol_round_trip_with_decrypt_test_double(self):
        s = module('linux_credentials_service')
        self.assertTrue(hasattr(s.Store, 'save'), 'encrypted enrollment missing')
        import subprocess
        original_run = subprocess.run
        auth = {'server': 'https://example.invalid', 'email': 'test@example.invalid',
                'master': 'synthetic-master', 'client_id': 'synthetic-id', 'client_secret': 'synthetic-secret'}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'keys').mkdir()
            (root / 'cipher').mkdir()
            path = root / 'cipher/auth.cred'
            def isolated_run(args, **kwargs):
                self.assertEqual(args[0], '/usr/bin/systemd-creds')
                self.assertNotIn(auth['master'], repr(args))
                self.assertEqual(kwargs['env'], s.SAFE_ENV)
                kwargs['env'] = dict(kwargs['env'], SYSTEMD_CREDENTIAL_SECRET=str(root / 'keys/credential.secret'))
                if 'decrypt' in args:
                    # systemd 252 insists the host key is root-owned on read.
                    # This unprivileged test double covers protocol/storage only.
                    self.assertEqual(kwargs['input'], path.read_bytes())
                    return subprocess.CompletedProcess(args, 0, json.dumps(auth).encode())
                return original_run(args, **kwargs)
            with patch.object(s.subprocess, 'run', side_effect=isolated_run):
                self.assertEqual(self.exchange(s.Store(path), {'operation': 'enroll', 'server': auth['server'], 'value': auth}),
                                 {'ok': True, 'value': {'registered': True}})
                self.assertEqual(self.exchange(s.Store(path), {'operation': 'get', 'server': auth['server']}),
                                 {'ok': True, 'value': auth})
                self.assertEqual(self.exchange(s.Store(path), {'operation': 'status', 'server': auth['server']}),
                                 {'ok': True, 'value': {'registered': True}})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertNotIn(auth['master'].encode(), path.read_bytes())
            self.assertNotIn(auth['client_secret'].encode(), path.read_bytes())
            self.assertEqual(sorted(p.name for p in path.parent.iterdir()), ['auth.cred'])

    def test_invalid_requests_have_one_constant_error(self):
        s = module('linux_credentials_service')
        from unittest.mock import Mock
        store = Mock()
        store.load.side_effect = RuntimeError('synthetic-secret-must-not-escape')
        requests = [
            {'operation': 'status', 'server': 'https://other.invalid'},
            {'operation': 'resume', 'server': 'https://example.invalid'},
            {'operation': 'get', 'server': 'https://example.invalid'},
            {'operation': 'enroll', 'server': 'https://example.invalid', 'value': {'master': 'synthetic-secret'}},
            {'operation': 'status', 'server': 'https://example.invalid', 'path': '/etc/shadow'},
        ]
        for request in requests:
            with self.subTest(operation=request['operation']):
                self.assertEqual(self.exchange(store, request), s.ERROR)
        store.reset_mock()
        self.assertEqual(self.exchange(store, {'operation': 'status', 'server': 'https://example.invalid'}, uid=os.getuid() + 1), s.ERROR)
        store.registered.assert_not_called()
        store.save.assert_not_called()
        store.load.assert_not_called()

    def test_frame_limits_invalid_json_and_slow_client_timeout(self):
        s = module('linux_credentials_service')
        from unittest.mock import Mock
        for data in [struct.pack('!I', s.MAX_FRAME + 1), struct.pack('!I', 0), struct.pack('!I', 1) + b'{', struct.pack('!I', 5) + b'{']:
            left, right = socket.socketpair()
            with left, right, patch.object(s, 'TIMEOUT', 0.05):
                left.settimeout(1)
                thread = threading.Thread(target=s.handle, args=(right, {'uid': os.getuid(), 'server': 'https://example.invalid'}, Mock()))
                thread.start()
                left.sendall(data)
                size = struct.unpack('!I', left.recv(4))[0]
                self.assertEqual(json.loads(left.recv(size)), s.ERROR)
                thread.join(1)
                self.assertFalse(thread.is_alive())

    def test_root_registration_schema_and_exact_server(self):
        s = module('linux_credentials_service')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'registration.json'
            for value in [{'uid': 1000, 'gid': 1001, 'server': 'http://example.invalid'}, {'uid': True, 'gid': 1001, 'server': 'https://example.invalid'}, {'uid': 1000, 'gid': 1001, 'server': 'https://user:pass@example.invalid'}, {'uid': 1000, 'gid': 1001, 'server': 'https://example.invalid', 'path': '/tmp/other'}]:
                path.write_text(json.dumps(value))
                with patch.object(s, 'trusted_path'), self.assertRaises(ValueError):
                    s.load_registration(path)
            valid = {'uid': 1000, 'gid': 1001, 'server': 'https://example.invalid/subpath/'}
            path.write_text(json.dumps(valid))
            with patch.object(s, 'trusted_path'):
                self.assertEqual(s.load_registration(path), valid)

    def test_stale_group_writable_socket_can_be_removed_for_restart(self):
        s = module('linux_credentials_service')
        self.assertTrue(hasattr(s, 'remove_stale_socket'), 'restart cleanup missing')
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'test.sock'
            with socket.socket(socket.AF_UNIX) as listener:
                listener.bind(str(path))
                info = path.lstat()
                with patch.object(Path, 'lstat', return_value=SimpleNamespace(st_uid=0, st_mode=(info.st_mode & ~0o777) | 0o660)):
                    s.remove_stale_socket(path)
            self.assertFalse(path.exists())

    def test_root_helper_rejects_untrusted_registration_and_nonroot_startup(self):
        s = module('linux_credentials_service')
        self.assertTrue(hasattr(s, 'load_registration'), 'trusted root registration missing')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'registration.json'
            path.write_text(json.dumps({'uid': 1000, 'gid': 1001, 'server': 'https://example.invalid'}))
            with self.assertRaises(ValueError):
                s.load_registration(path)
        with patch.object(s.os, 'geteuid', return_value=1000):
            with self.assertRaises(ValueError):
                s.main()

    def test_status_distinguishes_unregistered_over_private_socket(self):
        self.assertIsNotNone(importlib.util.find_spec('linux_credentials_service'), 'root helper missing')
        s = module('linux_credentials_service')
        with tempfile.TemporaryDirectory() as directory:
            store = s.Store(Path(directory) / 'auth.cred')
            left, right = socket.socketpair()
            with left, right:
                thread = threading.Thread(target=s.handle, args=(right, {'uid': os.getuid(), 'server': 'https://example.invalid'}, store))
                thread.start()
                data = json.dumps({'operation': 'status', 'server': 'https://example.invalid'}).encode()
                left.sendall(struct.pack('!I', len(data)) + data)
                size = struct.unpack('!I', left.recv(4))[0]
                self.assertEqual(json.loads(left.recv(size)), {'ok': True, 'value': {'registered': False}})
                thread.join(3)
                self.assertFalse(thread.is_alive())


class ManageTests(unittest.TestCase):
    def test_enrollment_prompts_locally_and_leaves_access_paused(self):
        m = module('linux_manage')
        self.assertTrue(hasattr(m, 'prompt_credentials'), 'TTY enrollment missing')
        auth = {'server': 'https://example.invalid', 'email': 'test@example.invalid',
                'master': 'synthetic-master', 'client_id': '', 'client_secret': ''}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'config.json').write_text(json.dumps({'server': auth['server'], 'credential_socket': '/run/warden-hermes-credentials/credentials.sock'}))
            with patch.object(m, 'require_tty'), patch.object(m, 'prompt_credentials', return_value=auth), patch.object(m, 'request', return_value={'registered': True}) as broker:
                self.assertEqual(m.manage(root, 'enroll'), {'registered': True, 'enabled': False})
                self.assertEqual(broker.call_args_list[-2].args[1:], ('enroll', auth))
                self.assertEqual(broker.call_args_list[-1].args[1:], ('status',))
            self.assertEqual(json.loads((root / 'access.json').read_text()), {'enabled': False, 'allow_all': True, 'items': []})
            self.assertNotIn('synthetic-master', (root / 'access.json').read_text())

    def test_real_controlling_tty_enrollment_prompt_does_not_echo(self):
        import pty
        import select
        import time
        import signal
        m = module('linux_manage')
        pid, fd = pty.fork()
        if pid == 0:
            try:
                value = m.prompt_credentials('https://example.invalid')
                os._exit(0 if value['master'] == 'synthetic-hidden-master' and value['client_secret'] == 'synthetic-hidden-api' else 2)
            except BaseException:
                os._exit(1)
        prompts = [b'Email: ', b'Master password: ', b'API client ID (blank for password login): ', b'API client secret (blank if no ID): ']
        answers = [b'test@example.invalid', b'synthetic-hidden-master', b'synthetic-id', b'synthetic-hidden-api']
        output = bytearray()
        index = 0
        deadline = time.monotonic() + 5
        status = None
        exited = 0
        try:
            while time.monotonic() < deadline:
                if select.select([fd], [], [], 0.1)[0]:
                    try:
                        chunk = os.read(fd, 4096)
                    except OSError:
                        break
                    output.extend(chunk)
                    if index < len(prompts) and prompts[index] in output:
                        os.write(fd, answers[index] + b'\n')
                        index += 1
                exited, status = os.waitpid(pid, os.WNOHANG)
                if exited:
                    break
            if status is None or exited == 0:
                exited, status = os.waitpid(pid, os.WNOHANG)
                if not exited:
                    os.kill(pid, signal.SIGKILL)
                    _, status = os.waitpid(pid, 0)
            self.assertEqual(status, 0, 'local /dev/tty prompt failed')
            self.assertEqual(index, 4)
            self.assertNotIn(answers[1], output)
            self.assertNotIn(answers[3], output)
        finally:
            os.close(fd)

    def test_secret_prompt_uses_tty_getpass_and_disables_core_dumps(self):
        import io
        m = module('linux_manage')
        self.assertTrue(hasattr(m, 'resource'), 'secret prompt core dump protection missing')
        tty = io.StringIO()
        with patch.object(m, 'require_tty'), patch('builtins.open', return_value=tty) as opened, patch.object(m.getpass, 'getpass', side_effect=['test@example.invalid', 'synthetic-master', '', '']) as prompt, patch.object(m.resource, 'setrlimit') as limits:
            value = m.prompt_credentials('https://example.invalid')
            limits.assert_called_once_with(m.resource.RLIMIT_CORE, (0, 0))
            opened.assert_called_once_with('/dev/tty', 'w')
            self.assertEqual(prompt.call_count, 4)
            self.assertTrue(all(call.kwargs['stream'] is tty for call in prompt.call_args_list))
            self.assertEqual(value['master'], 'synthetic-master')

    def test_status_cli_reports_unavailable_without_traceback(self):
        import subprocess
        m = module('linux_manage')
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / 'config.json').write_text('{"server":"https://example.invalid"}')
            result = subprocess.run([sys.executable, m.__file__, directory, 'status'], capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, '{"ok": false, "code": "credential_store"}\n')
            self.assertEqual(result.stderr, '')

    def test_local_pause_resume_preserves_policy_and_requires_tty(self):
        self.assertIsNotNone(importlib.util.find_spec('linux_manage'), 'local manager missing')
        m = module('linux_manage')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'config.json').write_text(json.dumps({'server': 'https://example.invalid', 'credential_socket': '/run/warden-hermes-credentials/credentials.sock'}))
            (root / 'access.json').write_text(json.dumps({'enabled': True, 'allow_all': True, 'items': [], 'extra': 42}))
            with patch.object(m, 'require_tty', return_value=None):
                m.manage(root, 'pause')
                self.assertFalse(json.loads((root / 'access.json').read_text())['enabled'])
                with patch.object(m, 'request', return_value={'registered': True}):
                    m.manage(root, 'resume')
            policy = json.loads((root / 'access.json').read_text())
            self.assertEqual(policy, {'enabled': True, 'allow_all': True, 'items': [], 'extra': 42})
            self.assertEqual((root / 'access.json').stat().st_mode & 0o777, 0o600)
            with patch.object(m.sys.stdin, 'isatty', return_value=False), patch.object(m, 'request') as broker:
                with self.assertRaises(m.CredentialError):
                    m.manage(root, 'enroll')
                broker.assert_not_called()


@unittest.skipUnless(os.environ.get('WARDEN_SYNTHETIC_CONTAINER') == '1' and os.geteuid() == 0 and Path('/.dockerenv').exists(), 'isolated container root required; never run on host root')
class ContainerTests(unittest.TestCase):
    def test_real_root_helper_uid1000_decrypt_and_restart(self):
        import shutil
        import subprocess
        import time
        s = module('linux_credentials_service')
        source = Path(__file__).resolve().parents[1]
        installed = Path('/usr/local/libexec/warden-hermes-credentials/linux_credentials_service.py')
        for path, mode in [(installed.parent, 0o755), (s.REGISTRATION.parent, 0o700), (s.STATE, 0o700), (s.SOCKET_PATH.parent, 0o755)]:
            path.mkdir(parents=True, exist_ok=True)
            path.chmod(mode)
        shutil.copyfile(source / 'agent_worker/linux_credentials_service.py', installed)
        installed.chmod(0o644)
        s.REGISTRATION.write_text(json.dumps({'uid': 1000, 'gid': 1001, 'server': 'https://example.invalid'}))
        s.REGISTRATION.chmod(0o600)
        subprocess.run(['/usr/bin/systemd-creds', 'setup'], env=s.SAFE_ENV, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.assertEqual(s.HOST_KEY.stat().st_mode & 0o777, 0o400)
        auth = {'server': 'https://example.invalid', 'email': 'test@example.invalid', 'master': 'synthetic-master', 'client_id': '', 'client_secret': ''}
        child = '''import json,os,sys
from pathlib import Path
sys.path.insert(0, '/test/agent_worker')
from credentials import request,load_credentials,credential_status,CredentialError
payload=json.load(sys.stdin)
config={'server':'https://example.invalid','credential_socket':'/run/warden-hermes-credentials/credentials.sock'}
action=payload['action']
try:
 if action=='status': assert credential_status(Path('.'),config)=={'registered':payload['registered']}
 elif action=='enroll': assert request(config,'enroll',payload['auth'])=={'registered':True}
 elif action=='get': assert load_credentials(Path('.'),config)==payload['auth']
 elif action=='deny':
  try: request(config,'get')
  except CredentialError: pass
  else: raise AssertionError()
 for p in ['/var/lib/systemd/credential.secret','/var/lib/warden-hermes-credentials/auth.cred']:
  assert not os.access(p,os.R_OK)
 assert not os.access('/usr/local/libexec/warden-hermes-credentials/linux_credentials_service.py',os.W_OK)
 assert not os.access('/etc/warden-hermes-credentials/registration.json',os.W_OK)
except BaseException:
 sys.exit(1)
'''
        def probe(action, uid=1000, **extra):
            def identity():
                os.setgroups([])
                os.setgid(1001)
                os.setuid(uid)
            result = subprocess.run([sys.executable, '-c', child], input=json.dumps(dict(action=action, **extra)).encode(), capture_output=True, preexec_fn=identity, timeout=10)
            self.assertEqual(result.returncode, 0, 'UID-scoped credential probe failed')
            self.assertEqual(result.stdout + result.stderr, b'')
        for attempt in range(2):
            service = subprocess.Popen(['/usr/bin/python3', '-I', str(installed)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=s.SAFE_ENV)
            try:
                for _ in range(100):
                    if service.poll() is not None:
                        self.fail('root helper failed to start')
                    if s.SOCKET_PATH.exists():
                        # On restart wait for replacement of the stale socket.
                        try:
                            probe('status', registered=bool(attempt))
                            break
                        except AssertionError:
                            pass
                    time.sleep(0.02)
                else:
                    self.fail('helper did not become ready')
                if not attempt:
                    probe('enroll', auth=auth)
                probe('get', auth=auth)
                probe('deny', uid=1002)
                self.assertEqual((s.STATE / 'auth.cred').stat().st_mode & 0o777, 0o600)
                self.assertNotIn(auth['master'].encode(), (s.STATE / 'auth.cred').read_bytes())
            finally:
                service.terminate()
                stdout, stderr = service.communicate(timeout=5)
                self.assertEqual(stdout + stderr, b'')


if __name__ == '__main__':
    unittest.main()
