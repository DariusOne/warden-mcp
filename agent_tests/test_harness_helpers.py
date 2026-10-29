"""Test-first coverage for disposable harness portability helpers."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

class DockerTests(unittest.TestCase):
    def test_linux_default_context_and_windows_desktop(self):
        import harness_helpers as h
        self.assertEqual(h.docker_command('docker', 'linux', {}), ['docker', '--context', 'default'])
        self.assertEqual(h.docker_command('docker.exe', 'win32', {}), ['docker.exe', '--context', 'desktop-linux'])
        self.assertEqual(h.docker_command('docker', 'linux', {'WARDEN_TEST_DOCKER_CONTEXT':'fixture'}), ['docker', '--context', 'fixture'])

class CredentialFixtureTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux private socket fixture')
    def test_synthetic_credentials_stay_in_memory_and_socket_is_private(self):
        import harness_helpers as h
        import json, socket, struct
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'credentials.sock'
            auth = {'server':'https://127.0.0.1:1/bitwarden','master':'SYNTHETIC_ONLY'}
            with h.SyntheticCredentials(path, auth):
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                for server, expected in [(auth['server'], True), ('https://wrong.invalid', False)]:
                    with socket.socket(socket.AF_UNIX) as conn:
                        conn.connect(str(path))
                        data = json.dumps({'operation':'get','server':server}).encode()
                        conn.sendall(struct.pack('!I',len(data))+data)
                        size=struct.unpack('!I',conn.recv(4))[0]
                        result=json.loads(conn.recv(size))
                    self.assertEqual(result['ok'], expected)
                    if expected: self.assertEqual(result['value'], auth)
                with socket.socket(socket.AF_UNIX) as conn:
                    conn.connect(str(path))
                    data=json.dumps({'operation':'status','server':auth['server']}).encode()
                    conn.sendall(struct.pack('!I',len(data))+data)
                    size=struct.unpack('!I',conn.recv(4))[0]
                    result=json.loads(conn.recv(size))
                self.assertEqual(result, {'ok':True,'value':{'registered':True}})
                self.assertEqual(list(Path(root).iterdir()), [path])
            self.assertFalse(path.exists())

class ProcessProbeTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux procfs')
    def test_descendants_detect_secret_and_session_without_echoing(self):
        import harness_helpers as h
        import subprocess, json, time
        marker = 'SYNTHETIC-ARGV-CANARY'
        child = subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(20)', marker, '--session=synthetic', '--no-sandbox'])
        try:
            result = h.probe_processes(os.getpid(), [marker])
            self.assertTrue(result['secret_args'])
            self.assertTrue(result['session_argument'])
            self.assertTrue(result['unsafe_browser_argument'])
            self.assertGreaterEqual(result['children_observed'],1)
            self.assertNotIn(marker, json.dumps(result))
            identities = [p for p in result['identities'] if p['pid'] == child.pid]
            self.assertTrue(h.alive_identities(identities))
        finally:
            child.terminate();child.wait()
        self.assertEqual(h.alive_identities(identities), [])

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux procfs')
    def test_probe_cli_emits_only_bounded_json(self):
        import subprocess, json
        child = subprocess.run([sys.executable, str(HERE/'process_probe.py')], input=json.dumps({'root_pid':os.getpid(),'markers':['not-present']}),text=True,capture_output=True)
        self.assertEqual(child.returncode,0,child.stderr)
        self.assertFalse(json.loads(child.stdout)['secret_args'])
        self.assertEqual(child.stderr,'')

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux procfs')
    def test_never_reads_unrelated_process_arguments(self):
        import harness_helpers as h
        from unittest.mock import patch
        original = Path.read_bytes
        reads = []
        def observe(path):
            if path.name == 'cmdline': reads.append(int(path.parent.name))
            return original(path)
        with patch.object(Path, 'read_bytes', observe):
            result = h.probe_processes(os.getpid(), [])
        allowed = {p['pid'] for p in result['identities']}
        self.assertTrue(set(reads).issubset(allowed), 'read unrelated argv')

class ServiceCleanupTests(unittest.TestCase):
    def test_cleanup_refuses_wrong_container_label(self):
        from services import Services
        from unittest.mock import patch
        import subprocess
        service=Services(Path('/unused'), {}, 'docker', 'synthetic-test-id')
        service.mysql_started=True
        with patch('services.subprocess.run', return_value=subprocess.CompletedProcess([],0,'someone-else','')) as run:
            with self.assertRaisesRegex(RuntimeError,'identity'):
                service.close()
        self.assertEqual(run.call_count,1)

class PrivateFileTests(unittest.TestCase):
    def test_private_file_overrides_inherited_executable_mode(self):
        import harness_helpers as h
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'synthetic'
            path.write_bytes(b'old');path.chmod(0o700)
            h.write_private(path,b'new')
            self.assertEqual(path.read_bytes(),b'new')
            if os.name == 'posix': self.assertEqual(path.stat().st_mode & 0o777,0o600)

class EnvironmentTests(unittest.TestCase):
    def test_seed_environment_drops_daily_credentials_and_tls_bypass(self):
        import harness_helpers as h
        source={'BW_SESSION':'real','BITWARDENCLI_APPDATA_DIR':'daily','KEYCHAIN_DEBUG_HTTP':'true','NODE_OPTIONS':'--inspect','NODE_TLS_REJECT_UNAUTHORIZED':'0','PATH':'runtime'}
        self.assertEqual(h.isolated_environment(source),{'PATH':'runtime'})

class TotpTests(unittest.TestCase):
    def test_rfc6238_vector_and_reject_wrong_code(self):
        import harness_helpers as h
        seed = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
        self.assertTrue(h.valid_totp(seed, '287082', now=59))
        self.assertFalse(h.valid_totp(seed, '000000', now=59))
        self.assertFalse(h.valid_totp(seed, 'abcdef', now=59))

if __name__ == '__main__': unittest.main()
