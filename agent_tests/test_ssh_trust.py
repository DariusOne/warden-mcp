"""Real loopback SSH: prove no password or command precedes host approval."""
import concurrent.futures
import logging
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import paramiko
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent_worker"))
import bridge_core as core
import ssh_trust

logging.getLogger("paramiko").setLevel(logging.CRITICAL)
ITEM = "10000000-0000-4000-8000-000000000001"


class Broker:
    def __init__(self, root, port):
        self.root = root
        self.item = {"id": ITEM, "name": "Synthetic SSH", "fields": [
            {"name": "host", "value": "127.0.0.1"}, {"name": "port", "value": str(port)}],
            "login": {"username": "fixture", "password": "synthetic-only-password"}}
        self.redactor = core.Redactor()

    def get_item(self, _):
        return self.item


class SshTrustTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key_a = paramiko.RSAKey.generate(2048)
        cls.key_b = paramiko.RSAKey.generate(2048)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="warden-host-trust-")
        self.base = Path(self.temp.name)
        self.root = self.base / "root"
        self.root.mkdir()
        self.home = self.base / "home"
        (self.home / ".ssh").mkdir(parents=True)
        self.home_patch = patch.object(Path, "home", return_value=self.home)
        self.home_patch.start()
        self.key = self.key_a
        self.auth = self.commands = 0
        self.accept_auth = True
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen()
        self.sock.settimeout(0.1)
        self.port = self.sock.getsockname()[1]
        self.closed = threading.Event()
        self.transports = []
        self.threads = []
        owner = self

        class Server(paramiko.ServerInterface):
            def check_auth_password(self, username, password):
                owner.auth += 1
                return paramiko.AUTH_SUCCESSFUL if owner.accept_auth else paramiko.AUTH_FAILED

            def get_allowed_auths(self, _):
                return "password"

            def check_channel_request(self, kind, _):
                return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

            def check_channel_exec_request(self, channel, command):
                owner.commands += 1
                def reply():
                    time.sleep(0.03)
                    try:
                        channel.send(b"fixture command completed\n")
                        channel.send_exit_status(0)
                        channel.shutdown_write()
                    except Exception:
                        pass
                threading.Thread(target=reply, daemon=True).start()
                return True

        def serve(conn):
            transport = paramiko.Transport(conn)
            self.transports.append(transport)
            try:
                transport.add_server_key(self.key)
                transport.start_server(server=Server())
                while transport.is_active() and not self.closed.wait(0.03):
                    pass
            except Exception:
                pass
            finally:
                transport.close()

        def accept():
            while not self.closed.is_set():
                try:
                    conn, _ = self.sock.accept()
                except (OSError, socket.timeout):
                    continue
                thread = threading.Thread(target=serve, args=(conn,), daemon=True)
                self.threads.append(thread)
                thread.start()
        self.thread = threading.Thread(target=accept, daemon=True)
        self.thread.start()
        self.broker = Broker(self.root, self.port)

    def tearDown(self):
        self.closed.set()
        self.sock.close()
        self.thread.join(2)
        for transport in self.transports:
            transport.close()
        for thread in self.threads:
            thread.join(2)
        self.home_patch.stop()
        self.temp.cleanup()

    def execute(self, approval=None):
        return core.ssh_exec(self.broker, ITEM, "synthetic read-only command", 3, approval=approval)

    def unknown(self):
        with self.assertRaises(core.BridgeError) as caught:
            self.execute()
        self.assertEqual(caught.exception.code, "ssh_host_unknown")
        self.assertEqual(self.auth, 0)
        self.assertEqual(self.commands, 0)
        info = caught.exception.details
        self.assertEqual(info["fingerprint"], ssh_trust.fingerprint(self.key))
        self.assertFalse((self.root / "state/known_hosts").exists())
        return {**info, "expires_at": time.time() * 1000 + 290_000}

    def write_key(self, path, key, hashed=False):
        path.parent.mkdir(exist_ok=True)
        name = f"[127.0.0.1]:{self.port}"
        if hashed:
            name = paramiko.HostKeys.hash_host(name)
        path.write_text(f"{name} {key.get_name()} {key.get_base64()}\n", encoding="ascii")

    def test_unknown_approve_repeat_and_new_broker(self):
        approval = self.unknown()
        self.assertEqual(self.execute(approval)["exit_code"], 0)
        self.broker = Broker(self.root, self.port)
        self.assertEqual(self.execute()["exit_code"], 0)
        self.assertEqual((self.auth, self.commands), (2, 2))
        stored = (self.root / "state/known_hosts").read_text()
        self.assertIn(self.key.get_base64(), stored)
        self.assertEqual(len(stored.splitlines()), 1)

    def test_key_changes_before_confirmation_no_write_or_auth(self):
        approval = self.unknown()
        self.key = self.key_b
        with self.assertRaises(core.BridgeError) as caught:
            self.execute(approval)
        self.assertEqual(caught.exception.code, "ssh_host_changed")
        self.assertEqual((self.auth, self.commands), (0, 0))
        self.assertFalse((self.root / "state/known_hosts").exists())

    def test_changed_known_key_returns_new_and_old_fingerprints(self):
        self.write_key(self.root / "state/known_hosts", self.key_b)
        with self.assertRaises(core.BridgeError) as caught:
            self.execute()
        self.assertEqual(caught.exception.code, "ssh_host_changed")
        self.assertEqual(caught.exception.details["previous_fingerprints"], [ssh_trust.fingerprint(self.key_b)])
        self.assertEqual((self.auth, self.commands), (0, 0))

    def test_conflicting_stores_never_override(self):
        self.write_key(self.home / ".ssh/known_hosts", self.key_a)
        self.write_key(self.root / "state/known_hosts", self.key_b)
        with self.assertRaises(core.BridgeError) as caught:
            self.execute()
        self.assertEqual(caught.exception.code, "ssh_host_conflict")
        self.assertEqual((self.auth, self.commands), (0, 0))

    def test_hashed_user_entry_is_preserved(self):
        self.write_key(self.home / ".ssh/known_hosts", self.key_a, hashed=True)
        original = (self.home / ".ssh/known_hosts").read_bytes()
        self.assertEqual(self.execute()["exit_code"], 0)
        self.assertEqual((self.home / ".ssh/known_hosts").read_bytes(), original)
        self.assertFalse((self.root / "state/known_hosts").exists())

    def test_user_change_and_expired_approval_fail_before_auth(self):
        approval = self.unknown()
        self.broker.item["login"]["username"] = "changed-user"
        with self.assertRaises(core.BridgeError) as caught:
            self.execute(approval)
        self.assertEqual(caught.exception.code, "ssh_target_changed")
        self.broker.item["login"]["username"] = "fixture"
        approval["expires_at"] = time.time() * 1000 - 1
        with self.assertRaises(core.BridgeError) as caught:
            self.execute(approval)
        self.assertEqual(caught.exception.code, "ssh_confirmation_timeout")
        self.assertEqual((self.auth, self.commands), (0, 0))

    def test_atomic_write_failure_does_not_authenticate(self):
        approval = self.unknown()
        with patch.object(ssh_trust.os, "replace", side_effect=OSError("synthetic failure")):
            with self.assertRaises(core.BridgeError) as caught:
                self.execute(approval)
        self.assertEqual(caught.exception.code, "ssh_trust_store")
        self.assertEqual((self.auth, self.commands), (0, 0))
        self.assertFalse((self.root / "state/known_hosts").exists())
        self.assertEqual(list((self.root / "state").glob('.known-hosts-*')), [])

    def test_parallel_confirmations_save_only_one_key(self):
        approval = self.unknown()
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            results = list(pool.map(lambda _: self.execute(approval), range(3)))
        self.assertTrue(all(r["exit_code"] == 0 for r in results))
        self.assertEqual(len((self.root / "state/known_hosts").read_text().splitlines()), 1)
        self.assertEqual(self.commands, 3)

    def test_saved_trust_is_independent_of_password_authentication(self):
        approval = self.unknown()
        self.accept_auth = False
        with self.assertRaises(core.BridgeError) as caught:
            self.execute(approval)
        self.assertEqual(caught.exception.code, "ssh_auth_failed")
        self.assertEqual(self.commands, 0)
        self.assertTrue((self.root / "state/known_hosts").exists())

    def test_trust_store_symlink_is_rejected(self):
        victim = self.base / "victim"
        victim.write_text("untouched")
        (self.root / "state").mkdir()
        try:
            (self.root / "state/known_hosts").symlink_to(victim)
        except OSError:
            self.skipTest("OS does not permit test symlinks")
        with self.assertRaises(core.BridgeError) as caught:
            self.execute()
        self.assertEqual(caught.exception.code, "ssh_trust_store")
        self.assertEqual(victim.read_text(), "untouched")
        self.assertEqual((self.auth, self.commands), (0, 0))

    def test_trust_store_hardlink_is_rejected(self):
        victim = self.base / "victim"
        victim.write_text("untouched")
        (self.root / "state").mkdir()
        os.link(victim, self.root / "state/known_hosts")
        with self.assertRaises(core.BridgeError) as caught:
            self.execute()
        self.assertEqual(caught.exception.code, "ssh_trust_store")
        self.assertEqual(victim.read_text(), "untouched")
        self.assertEqual((self.auth, self.commands), (0, 0))


if __name__ == "__main__":
    unittest.main()
