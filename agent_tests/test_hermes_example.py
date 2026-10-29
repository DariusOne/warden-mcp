"""Offline deployment contract; never reads the operator's Hermes config."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class HermesExampleTests(unittest.TestCase):
    def test_exact_stdio_tools_timeouts_and_approval_gate(self):
        document = json.loads((ROOT / 'examples/agent-safe/hermes.linux.example.json').read_text())
        self.assertEqual(set(document), {'mcp_servers'})
        self.assertEqual(set(document['mcp_servers']), {'vaultwarden'})
        server = document['mcp_servers']['vaultwarden']
        self.assertNotIn('url', server)
        self.assertEqual(server['trust'], 'untrusted')
        self.assertEqual(server['sampling'], {'enabled': False})
        self.assertEqual(server['connect_timeout'], 30)
        self.assertEqual(server['timeout'], 120)
        self.assertIn('--agent-safe', server['args'])
        self.assertNotIn('--http', server['args'])
        expected = {'status', 'search', 'sync', 'browser_open', 'browser_state',
                    'browser_fill_login', 'browser_fill_totp', 'browser_action',
                    'mysql_query', 'ssh_exec', 'browser_close', 'pause_access'}
        self.assertEqual(set(server['tools']['include']), expected)
        self.assertEqual(len(server['tools']['include']), len(expected))


if __name__ == '__main__':
    unittest.main()
