"""Identity discovery stays on the inherited private pipe; synthetic data only."""
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'agent_worker'))
import worker


class CredentialIdentityTests(unittest.TestCase):
    def test_identity_response_excludes_all_secrets(self):
        for apikey in (False, True):
            with self.subTest(apikey=apikey), tempfile.TemporaryDirectory() as directory:
                auth = {'server': 'https://vault.example.test/bitwarden',
                        'email': 'agent@example.test', 'master': 'synthetic-master',
                        'unexpected_secret': 'synthetic-hidden-field'}
                login = {'method': 'userpass', 'user': auth['email']}
                if apikey:
                    auth.update(client_id='client.example', client_secret='synthetic-api-secret')
                    login = {'method': 'apikey', 'clientId': auth['client_id']}
                (Path(directory) / 'config.json').write_text(json.dumps({'server': auth['server']}))
                output = io.StringIO()
                with patch.object(worker, 'contain_children', return_value=True), \
                     patch.object(worker, 'load_credentials', return_value=auth), \
                     patch.object(worker.sys, 'argv', ['worker.py', directory]), \
                     patch.object(worker.sys, 'stdin', io.StringIO('{"id":1,"operation":"credential_identity"}\n')), \
                     patch.object(worker.sys, 'stdout', output):
                    worker.main()
                self.assertEqual(json.loads(output.getvalue()), {
                    'id': 1, 'ok': True, 'value': {'server': auth['server'], 'login': login}})
                self.assertNotIn('synthetic-', output.getvalue())


if __name__ == '__main__':
    unittest.main()
