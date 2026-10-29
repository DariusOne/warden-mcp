"""Upgrade staging must leave enrollment and live configuration in place."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'agent_tools'))
from stage_release import stage


class StagingTests(unittest.TestCase):
    def test_candidate_is_immutable_and_never_copies_runtime_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            source,live,old=[root/x for x in ('source','runtime','old')]
            for p in (source,live,old,live/'versions',live/'state',old/'node_modules'):
                p.mkdir()
            for name in ('dist','agent_worker','agent_tools'):
                (source/name).mkdir()
                (source/name/'fixture.txt').write_text('reviewed code')
            (source/'dist/server.js').write_text('fixture')
            for name in ('package.json','package-lock.json','LICENSE','AGENT_SAFE.md','SSH_HOST_TRUST.md'):
                (source/name).write_text('fixture')
            (old/'package-lock.json').write_text('fixture')
            (live/'state/auth.dpapi').write_text('synthetic-ciphertext')
            (live/'state/known_hosts').write_text('synthetic-existing-trust')
            (live/'config.json').write_text('synthetic-live-config')
            before={p.name:p.read_bytes() for p in live.rglob('*') if p.is_file()}
            result=stage(source,live,old,'agent-v0.2.0-rc.1','a'*40,'b'*40)
            candidate=live/'versions/agent-v0.2.0-rc.1'
            self.assertTrue(result['staged'])
            self.assertFalse((candidate/'state').exists())
            self.assertFalse((candidate/'config.json').exists())
            self.assertEqual(json.loads((candidate/'BUILD.json').read_text())['source_commit'],'a'*40)
            for p in (live/'state/auth.dpapi',live/'state/known_hosts',live/'config.json'):
                self.assertEqual(p.read_bytes(),before[p.name])
            with self.assertRaises(FileExistsError):stage(source,live,old,'agent-v0.2.0-rc.1','a'*40,'b'*40)
            (old/'package-lock.json').write_text('different')
            with self.assertRaises(ValueError):stage(source,live,old,'agent-v0.2.0-rc.2','a'*40,'b'*40)
            self.assertFalse((live/'versions/agent-v0.2.0-rc.2').exists())


if __name__=='__main__':unittest.main()
