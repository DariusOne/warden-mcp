import json
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import unittest

class ConfigurationTests(unittest.TestCase):
    def test_change_and_rollback_preserve_other_servers_and_approval(self):
        script=Path(__file__).resolve().parents[1]/'agent_tools/configure_codex.py'
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); cfg=root/'codex.toml'
            before='''model = "example"
[mcp_servers.vaultwarden]
command = "old"
args = ["old.py"]
default_tools_approval_mode = "prompt"
tool_timeout_sec = 90

[mcp_servers.other]
command = "keep-this"
args = ["unchanged"]
'''
            cfg.write_bytes(before.encode())
            args=[sys.executable,str(script),'activate','--root',str(root),'--config',str(cfg)]
            p=subprocess.run(args,capture_output=True)
            self.assertEqual(p.returncode,0)
            after=tomllib.loads(cfg.read_text(encoding='utf-8'))
            self.assertEqual(after['mcp_servers']['other'],tomllib.loads(before)['mcp_servers']['other'])
            self.assertEqual(after['mcp_servers']['vaultwarden']['default_tools_approval_mode'],'prompt')
            self.assertEqual(len(after['mcp_servers']['vaultwarden']['enabled_tools']),12)
            self.assertEqual(after['mcp_servers']['vaultwarden']['tool_timeout_sec'],480)
            args[2]='rollback'
            self.assertEqual(subprocess.run(args,capture_output=True).returncode,0)
            self.assertEqual(cfg.read_bytes(),before.encode())

if __name__=='__main__': unittest.main()
