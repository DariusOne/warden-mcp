"""Change only the existing vaultwarden MCP block; preserve approval settings."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import tomllib

TOOLS = ['status','search','sync','browser_open','browser_state','browser_fill_login',
         'browser_fill_totp','browser_action','mysql_query','ssh_exec','browser_close','pause_access']
PATTERN = re.compile(r'^\[mcp_servers\.vaultwarden\]\r?\n.*?(?=^\[|\Z)',re.M|re.S)


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('mode',choices=['activate','rollback'])
    ap.add_argument('--root',type=Path,required=True)
    ap.add_argument('--config',type=Path,required=True)
    ap.add_argument('--version',default='agent-v0.1.0')
    args=ap.parse_args()
    root=args.root.resolve(); config=args.config.resolve()
    original=config.read_bytes().decode('utf-8-sig')
    parsed=tomllib.loads(original)
    found=list(PATTERN.finditer(original))
    if len(found)!=1: raise RuntimeError('Expected one existing vaultwarden block')
    old=found[0].group(0)
    backup=root/'backups'; backup.mkdir(exist_ok=True)
    manifest=backup/'codex-migration.json'
    if args.mode=='activate':
        values={
            'command':str(root/'runtime/node.exe'),
            'args':[str(root/'versions'/args.version/'dist/server.js'),'--agent-safe','--agent-root',str(root)],
            'startup_timeout_sec':30,'tool_timeout_sec':120,'enabled':True,'enabled_tools':TOOLS,
        }
        if 'disabled_tools' in parsed['mcp_servers']['vaultwarden']:
            values['disabled_tools']=parsed['mcp_servers']['vaultwarden']['disabled_tools']
        block=old
        for key,value in values.items():
            line=key+' = '+json.dumps(value,ensure_ascii=False)
            pattern=re.compile(r'^'+re.escape(key)+r'\s*=.*$',re.M)
            if pattern.search(block): block=pattern.sub(lambda _:line,block)
            else: block=block.rstrip()+'\n'+line+'\n'
        block=block.rstrip()+'\n\n'
        target=original[:found[0].start()]+block+original[found[0].end():]
        check=tomllib.loads(target)
        before_other=parsed['mcp_servers'].pop('vaultwarden')
        after_other=check['mcp_servers'].pop('vaultwarden')
        if parsed != check: raise RuntimeError('Unrelated configuration changed')
        for key,value in before_other.items():
            if key not in values and after_other.get(key)!=value: raise RuntimeError('Existing approval or environment setting changed')
        stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        saved=backup/('vaultwarden-before-'+stamp+'.toml')
        saved.write_bytes(old.encode('utf-8'))
        manifest.write_text(json.dumps({'original_block':saved.name,'active_block_sha256':hashlib.sha256(block.encode()).hexdigest(),'version':args.version},indent=2),encoding='utf-8')
    else:
        state=json.loads(manifest.read_text(encoding='utf-8'))
        if hashlib.sha256(old.encode()).hexdigest()!=state['active_block_sha256']:
            raise RuntimeError('Vaultwarden block changed after activation; review before rollback')
        name=state['original_block']
        if Path(name).name != name: raise RuntimeError('Invalid backup path')
        block=(backup/name).read_bytes().decode('utf-8')
        target=original[:found[0].start()]+block+original[found[0].end():]
        tomllib.loads(target)
    temp=config.with_name(config.name+'.warden-mcp.tmp')
    temp.write_bytes(target.encode('utf-8'))
    os.replace(temp,config)
    print(json.dumps({'mode':args.mode,'only_vaultwarden_block_changed':True}))


if __name__=='__main__': main()
