"""Stage an immutable upgrade without reading enrollment, CLI state or policy.

Dependencies must come from a previously installed version with the identical
package lock. Activation is separate, after checking this candidate.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def stage(source, root, dependencies, version, commit, tree):
    source, root, dependencies = source.resolve(), root.resolve(), dependencies.resolve()
    if not re.fullmatch(r'agent-v\d+\.\d+\.\d+(?:-[a-z0-9.-]+)?', version):
        raise ValueError('invalid version')
    if not re.fullmatch(r'[a-f0-9]{40}', commit) or not re.fullmatch(r'[a-f0-9]{40}', tree):
        raise ValueError('invalid build identity')
    if sha(source/'package-lock.json') != sha(dependencies/'package-lock.json'):
        raise ValueError('dependency lock differs; install reviewed dependencies first')
    if not (source/'dist/server.js').is_file() or not (dependencies/'node_modules').is_dir():
        raise ValueError('build or dependencies missing')
    destination = root/'versions'/version
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    if os.name != 'nt': destination.chmod(0o700)
    for name in ('dist', 'agent_worker', 'agent_tools'):
        shutil.copytree(source/name, destination/name,
                        ignore=shutil.ignore_patterns('*.test.js', '*.pyc', '__pycache__'))
    for name in ('package.json','package-lock.json','LICENSE','AGENT_SAFE.md','SSH_HOST_TRUST.md'):
        shutil.copyfile(source/name, destination/name)
    shutil.copytree(dependencies/'node_modules', destination/'node_modules', symlinks=os.name!='nt')
    files = {str(p.relative_to(destination)).replace('\\','/'):sha(p)
             for name in ('dist','agent_worker','agent_tools') for p in (destination/name).rglob('*') if p.is_file()}
    manifest = {'version':version,'source_commit':commit,'source_tree':tree,
                'package_lock_sha256':sha(source/'package-lock.json'),'files':files}
    (destination/'ARTIFACTS.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    (destination/'BUILD.json').write_text(json.dumps({k:v for k,v in manifest.items() if k!='files'},indent=2),encoding='utf-8')
    if os.name != 'nt':
        for base, directories, names in os.walk(destination):
            Path(base).chmod(0o700)
            for n in names:
                p=Path(base)/n
                if not p.is_symlink(): p.chmod(p.stat().st_mode & ~0o022)
    for name, digest in files.items():
        if sha(destination/name) != digest: raise ValueError('artifact verification failed')
    return {'staged':True,'version':version,'source_commit':commit,'file_count':len(files)}


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    for name in ('source','root','dependencies'): parser.add_argument('--'+name,type=Path,required=True)
    for name in ('version','commit','tree'): parser.add_argument('--'+name,required=True)
    a=parser.parse_args()
    print(json.dumps(stage(a.source,a.root,a.dependencies,a.version,a.commit,a.tree)))
