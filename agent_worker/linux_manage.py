"""Local terminal management only; this module is never an MCP operation."""
import json
import getpass
import warnings
import resource
import os
from pathlib import Path
import sys
import tempfile
from credentials import CredentialError, credential_status, request


def require_tty():
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise CredentialError()
    with open('/dev/tty', 'w') as tty:
        if not tty.isatty():
            raise CredentialError()


def write_policy(root, policy):
    fd, temporary = tempfile.mkstemp(prefix='.access-', dir=root)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as output:
            os.fchmod(output.fileno(), 0o600)
            json.dump(policy, output, ensure_ascii=True)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, root / 'access.json')
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def prompt_credentials(server):
    require_tty()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    with open('/dev/tty', 'w') as tty, warnings.catch_warnings():
        warnings.simplefilter('error', getpass.GetPassWarning)
        value = {'server': server}
        for key, label in [('email', 'Email: '), ('master', 'Master password: '),
                           ('client_id', 'API client ID (blank for password login): '),
                           ('client_secret', 'API client secret (blank if no ID): ')]:
            value[key] = getpass.getpass(label, stream=tty)
    if not value['email'] or not value['master'] or bool(value['client_id']) != bool(value['client_secret']):
        raise CredentialError()
    return value


def manage(root, operation):
    root = Path(root)
    if operation != 'status':
        require_tty()
    config = json.loads((root / 'config.json').read_text(encoding='utf-8-sig'))
    if operation == 'status':
        return credential_status(root, config)
    try:
        policy = json.loads((root / 'access.json').read_text(encoding='utf-8-sig'))
    except FileNotFoundError:
        policy = {'enabled': False, 'allow_all': True, 'items': []}
    if operation == 'enroll':
        # Pause before replacement, including when enrollment subsequently fails.
        policy['enabled'] = False
        write_policy(root, policy)
        request(config, 'status')
        value = prompt_credentials(config['server'])
        try:
            if request(config, 'enroll', value) != {'registered': True}:
                raise CredentialError()
        finally:
            value = None
        if request(config, 'status') != {'registered': True}:
            raise CredentialError()
        return {'registered': True, 'enabled': False}
    if operation == 'pause':
        policy['enabled'] = False
    elif operation == 'resume':
        if request(config, 'status') != {'registered': True}:
            raise CredentialError()
        policy['enabled'] = True
    else:
        raise CredentialError()
    write_policy(root, policy)
    return {'enabled': policy['enabled']}


def main():
    try:
        if len(sys.argv) != 3 or sys.argv[2] not in ('status', 'enroll', 'pause', 'resume') or not sys.platform.startswith('linux'):
            raise CredentialError()
        result = manage(Path(sys.argv[1]).resolve(), sys.argv[2])
        print(json.dumps({'ok': True, 'value': result}))
        return 0
    except BaseException:
        print(json.dumps({'ok': False, 'code': 'credential_store'}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
