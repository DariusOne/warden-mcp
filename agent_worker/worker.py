"""Inherited-pipe worker; never a public MCP or network service.

Credentials are returned ONLY on this private pipe to the parent Node process.
No credentials are passed in command arguments, printed to stderr or logged.
"""
from pathlib import Path
import json
import logging
import sys
import bridge_core as core
from browser_worker import BrowserWorker
from job import contain_children
from credentials import CredentialError, credential_status, load_credentials

logging.disable(logging.CRITICAL)


class SnapshotBroker:
    def __init__(self, root):
        self.root = root
        self.item = None
        self.token = None
        # Raw execution replies stay on the private pipe. Node performs the
        # final fingerprint-based filtering on every MCP output channel.
        self.redactor = core.Redactor()

    def get_item(self, item_id):
        if not self.item or self.item.get('id') != item_id:
            raise core.BridgeError('not_allowed', 'No authorized snapshot')
        return self.item

    def otp(self, item_id):
        self.get_item(item_id)
        if not self.token:
            raise core.BridgeError('totp', 'No OTP')
        return self.token


def main():
    job_handle = contain_children()
    root = Path(sys.argv[1]).resolve()
    config = json.loads((root / 'config.json').read_text(encoding='utf-8-sig'))
    core.SERVER = config['server']
    broker = SnapshotBroker(root)
    browser = BrowserWorker(broker)
    try:
        for line in sys.stdin:
            request_id = None
            try:
                request = json.loads(line)
                request_id = request['id']
                operation = request['operation']
                payload = request.get('payload') or {}
                if operation in ('credentials', 'credential_status'):
                    try:
                        value = load_credentials(root, config) if operation == 'credentials' else credential_status(root, config)
                    except CredentialError:
                        raise core.BridgeError('credential_store', 'Credential provider unavailable') from None
                elif operation == 'browser_close':
                    value = browser.call('close_all') if browser.thread and browser.thread.is_alive() else {'closed': True}
                else:
                    broker.item, broker.token = payload.get('item'), payload.get('otp')
                    args = payload.get('args') or {}
                    if operation == 'ssh_exec':
                        value = core.ssh_exec(broker, **args, approval=payload.get('ssh_approval'))
                    elif operation == 'mysql_query':
                        value = core.mysql_query(broker, **args)
                    elif operation in ('browser_open', 'browser_state', 'browser_fill_login', 'browser_fill_totp', 'browser_action'):
                        value = browser.call(operation.removeprefix('browser_'), **args)
                    else:
                        raise core.BridgeError('unsupported', 'Operation unavailable')
                sys.stdout.write(json.dumps({'id': request_id, 'ok': True, 'value': value}, ensure_ascii=True) + '\n')
                sys.stdout.flush()
                value = None
            except core.BridgeError as error:
                response = {'id': request_id, 'ok': False, 'code': error.code}
                if error.code in ('ssh_host_unknown', 'ssh_host_changed') and isinstance(error.details, dict):
                    response['host_key'] = error.details
                sys.stdout.write(json.dumps(response) + '\n')
                sys.stdout.flush()
            except Exception:
                sys.stdout.write(json.dumps({'id': request_id, 'ok': False, 'code': 'worker_failed'}) + '\n')
                sys.stdout.flush()
            finally:
                broker.item, broker.token = None, None
                request, payload, args, line = None, None, None, None
    finally:
        if browser.thread and browser.thread.is_alive():
            browser.call('close_all')
        assert job_handle


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # No raw traceback, including during bootstrap or interpreter teardown.
        sys.exit(1)
