"""Linux /proc probe. Input stays on stdin; output never includes argv."""
import json
import sys
from harness_helpers import probe_processes, alive_identities

if __name__ == '__main__':
    request = json.load(sys.stdin)
    if 'identities' in request:
        result = {'alive': alive_identities(request['identities'])}
    else:
        result = probe_processes(request['root_pid'], request['markers'])
    print(json.dumps(result))
