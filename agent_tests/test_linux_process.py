"""Synthetic process trees only; never signal the test runner's process group."""
import json
import os
from pathlib import Path
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

REPO = Path(__file__).resolve().parents[1]
WORKER_PATH = REPO / 'agent_worker'
TREE = r'''
import json, os, subprocess, sys, time
sys.path.insert(0, sys.argv[1])
from job import contain_children
handle = contain_children()
# Playwright launches browsers in a new session; include that escape case.
child = subprocess.Popen([sys.executable, '-u', '-c',
    "import subprocess,sys,time; p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(120)']); print(p.pid,flush=True); time.sleep(120)"],
    start_new_session=True, stdout=subprocess.PIPE, text=True)
grandchild = int(child.stdout.readline())
print(json.dumps({'worker':os.getpid(),'watchdog':os.getppid(),
                  'child':child.pid,'grandchild':grandchild}), flush=True)
time.sleep(120)
'''


def running(pid):
    try:
        return Path(f'/proc/{pid}/stat').read_text().split(') ', 1)[1][0] != 'Z'
    except FileNotFoundError:
        return False


def wait_gone(pids, seconds=5):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if not any(running(pid) for pid in pids):
            return True
        time.sleep(.02)
    return False


NODE = os.environ.get('WARDEN_TEST_NODE') or shutil.which('node') or 'node'
NODE_WORKER = r'''
import json, os, subprocess, sys, time
sys.path.insert(0, sys.argv[1])
from job import contain_children
handle = contain_children()
child = subprocess.Popen([sys.executable, '-u', '-c',
    "import subprocess,sys,time; p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(120)']); print(p.pid,flush=True); time.sleep(120)"],
    start_new_session=True, stdout=subprocess.PIPE, text=True)
grandchild = int(child.stdout.readline())
pids = {'worker':os.getpid(), 'watchdog':os.getppid(), 'child':child.pid, 'grandchild':grandchild}
for line in sys.stdin:
    request = json.loads(line)
    if request['operation'] == 'hang':
        time.sleep(120)
    if request['operation'] == 'browser_timeout':
        print(json.dumps({'id':request['id'], 'ok':False, 'code':'browser_timeout'}), flush=True)
        continue
    print(json.dumps({'id':request['id'], 'ok':True, 'value':pids}), flush=True)
'''


REAL_BROWSER_WORKER = r'''
import json, os, sqlite3, sys, time
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0, WORKER_PATH)
from job import contain_children
# A filesystem barrier observes the real watchdog before descendant teardown;
# it never replaces the actual reclaim implementation.
config_path = Path(sys.argv[1]) / 'config.json'
if json.loads(config_path.read_text()).get('fixture_reclaim_barrier'):
    import job
    real_reclaim = job._reclaim
    def gated_reclaim(worker):
        (config_path.parent / 'reclaim-started').write_text('ready')
        end = time.monotonic() + 5
        while not (config_path.parent / 'reclaim-release').exists() and time.monotonic() < end:
            time.sleep(.01)
        real_reclaim(worker)
    job._reclaim = gated_reclaim
handle = contain_children()
from browser_worker import BrowserWorker
from bridge_core import Redactor
root = Path(sys.argv[1])
config = json.loads((root / 'config.json').read_text())
item = {'id':'synthetic', 'login':{'uris':[{'uri':config['fixture_url']}]}}
broker = SimpleNamespace(root=root, redactor=Redactor(), get_item=lambda _:item)
class FixtureBrowser(BrowserWorker):
    def do_seed(self):
        first = self.do_open('synthetic')
        entry = self.pages[first['page_id']]
        entry['page'].evaluate("localStorage.setItem('synthetic-storage', 'synthetic-value')")
        entry['context'].close()
        profile = next(iter(self.profiles.values()))
        with sqlite3.connect(profile / 'Default' / 'Cookies') as db:
            persisted = db.execute("select count(*) from cookies where name='synthetic_cookie'").fetchone()[0] == 1
        second = self.do_open('synthetic')
        isolated = self.pages[second['page_id']]['page'].evaluate("localStorage.getItem('synthetic-storage') === null")
        pids = {'worker':os.getpid(), 'watchdog':os.getppid()}
        todo = [os.getpid()]
        while todo:
            pid = todo.pop()
            try:
                children = set()
                for task in Path(f'/proc/{pid}/task').iterdir():
                    children.update((task / 'children').read_text().split())
            except FileNotFoundError:
                continue
            for child in children:
                child = int(child)
                pids[f'descendant-{child}'] = child
                todo.append(child)
        return {'pids':pids, 'profiles':[str(p) for p in self.profiles.values()],
                'cookie_persisted':persisted, 'storage_isolated':isolated, 'page_id':second['page_id']}
browser = FixtureBrowser(broker, test_options={'launch_args':['--ignore-certificate-errors-spki-list=' + config['fixture_pin']]})
for line in sys.stdin:
    request = json.loads(line)
    operation = request['operation']
    if operation == 'seed':
        value = browser.call('seed')
    elif operation == 'hang':
        time.sleep(120)
    elif operation == 'browser_timeout':
        print(json.dumps({'id':request['id'], 'ok':False, 'code':'browser_timeout'}), flush=True)
        continue
    elif operation == 'close':
        value = browser.call('close_all')
    elif operation == 'state':
        value = browser.call('state', page_id=request['payload']['page_id'])
    print(json.dumps({'id':request['id'], 'ok':True, 'value':value}), flush=True)
'''


@unittest.skipUnless(sys.platform == 'linux', 'Linux containment')
class LinuxContainmentTests(unittest.TestCase):
    def start_tree(self, parent=False, source=TREE):
        args = [sys.executable, '-u', '-c', source, str(WORKER_PATH)]
        if parent:
            launcher = 'import subprocess,sys,time; subprocess.Popen(sys.argv[1:], start_new_session=True); time.sleep(120)'
            args = [sys.executable, '-u', '-c', launcher, *args]
        proc = subprocess.Popen(args,
                                start_new_session=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
        self.addCleanup(self.cleanup_tree, proc)
        assert proc.stdout is not None and proc.stderr is not None
        self.assertTrue(select.select([proc.stdout], [], [], 5)[0], 'worker ready timeout')
        line = proc.stdout.readline()
        if not line:
            self.fail('containment bootstrap failed: ' + proc.stderr.read())
        pids = json.loads(line)
        self.addCleanup(self.cleanup_pids, pids)
        return proc, pids

    @staticmethod
    def cleanup_pids(pids):
        for pid in pids.values():
            if pid > 1 and pid != os.getpid():
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    @staticmethod
    def cleanup_tree(proc):
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        proc.stdout.close()
        proc.stderr.close()

    def node_case(self, body):
        with tempfile.TemporaryDirectory(prefix='warden-process-') as tmp:
            script = Path(tmp) / 'fixture.py'
            script.write_text(NODE_WORKER)
            source = f'''
import assert from 'node:assert/strict';
import {{ PrivateWorker }} from './src/agent-safe/privateWorker.ts';
const w = new PrivateWorker({json.dumps(sys.executable)}, {json.dumps(str(script))}, {json.dumps(str(WORKER_PATH))});
try {{
{body}
}} finally {{ w.stop(); }}
'''
            result = subprocess.run([NODE, '--import', 'tsx', '--input-type=module', '-e', source],
                                    cwd=REPO, capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            trees = [json.loads(line) for line in result.stdout.splitlines()]
            for pids in trees:
                self.addCleanup(self.cleanup_pids, pids)
                self.assertTrue(wait_gone(list(pids.values())), 'Node left live descendants')
            return trees

    def real_browser_case(self, body='', *, node_killed=False, reclaim_barrier=False):
        # Flush a real Chromium cookie DB, then leave another Chromium live
        # when the actual Node PrivateWorker teardown path is exercised.
        from agent_tests.test_linux_browser import synthetic_https_fixture
        with tempfile.TemporaryDirectory(prefix='warden-profile-stop-') as tmp:
            root = Path(tmp)
            with synthetic_https_fixture(root) as (url, pin):
                config = {'browser_executable': os.environ['WARDEN_TEST_BROWSER'],
                          'fixture_url': url, 'fixture_pin': pin,
                          'fixture_reclaim_barrier': reclaim_barrier}
                (root / 'config.json').write_text(json.dumps(config))
                sibling = root / 'state' / 'browser' / 'session-unrelated'
                sibling.mkdir(parents=True, mode=0o700)
                sibling.parent.chmod(0o700)
                sibling.parent.parent.chmod(0o700)
                (sibling / 'daily-marker').write_text('synthetic-unrelated-data')
                script = root / 'fixture.py'
                script.write_text(REAL_BROWSER_WORKER.replace('WORKER_PATH', repr(str(WORKER_PATH))))
                source = f'''
import assert from 'node:assert/strict';
import {{ existsSync, symlinkSync, renameSync, mkdirSync, writeFileSync, unlinkSync }} from 'node:fs';
import {{ dirname, basename }} from 'node:path';
import {{ PrivateWorker }} from './src/agent-safe/privateWorker.ts';
const makeWorker = () => new PrivateWorker({json.dumps(sys.executable)}, {json.dumps(str(script))}, {json.dumps(str(root))});
const w = makeWorker();
try {{
  const data = await w.call('seed');
  console.log(JSON.stringify(data));
  {body}
}} finally {{ w.stop(); }}
'''
                result = subprocess.run([NODE, '--import', 'tsx', '--input-type=module', '-e', source],
                                        cwd=REPO, capture_output=True, text=True, timeout=25)
                trees = [json.loads(line) for line in result.stdout.splitlines()]
                for data in trees:
                    self.addCleanup(self.cleanup_pids, data['pids'])
                self.assertEqual(result.returncode, -signal.SIGKILL if node_killed else 0, result.stderr)
                self.assertTrue(trees, 'fixture must return real browser evidence')
                profiles = []
                for data in trees:
                    self.assertTrue(data['cookie_persisted'], 'real Chromium cookie must be written before stop')
                    self.assertTrue(data['storage_isolated'], 'a fresh profile must not reuse local storage')
                    self.assertGreater(len(data['pids']), 3, 'real Playwright/Chromium descendants required')
                    self.assertTrue(wait_gone(list(data['pids'].values())))
                    for pid in data['pids'].values():
                        if pid != data['pids']['watchdog']:
                            self.assertFalse(Path(f'/proc/{pid}').exists(), f'profile reclaimed before reaping {pid}')
                    profiles.extend(data['profiles'])
                self.assertEqual(len(profiles), len(set(profiles)), 'concurrent/replacement profiles must be unique')
                for profile in profiles:
                    self.assertFalse(Path(profile).exists(), 'stop retained synthetic Chromium cookies')
                self.assertEqual((sibling / 'daily-marker').read_text(), 'synthetic-unrelated-data')
                self.assertEqual(list(sibling.parent.iterdir()), [sibling], 'empty owned worker directories must also be removed')

    @unittest.skipUnless(os.environ.get('WARDEN_TEST_BROWSER'), 'Set dedicated test Chromium executable')
    def test_real_browser_stop_removes_only_its_cookie_profiles(self):
        self.real_browser_case()

    @unittest.skipUnless(os.environ.get('WARDEN_TEST_BROWSER'), 'Set dedicated test Chromium executable')
    def test_real_browser_profiles_retained_until_descendant_teardown(self):
        self.real_browser_case("""
const root = dirname(dirname(dirname(dirname(data.profiles[0]))));
w.stop();
try {
  const end = Date.now() + 3000;
  while (!existsSync(root + '/reclaim-started') && Date.now() < end) await new Promise(r => setTimeout(r, 10));
  assert.ok(existsSync(root + '/reclaim-started'), 'watchdog must reach real teardown');
  assert.ok(data.profiles.every(existsSync), 'profiles were deleted before descendant teardown');
  assert.ok(existsSync('/proc/' + data.pids.worker), 'worker is still live at the teardown barrier');
} finally { writeFileSync(root + '/reclaim-release', 'continue'); }
""", reclaim_barrier=True)

    @unittest.skipUnless(os.environ.get('WARDEN_TEST_BROWSER'), 'Set dedicated test Chromium executable')
    def test_real_browser_abort_reclaims_cookie_profiles(self):
        self.real_browser_case("""
const controller = new AbortController();
const pending = w.call('hang', {}, controller.signal);
controller.abort();
await assert.rejects(pending);
""")

    @unittest.skipUnless(os.environ.get('WARDEN_TEST_BROWSER'), 'Set dedicated test Chromium executable')
    def test_real_browser_node_timeout_reclaims_cookie_profiles(self):
        self.real_browser_case("""
const realTimeout = globalThis.setTimeout;
globalThis.setTimeout = (fn, ms, ...args) => realTimeout(fn, ms === 75000 ? 50 : ms, ...args);
await assert.rejects(w.call('hang'));
""")

    @unittest.skipUnless(os.environ.get('WARDEN_TEST_BROWSER'), 'Set dedicated test Chromium executable')
    def test_real_browser_operation_timeout_reclaims_cookie_profiles(self):
        self.real_browser_case("await assert.rejects(w.call('browser_timeout'), {code:'browser_timeout'});")

    @unittest.skipUnless(os.environ.get('WARDEN_TEST_BROWSER'), 'Set dedicated test Chromium executable')
    def test_real_browser_node_sigkill_reclaims_cookie_profiles(self):
        self.real_browser_case("process.kill(process.pid, 'SIGKILL');", node_killed=True)

    @unittest.skipUnless(os.environ.get('WARDEN_TEST_BROWSER'), 'Set dedicated test Chromium executable')
    def test_real_browser_worker_sigkill_reclaims_cookie_profiles(self):
        self.real_browser_case("process.kill(data.pids.worker, 'SIGKILL'); await assert.rejects(w.call('hang'));")

    @unittest.skipUnless(os.environ.get('WARDEN_TEST_BROWSER'), 'Set dedicated test Chromium executable')
    def test_real_browser_normal_close_reclaims_cookie_profiles(self):
        self.real_browser_case("""
await w.call('close');
assert.ok(data.profiles.every(p => !existsSync(p)), 'normal close must remove cookies');
""")

    @unittest.skipUnless(os.environ.get('WARDEN_TEST_BROWSER'), 'Set dedicated test Chromium executable')
    def test_real_browser_cleanup_does_not_follow_profile_symlinks(self):
        self.real_browser_case("symlinkSync('../..', data.profiles[0] + '/external-parent', 'dir');")

    @unittest.skipUnless(os.environ.get('WARDEN_TEST_BROWSER'), 'Set dedicated test Chromium executable')
    def test_real_browser_close_uses_owned_inode_not_replaced_parent_path(self):
        self.real_browser_case("""
const owner = dirname(data.profiles[0]);
const sibling = dirname(owner) + '/session-unrelated';
const outside = sibling + '/' + basename(data.profiles[0]);
mkdirSync(outside);
writeFileSync(outside + '/outside-marker', 'synthetic-unowned-data');
renameSync(owner, owner + '-moved');
symlinkSync(sibling, owner, 'dir');
try {
  let error;
  try { await w.call('close'); } catch (e) { error = e; }
  assert.ok(existsSync(outside + '/outside-marker'), 'normal close deleted unrelated data through a replaced parent');
  assert.equal(error, undefined);
  assert.ok(data.profiles.every(p => !existsSync(owner + '-moved/' + basename(p))));
} finally {
  unlinkSync(owner);
  renameSync(owner + '-moved', owner);
}
""")

    @unittest.skipUnless(os.environ.get('WARDEN_TEST_BROWSER'), 'Set dedicated test Chromium executable')
    def test_real_browser_concurrent_worker_survives_other_profile_cleanup(self):
        self.real_browser_case("""
const other = makeWorker();
try {
  const second = await other.call('seed');
  console.log(JSON.stringify(second));
  w.stop();
  const end = Date.now() + 5000;
  while (data.profiles.some(existsSync) && Date.now() < end) await new Promise(r => setTimeout(r, 10));
  assert.ok(data.profiles.every(p => !existsSync(p)));
  assert.ok(second.profiles.every(existsSync));
  assert.equal((await other.call('state', {page_id:second.page_id})).title, 'Synthetic cleanup fixture');
} finally { other.stop(); }
""")

    @unittest.skipUnless(os.environ.get('WARDEN_TEST_BROWSER'), 'Set dedicated test Chromium executable')
    def test_real_browser_replacement_never_reuses_retired_profile(self):
        self.real_browser_case("""
w.stop();
console.log(JSON.stringify(await w.call('seed')));
""")

    def test_node_starts_isolated_worker_and_stop_reclaims_tree(self):
        trees = self.node_case("console.log(JSON.stringify(await w.call('pids'))); w.stop();")
        self.assertEqual(len(trees), 1)

    def test_old_worker_events_cannot_kill_replacement(self):
        self.node_case("""
console.log(JSON.stringify(await w.call('pids')));
const old = w.child;
w.stop();
const replacement = w.call('pids');
old.emit('error', new Error('late'));
old.stdin.emit('error', new Error('late pipe'));
old.stdout.emit('data', Buffer.from('malformed old response\\n'));
console.log(JSON.stringify(await replacement));
""")

    def test_abort_rejects_pending_and_reclaims_tree(self):
        self.node_case("""
console.log(JSON.stringify(await w.call('pids')));
const controller = new AbortController();
const pending = [w.call('hang', {}, controller.signal), w.call('hang')];
const settled = Promise.allSettled(pending);
controller.abort();
const results = await Promise.race([settled, new Promise(resolve => setTimeout(() => resolve([]), 500))]);
assert.equal(results.length, 2);
assert.ok(results.every(r => r.status === 'rejected'));
""")

    def test_browser_timeout_disposes_worker_not_just_request(self):
        self.node_case("""
console.log(JSON.stringify(await w.call('pids')));
await assert.rejects(w.call('browser_timeout'), {code:'browser_timeout'});
assert.equal(w.child, undefined, 'a timed-out browser must not continue in background');
""")

    def test_stale_timeout_cannot_stop_new_worker(self):
        self.node_case("""
const timers = [];
const realTimeout = globalThis.setTimeout;
globalThis.setTimeout = (fn, ms, ...args) => {
  if (ms === 75000) timers.push(fn);
  return realTimeout(fn, ms, ...args);
};
console.log(JSON.stringify(await w.call('pids')));
w.stop();
const replacement = w.call('pids');
timers[0]();
console.log(JSON.stringify(await replacement));
""")

    def test_node_timeout_rejects_every_pending_call(self):
        self.node_case("""
console.log(JSON.stringify(await w.call('pids')));
const realTimeout = globalThis.setTimeout;
globalThis.setTimeout = (fn, ms, ...args) => realTimeout(fn, ms === 75000 ? 50 : ms, ...args);
const results = await Promise.allSettled([w.call('hang'), w.call('hang')]);
assert.ok(results.every(r => r.status === 'rejected'));
assert.equal(w.pending.size, 0);
""")

    def test_node_sigkill_reclaims_worker_and_descendants(self):
        with tempfile.TemporaryDirectory(prefix='warden-node-death-') as tmp:
            script = Path(tmp) / 'fixture.py'
            script.write_text(NODE_WORKER)
            source = f'''
import {{ PrivateWorker }} from './src/agent-safe/privateWorker.ts';
const w = new PrivateWorker({json.dumps(sys.executable)}, {json.dumps(str(script))}, {json.dumps(str(WORKER_PATH))});
console.log(JSON.stringify(await w.call('pids')));
setInterval(() => {{}}, 1000);
'''
            proc = subprocess.Popen([NODE, '--import', 'tsx', '--input-type=module', '-e', source],
                                    cwd=REPO, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.addCleanup(self.cleanup_tree, proc)
            assert proc.stdout is not None
            self.assertTrue(select.select([proc.stdout], [], [], 5)[0])
            pids = json.loads(proc.stdout.readline())
            self.addCleanup(self.cleanup_pids, pids)
            proc.kill()
            proc.wait(timeout=5)
            self.assertTrue(wait_gone(list(pids.values())))

    def test_watchdog_retains_no_private_pipe_fds(self):
        proc, pids = self.start_tree()
        targets = [os.readlink(path) for path in Path(f"/proc/{pids['watchdog']}/fd").iterdir()]
        self.assertTrue(targets)
        self.assertTrue(all(target in ('/dev/null', 'anon_inode:[pidfd]') for target in targets), targets)
        proc.terminate()
        proc.wait(timeout=5)

    def test_shared_process_group_is_refused(self):
        source = f"import sys; sys.path.insert(0,{str(WORKER_PATH)!r}); from job import contain_children; contain_children()"
        result = subprocess.run([sys.executable, '-c', source], capture_output=True, text=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('worker_containment', result.stderr)
        self.assertTrue(running(os.getpid()))

    def test_startup_rejects_reparented_worker(self):
        source = f"import sys; sys.path.insert(0,{str(WORKER_PATH)!r}); from job import contain_children; contain_children(); print('unsafe startup')"
        result = subprocess.run([sys.executable, '-c', source], start_new_session=True,
                                env={**os.environ, 'WARDEN_PARENT_PID': '1'}, capture_output=True, text=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('unsafe startup', result.stdout)

    @unittest.skipUnless(os.environ.get('WARDEN_TEST_BROWSER'), 'Set dedicated test Chromium executable')
    def test_real_playwright_tree_reaped_after_worker_sigkill(self):
        with tempfile.TemporaryDirectory(prefix='warden-real-browser-tree-') as tmp:
            profile = Path(tmp) / 'state' / 'browser' / 'session'
            profile.mkdir(parents=True, mode=0o700)
            source = f'''
import json, os, sys, time
sys.path.insert(0, sys.argv[1])
from job import contain_children
handle = contain_children()
from playwright.sync_api import sync_playwright
with sync_playwright() as pw:
    context = pw.chromium.launch_persistent_context({str(profile)!r}, executable_path=os.environ['WARDEN_TEST_BROWSER'], chromium_sandbox=True, headless=True)
    print(json.dumps({{'worker':os.getpid(),'watchdog':os.getppid()}}), flush=True)
    time.sleep(120)
'''
            proc, pids = self.start_tree(source=source)
            todo = [pids['watchdog']]
            seen = set(todo)
            while todo:
                pid = todo.pop()
                for child in Path(f'/proc/{pid}/task/{pid}/children').read_text().split():
                    child = int(child)
                    if child not in seen:
                        seen.add(child)
                        todo.append(child)
                        pids[f'descendant-{child}'] = child
            self.assertGreater(len(seen), 3, 'real Chromium and Playwright children required')
            os.kill(pids['worker'], signal.SIGKILL)
            proc.wait(timeout=10)
            for pid in seen - {pids['watchdog']}:
                self.assertFalse(Path(f'/proc/{pid}').exists(), f'unreaped browser child {pid}')

    def test_parent_sigkill_reaps_worker_and_detached_descendants(self):
        proc, pids = self.start_tree(parent=True)
        proc.kill()
        proc.wait(timeout=5)
        self.assertTrue(wait_gone(list(pids.values())), 'watchdog did not notice parent death')

    def test_stop_watchdog_reaps_all_children(self):
        proc, pids = self.start_tree()
        proc.terminate()
        self.assertTrue(wait_gone(list(pids.values())), 'stop left descendants alive')
        proc.wait(timeout=5)

    def test_sigkill_worker_reaps_detached_browser_descendants(self):
        proc, pids = self.start_tree()
        self.assertNotEqual(os.getpgrp(), os.getpgid(pids['worker']))
        os.kill(pids['worker'], signal.SIGKILL)
        self.assertTrue(wait_gone(list(pids.values())), 'descendants or watchdog survived worker SIGKILL')
        proc.wait(timeout=5)
        for pid in (pids['child'], pids['grandchild']):
            self.assertFalse(Path(f'/proc/{pid}').exists(), 'watchdog must reap adopted children')


if __name__ == '__main__':
    unittest.main()
