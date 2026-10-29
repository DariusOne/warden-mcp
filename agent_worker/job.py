"""Private-worker containment. Linux supervisor; Windows kill-on-close Job.

On Linux this must run BEFORE threads, credentials or subprocesses exist. The
spawned process becomes a subreaper/watchdog; only its forked child returns to
worker.py. The child has a separate session. Thus even Playwright's detached
browser processes are adopted, killed and reaped when the worker goes away.
"""
import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import select
import signal
import shutil
import stat
import sys
import time
import uuid


_browser_owner = None


def private_browser_directory(root):
    """Validate the dedicated runtime, never a user's existing profile."""
    directory = Path(root) / 'state' / 'browser'
    for path in (Path(root), directory.parent, directory):
        if path.resolve() != path:
            raise ValueError('browser_directory')
        try:
            path.mkdir(mode=0o700)
        except FileExistsError:
            pass
        else:
            path.chmod(0o700)
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o777 != 0o700:
            raise ValueError('browser_directory')
    return directory


def browser_profile_directory(root):
    directory = private_browser_directory(root)
    if _browser_owner is None:
        # Standalone BrowserWorker callers retain their normal close cleanup.
        return directory
    owner_root, path, identity = _browser_owner
    info = path.lstat()
    if Path(root) != owner_root or not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) != identity:
        raise ValueError('browser_owner')
    return path


def _reserve_browser_owner(root):
    directory = private_browser_directory(root)
    parent_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    name = 'worker-' + uuid.uuid4().hex
    try:
        os.mkdir(name, mode=0o700, dir_fd=parent_fd)
        directory_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        os.fchmod(directory_fd, 0o700)
    except BaseException:
        os.close(parent_fd)
        raise
    return Path(root), directory / name, parent_fd, directory_fd


def _remove_browser_owner(owner):
    # Run ONLY after _reclaim has reaped every owned descendant. Pinned dirfds
    # prevent renamed parents or profile symlinks from redirecting deletion.
    _, path, parent_fd, directory_fd = owner
    try:
        # Reopen "." through the pinned inode: some filesystems snapshot a
        # directory stream opened before the child created its profiles.
        scan_fd = os.open('.', os.O_RDONLY | os.O_DIRECTORY, dir_fd=directory_fd)
        try:
            names = os.listdir(scan_fd)
        finally:
            os.close(scan_fd)
        for name in names:
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                shutil.rmtree(name, dir_fd=directory_fd)
            else:
                os.unlink(name, dir_fd=directory_fd)
        info = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        owned = os.fstat(directory_fd)
        if (info.st_dev, info.st_ino) == (owned.st_dev, owned.st_ino):
            os.rmdir(path.name, dir_fd=parent_fd)
    except FileNotFoundError:
        pass
    finally:
        os.close(directory_fd)
        os.close(parent_fd)


def _close_inherited_fds(keep):
    # A watchdog must not retain the private protocol or credential sockets.
    for name in os.listdir('/proc/self/fd'):
        fd = int(name)
        if fd not in keep:
            try:
                os.close(fd)
            except OSError:
                pass
    fd = os.open(os.devnull, os.O_RDWR)
    for target in (0, 1, 2):
        os.dup2(fd, target)
    if fd > 2:
        os.close(fd)


def _reclaim(worker):
    # Never signal an inherited process group (in particular Hermes/Node's).
    try:
        if os.getpgid(worker) == worker and worker != os.getpgrp():
            os.killpg(worker, signal.SIGKILL)
    except ProcessLookupError:
        pass
    children_file = Path(f'/proc/self/task/{os.getpid()}/children')
    while True:
        # The subreaper adopts escaped-session grandchildren as their parents
        # die. Do not scan or signal unrelated host/browser processes.
        children = [int(pid) for pid in children_file.read_text().split()]
        for pid in children:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        while True:
            try:
                pid, _ = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                return
            if pid == 0:
                break
        time.sleep(.01)


def _linux_containment():
    global _browser_owner
    # Fail closed unless Node detached us. Never setsid an arbitrary caller or
    # kill the caller's group in an attempt to repair an unsafe launch.
    if os.getpgrp() != os.getpid() or os.getsid(0) != os.getpid():
        raise RuntimeError('worker_containment')
    parent = os.getppid()
    expected_parent = os.environ.pop('WARDEN_PARENT_PID', str(parent))
    if parent <= 1 or expected_parent != str(parent):
        raise RuntimeError('worker_containment')
    parent_fd = os.pidfd_open(parent)
    # The parent may exit between getppid and pidfd_open. Never watch a
    # recycled PID or a reparented process instead of the launching Node.
    if os.getppid() != parent:
        os.close(parent_fd)
        raise RuntimeError('worker_containment')
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise RuntimeError('worker_containment')
    # The real worker's runtime argument has config.json; process-only callers
    # need no profile owner. Reserve before the child can load any credentials.
    owner = None
    if len(sys.argv) > 1 and (Path(sys.argv[1]) / 'config.json').is_file():
        owner = _reserve_browser_owner(Path(sys.argv[1]))
        info = os.fstat(owner[3])
        _browser_owner = (owner[0], owner[1], (info.st_dev, info.st_ino))
    watched_signals = {signal.SIGTERM, signal.SIGINT, signal.SIGHUP}
    old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, watched_signals)
    read_fd, write_fd = os.pipe()
    worker = os.fork()
    if worker == 0:
        if owner is not None:
            os.close(owner[2])
            os.close(owner[3])
        os.close(parent_fd)
        os.close(write_fd)
        os.setsid()
        signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
        ready = os.read(read_fd, 1)
        os.close(read_fd)
        if ready != b'1':
            os._exit(1)
        return os.getppid()
    os.close(read_fd)
    stopped = False

    def stop(_signum, _frame):
        nonlocal stopped
        stopped = True

    for signum in watched_signals:
        signal.signal(signum, stop)
    signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
    try:
        worker_fd = os.pidfd_open(worker)
        kept = {parent_fd, worker_fd, write_fd}
        if owner is not None:
            kept.update(owner[2:])
        _close_inherited_fds(kept)
        os.write(write_fd, b'1')
        os.close(write_fd)
        while not stopped:
            if select.select([parent_fd, worker_fd], [], [], .1)[0]:
                break
    finally:
        _reclaim(worker)
        if owner is not None:
            _remove_browser_owner(owner)
        os._exit(0)


def contain_children():
    if sys.platform == 'linux':
        return _linux_containment()
    if sys.platform != 'win32':
        raise RuntimeError('worker_containment')
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    class Basic(ctypes.Structure):
        _fields_ = [('process_time', ctypes.c_int64), ('job_time', ctypes.c_int64),
                    ('flags', wintypes.DWORD), ('min_ws', ctypes.c_size_t),
                    ('max_ws', ctypes.c_size_t), ('active', wintypes.DWORD),
                    ('affinity', ctypes.c_size_t), ('priority', wintypes.DWORD),
                    ('scheduling', wintypes.DWORD)]
    class IO(ctypes.Structure):
        _fields_ = [(name, ctypes.c_uint64) for name in ('read_ops','write_ops','other_ops','read_bytes','write_bytes','other_bytes')]
    class Extended(ctypes.Structure):
        _fields_ = [('basic', Basic), ('io', IO), ('process_memory', ctypes.c_size_t),
                    ('job_memory', ctypes.c_size_t), ('peak_process', ctypes.c_size_t), ('peak_job', ctypes.c_size_t)]
    kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel.CreateJobObjectW.restype = wintypes.HANDLE
    kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    handle = kernel.CreateJobObjectW(None, None)
    info = Extended()
    info.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    if not handle or not kernel.SetInformationJobObject(handle, 9, ctypes.byref(info), ctypes.sizeof(info)):
        raise RuntimeError('worker_containment')
    if not kernel.AssignProcessToJobObject(handle, kernel.GetCurrentProcess()):
        raise RuntimeError('worker_containment')
    # Do not inherit the handle. Windows closes it on worker termination.
    return handle
