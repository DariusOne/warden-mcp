"""Linux-only bw supervisor. Never read the credential pipe in the watchdog.

Node launches this in a new session with a clean environment. fd 3 carries the
CLI environment, separate from CLI stdin. Only the contained fork reads it.
The subreaper watches Node's pidfd, kills/reaps even detached descendants, and
returns the actual CLI exit status after reclaiming its whole private tree.
"""
import ctypes
import errno
import json
import os
from pathlib import Path
import select
import signal
import sys
import time


def report(code):
    try:
        os.write(4, (code + '\n').encode('ascii'))
    except OSError:
        pass


def reclaim():
    children_file = Path(f'/proc/self/task/{os.getpid()}/children')
    while True:
        # Only our unreaped children can occur here: PID reuse cannot turn an
        # owned child into an unrelated target before waitpid releases its PID.
        for pid in map(int, children_file.read_text().split()):
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


def close_except(keep):
    for name in os.listdir('/proc/self/fd'):
        fd = int(name)
        if fd not in keep:
            try:
                os.close(fd)
            except OSError:
                pass


def main():
    if sys.platform != 'linux' or os.getsid(0) != os.getpid():
        raise RuntimeError()
    parent = int(sys.argv[1])
    if parent <= 1 or os.getppid() != parent:
        raise RuntimeError()
    parent_fd = os.pidfd_open(parent)
    if os.getppid() != parent:
        raise RuntimeError()
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise RuntimeError()
    watched = {signal.SIGTERM, signal.SIGINT, signal.SIGHUP}
    old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, watched)
    read_gate, write_gate = os.pipe()
    child = os.fork()
    if child == 0:
        try:
            close_except({0, 1, 2, 3, 4, read_gate})
            os.set_inheritable(4, False)
            os.setsid()
            signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
            if os.read(read_gate, 1) != b'1':
                os._exit(1)
            os.close(read_gate)
            # No credential has entered Python memory before this fork.
            with os.fdopen(3, 'rb') as pipe:
                payload = pipe.read(1024 * 1024 + 1)
            if len(payload) > 1024 * 1024:
                raise RuntimeError()
            env = json.loads(payload)
            if not isinstance(env, dict) or not all(
                isinstance(k, str) and isinstance(v, str)
                for k, v in env.items()
            ):
                raise RuntimeError()
            report('READY')
            os.execve(sys.argv[2], sys.argv[2:], env)
        except OSError as error:
            report('ENOENT' if error.errno == errno.ENOENT else 'EXEC')
            os._exit(1)
        except BaseException:
            report('CONTAINMENT')
            os._exit(1)
    stopped = False

    def stop(_signum, _frame):
        nonlocal stopped
        stopped = True

    for signum in watched:
        signal.signal(signum, stop)
    signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
    code = 1
    try:
        child_fd = os.pidfd_open(child)
        # Drop all private streams and the unread credential pipe before
        # permitting the child to receive secrets. Never keep stdin alive.
        close_except({parent_fd, child_fd, write_gate})
        null = os.open(os.devnull, os.O_RDWR)
        for fd in (0, 1, 2):
            os.dup2(null, fd)
        if null > 2:
            os.close(null)
        os.write(write_gate, b'1')
        os.close(write_gate)
        while not stopped:
            ready = select.select([parent_fd, child_fd], [], [], .05)[0]
            if parent_fd in ready:
                break
            if child_fd in ready:
                _, status = os.waitpid(child, 0)
                code = os.waitstatus_to_exitcode(status)
                if code < 0:
                    code = 128 - code
                break
    finally:
        reclaim()
    return code


if __name__ == '__main__':
    try:
        result = main()
    except BaseException:
        report('CONTAINMENT')
        result = 1
    os._exit(result)
