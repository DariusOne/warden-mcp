"""Local Vaultwarden credential broker. Secrets never form MCP return values."""
from __future__ import annotations
import base64
import ctypes
from ctypes import wintypes
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import threading
import time
from urllib.parse import quote, urlsplit

ROOT = Path(__file__).resolve().parent
SERVER = "https://vault.example.invalid/bitwarden"
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


class BridgeError(Exception):
    def __init__(self, code: str, message: str, details=None):
        super().__init__(message)
        self.code, self.message = code, message
        self.details = details


def atomic_json(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def load_json(path, fallback):
    if not path.exists():
        return fallback
    return json.loads(path.read_text(encoding="utf-8"))


def dpapi(data: bytes, decrypt=False) -> bytes:
    """User-scoped Windows DPAPI. Never use CRYPTPROTECT_LOCAL_MACHINE."""
    class Blob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]
    buf = ctypes.create_string_buffer(data)
    source = Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte)))
    target = Blob()
    crypt = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    if decrypt:
        fn = crypt.CryptUnprotectData
        fn.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.c_void_p,
                       ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
        ok = fn(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(target))
    else:
        fn = crypt.CryptProtectData
        fn.argtypes = [ctypes.POINTER(Blob), wintypes.LPCWSTR, ctypes.c_void_p,
                       ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
        ok = fn(ctypes.byref(source), "Codex Vaultwarden bridge", None, None, None, 1, ctypes.byref(target))
    ctypes.memset(buf, 0, len(data))
    if not ok:
        raise BridgeError("credential_store", "Windows 用户凭据解密失败；请用登记凭据的 Windows 账户运行。")
    try:
        return ctypes.string_at(target.pbData, target.cbData)
    finally:
        ctypes.memset(target.pbData, 0, target.cbData)
        kernel.LocalFree(target.pbData)


class Redactor:
    def __init__(self):
        self.values = set()
    def add(self, *values):
        for value in values:
            if not isinstance(value, str) or not value:
                continue
            self.values.add(value)
            self.values.add(quote(value, safe=""))
            self.values.add(base64.b64encode(value.encode()).decode())
            self.values.add(json.dumps(value, ensure_ascii=True)[1:-1])
    def clean(self, value):
        if isinstance(value, dict):
            return {self.clean(str(k)): self.clean(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.clean(v) for v in value]
        if isinstance(value, str):
            for secret in sorted(self.values, key=len, reverse=True):
                value = value.replace(secret, "[REDACTED]")
        return value


def origin(url: str) -> str:
    p = urlsplit(url)
    if p.scheme not in ("https", "http") or not p.hostname or p.username or p.password:
        raise BridgeError("target", "条目需要有效的 HTTP(S) 网站地址，地址中不能含用户名或密码。")
    host = p.hostname.lower()
    if ":" in host:
        host = "[" + host + "]"
    port = p.port or (443 if p.scheme == "https" else 80)
    return f"{p.scheme}://{host}:{port}"


def urls_of(item):
    return [u.get("uri", "") for u in item.get("login", {}).get("uris", [])
            if u.get("uri") and u.get("match") != 5]


def check_browser_target(item, url):
    allowed = set()
    for saved in urls_of(item):
        try:
            candidate = origin(saved)
            if candidate.startswith('https:'):
                allowed.add(candidate)
        except (BridgeError, ValueError):
            continue
    wanted = origin(url)
    if wanted not in allowed:
        raise BridgeError("origin_denied", "目标网站的协议、主机和端口必须与此条目保存的网址一致。")
    if wanted == origin(SERVER):
        raise BridgeError("vault_ui_denied", "凭据工具不自动登录密码库网页本身。")
    if not wanted.startswith("https:"):
        raise BridgeError("https_required", "网页密码自动填充要求 HTTPS。")
    return allowed


def connection_target(item, service):
    fields = {str(f.get("name", "")).strip().casefold(): str(f.get("value", "")).strip()
              for f in item.get("fields") or [] if f.get("type", 0) == 0}
    def first(names):
        return next((fields[n] for n in names if fields.get(n)), "")
    host = first(["host", "hostname", "ip", "server", "主机", "服务器", "服务器ip", "ip地址", "地址"])
    port = first(["port", "端口", service + "端口"])
    database = first(["database", "dbname", "数据库", "数据库名"])
    scheme_url = next((u for u in urls_of(item) if u.startswith(service + "://")), None)
    if scheme_url:
        p = urlsplit(scheme_url)
        host = host or p.hostname or ""
        port = port or str(p.port or "")
        database = database or p.path.lstrip("/")
    if not host or not re.fullmatch(r"[A-Za-z0-9._:\-\[\]]+", host):
        raise BridgeError("host_required", "请在条目添加文本自定义字段 host（主机/IP）和 port（端口）。")
    try:
        port = int(port or (3306 if service == "mysql" else 22))
        if not 1 <= port <= 65535:
            raise ValueError()
    except ValueError:
        raise BridgeError("port", "条目端口无效。") from None
    login = item.get("login") or {}
    if not login.get("username") or not login.get("password"):
        raise BridgeError("login_required", "该服务条目需要原生用户名和密码字段。")
    return {"host": host, "port": port, "user": login["username"], "password": login["password"], "database": database}


def check_read_query(sql):
    if len(sql) > 16000 or not re.match(r"^\s*(SELECT|SHOW|DESCRIBE|DESC|EXPLAIN)\b", sql, re.I):
        raise BridgeError("readonly_sql", "只支持 SELECT、SHOW、DESCRIBE 和 EXPLAIN 查询。")
    if re.search(r";|--|/\*|#|:=|\b(INTO|OUTFILE|DUMPFILE|LOAD_FILE|SLEEP|BENCHMARK|GET_LOCK|RELEASE_LOCK|FOR\s+(UPDATE|SHARE)|LOCK|ANALYZE)\b", sql, re.I):
        raise BridgeError("readonly_sql", "查询包含未允许的语法。")


def mysql_query(broker, item_id, sql, max_rows=100):
    import pymysql
    check_read_query(sql)
    target = connection_target(broker.get_item(item_id), "mysql")
    args = {"host": target["host"], "port": target["port"], "user": target["user"],
            "password": target["password"], "connect_timeout": 8, "read_timeout": 15,
            "write_timeout": 10, "local_infile": False, "autocommit": False, "charset": "utf8mb4"}
    if target["database"]:
        args["database"] = target["database"]
    # Stream result rows; closing the connection cancels any unread remainder.
    # MySQL transport encryption depends on the target server configuration.
    args['cursorclass'] = pymysql.cursors.SSCursor
    conn = None
    try:
        conn = pymysql.connect(**args)
        cur = conn.cursor()
        cur.execute("SET SESSION TRANSACTION READ ONLY")
        cur.execute("SET SESSION MAX_EXECUTION_TIME=10000")
        cur.execute(sql)
        cols = [x[0] for x in cur.description or []]
        limit = min(max(int(max_rows), 1), 500)
        rows = cur.fetchmany(limit + 1)
        return broker.redactor.clean({"columns": cols, "rows": [[str(v) if v is not None else None for v in row]
               for row in rows[:limit]], "truncated": len(rows) > limit})
    except BridgeError:
        raise
    except Exception:
        raise BridgeError("mysql_failed", "MySQL 连接或只读查询失败；原始错误已隐藏以避免泄露凭据。") from None
    finally:
        if conn is not None:
            conn.close()


def ssh_exec(broker, item_id, command, timeout=20, *, approval=None):
    import paramiko
    from ssh_trust import connect
    if not command or len(command) > 16000:
        raise BridgeError("command", "命令为空或过长。")
    target = connection_target(broker.get_item(item_id), "ssh")
    client = None
    try:
        client = connect(broker.root, target, item_id, approval)
        started = time.monotonic()
        _, stdout, stderr = client.exec_command(command, timeout=min(max(timeout, 1), 60))
        channel = stdout.channel
        out, err = bytearray(), bytearray()
        while True:
            if channel.recv_ready():
                out.extend(channel.recv(4096))
            if channel.recv_stderr_ready():
                err.extend(channel.recv_stderr(4096))
            if len(out) + len(err) > 65536:
                channel.close()
                raise BridgeError("output_limit", "SSH 输出超过 64 KiB，连接已关闭。")
            if time.monotonic() - started > min(max(timeout, 1), 60):
                channel.close()
                raise BridgeError("ssh_timeout", "SSH 命令超时，连接已关闭。")
            if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                break
            time.sleep(0.03)
        return broker.redactor.clean({"exit_code": channel.recv_exit_status(), "stdout": out.decode("utf-8", "replace"),
                                      "stderr": err.decode("utf-8", "replace")})
    except BridgeError:
        raise
    except paramiko.SSHException:
        raise BridgeError("ssh_failed", "SSH 握手或身份验证失败；原始错误已隐藏。") from None
    except Exception:
        raise BridgeError("ssh_failed", "SSH 连接失败，请检查条目地址、端口及账户。") from None
    finally:
        if client is not None:
            client.close()
