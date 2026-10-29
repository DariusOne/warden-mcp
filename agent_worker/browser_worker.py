"""A dedicated browser thread: MCP never receives secrets or browser cookies."""
from __future__ import annotations
import concurrent.futures
import json
import os
from pathlib import Path
import sys
import queue
import re
import shutil
import threading
import uuid
from urllib.parse import urlsplit
from job import browser_profile_directory
from bridge_core import BridgeError, check_browser_target, origin, urls_of


class BrowserWorker:
    def __init__(self, broker, *, test_options=None):
        self.broker = broker
        self.test_options = test_options or {}
        self.queue = queue.Queue()
        self.thread = None
        self.pages = {}
        self.browser = None
        self.profiles = {}
        self.profile_dirs = {}
    def remove_profile(self, profile):
        # Pin the parent when the profile is created. Absolute-path rmtree
        # would follow a later replacement of an ancestor directory.
        parent_fd = self.profile_dirs[profile]
        shutil.rmtree(profile.name, dir_fd=parent_fd)
        os.close(parent_fd)
        del self.profile_dirs[profile]
    def call(self, operation, **kwargs):
        if not self.thread or not self.thread.is_alive():
            self.thread = threading.Thread(target=self._loop, daemon=True, name="vaultwarden-browser")
            self.thread.start()
        future = concurrent.futures.Future()
        self.queue.put((future, operation, kwargs))
        try:
            result = future.result(timeout=50)
            if operation == 'close_all':
                self.thread.join(timeout=10)
                if self.thread.is_alive():
                    raise BridgeError('browser_timeout', 'Browser shutdown timed out')
                self.thread = None
            return result
        except concurrent.futures.TimeoutError:
            raise BridgeError("browser_timeout", "浏览器操作超时，请检查受控浏览器窗口。") from None
    def _loop(self):
        from playwright.sync_api import sync_playwright
        with sync_playwright() as pw:
            self.pw = pw
            while True:
                future, action, kwargs = self.queue.get()
                try:
                    result = getattr(self, "do_" + action)(**kwargs)
                    future.set_result(self.broker.redactor.clean(result))
                except BridgeError as error:
                    future.set_exception(error)
                except Exception:
                    future.set_exception(BridgeError("browser_failed", "浏览器操作失败，请刷新页面状态后重试；原始错误已隐藏。"))
                if action == "close_all":
                    break
    def entry(self, page_id):
        if page_id not in self.pages or self.pages[page_id]["page"].is_closed():
            raise BridgeError("page", "受控页面不存在或已关闭，请重新打开。")
        entry = self.pages[page_id]
        item = self.broker.get_item(entry["item_id"])
        # Recheck the current vault entry before every action, including when
        # the user removes a previously allowed secondary origin.
        current = check_browser_target(item, entry['page'].url)
        entry['origins'].intersection_update(current)
        if origin(entry["page"].url) not in entry["origins"]:
            raise BridgeError("origin_denied", "页面已离开条目允许的网址。")
        return entry
    def do_open(self, item_id, url=""):
        item = self.broker.get_item(item_id)
        if not url:
            url = next((u for u in urls_of(item) if u.startswith("https://")), "")
        allowed = check_browser_target(item, url)
        launch_args = self.test_options.get('launch_args', [])
        # Test fixtures may pin one ephemeral certificate, not weaken sandbox,
        # reuse a profile, enable a listener, or disable TLS verification.
        if not isinstance(launch_args, list) or any(
            not isinstance(arg, str) or not re.fullmatch(r'--ignore-certificate-errors-spki-list=[A-Za-z0-9+/]{43}=', arg)
            for arg in launch_args
        ):
            raise BridgeError('browser_config', 'Unsafe browser launch options')
        if sys.platform == 'linux':
            try:
                config = json.loads((Path(self.broker.root) / 'config.json').read_text(encoding='utf-8-sig'))
                executable = config['browser_executable']
                if not isinstance(executable, str) or not Path(executable).is_absolute():
                    raise ValueError()
                path = Path(executable)
                if str(path.resolve(strict=True)) != executable or not path.is_file() or not os.access(path, os.X_OK):
                    raise ValueError()
                if path.stat().st_mode & 0o022:
                    raise ValueError()
            except (KeyError, TypeError, ValueError, OSError):
                raise BridgeError('browser_config', 'Dedicated Chromium executable required') from None
            try:
                directory = browser_profile_directory(self.broker.root)
            except (ValueError, OSError):
                raise BridgeError('browser_config', 'Private runtime browser directory required') from None
            parent_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                profile = directory / ('session-' + uuid.uuid4().hex)
                os.mkdir(profile.name, mode=0o700, dir_fd=parent_fd)
            except BaseException:
                os.close(parent_fd)
                raise
            self.profile_dirs[profile] = parent_fd
            try:
                context = self.pw.chromium.launch_persistent_context(
                    user_data_dir=str(profile), executable_path=executable,
                    chromium_sandbox=True, headless=self.test_options.get('headless', True),
                    env={**os.environ, 'HOME': str(profile), 'XDG_CONFIG_HOME': str(profile),
                         'XDG_CACHE_HOME': str(profile)},
                    # Leave TMPDIR unchanged: Chromium's AF_UNIX singleton
                    # sockets fail for deep profile paths (108-byte limit).
                    args=launch_args, service_workers='block',
                    accept_downloads=False, ignore_https_errors=False)
            except Exception:
                self.remove_profile(profile)
                raise
            self.profiles[context] = profile
        else:
            if not self.browser:
                self.browser = self.pw.chromium.launch(channel="msedge", chromium_sandbox=True,
                    headless=self.test_options.get("headless", False), args=launch_args)
            context = self.browser.new_context(service_workers="block", accept_downloads=False,
                                              ignore_https_errors=False)
        blocked = []
        def route(request_route):
            try:
                permitted = origin(request_route.request.url) in allowed
            except (BridgeError, ValueError):
                permitted = False
            if permitted:
                request_route.continue_()
            else:
                blocked.append(True)
                request_route.abort()
        context.route("**/*", route)
        def websocket_route(ws):
            url = ws.url.replace("wss://", "https://", 1).replace("ws://", "http://", 1)
            if origin(url) in allowed:
                ws.connect_to_server()
            else:
                ws.close()
        context.route_web_socket("**/*", websocket_route)
        page = context.new_page()
        page.set_default_timeout(8000)
        page.goto(url, wait_until="domcontentloaded", timeout=25000)
        page_id = uuid.uuid4().hex[:12]
        self.pages[page_id] = {"page": page, "context": context, "item_id": item_id,
                               "origins": allowed, "refs": {}, "blocked": blocked}
        return self.do_state(page_id)
    def do_state(self, page_id):
        e = self.entry(page_id)
        page = e["page"]
        refs, fields = {}, []
        for handle in page.locator("input,button,textarea,select,a").element_handles()[:250]:
            if not handle.is_visible():
                continue
            info = handle.evaluate("""el => ({tag:el.tagName.toLowerCase(),type:el.getAttribute('type')||'',
                name:el.getAttribute('name')||'',label:el.getAttribute('aria-label')||
                (el.labels&&el.labels[0]?el.labels[0].innerText:'')||el.getAttribute('placeholder')||
                (['BUTTON','A'].includes(el.tagName)?el.innerText:'')})""")
            ref = "e" + str(len(refs) + 1)
            refs[ref] = handle
            fields.append({"ref": ref, **{k: str(v)[:180] for k, v in info.items()}})
        e["refs"] = refs
        p = urlsplit(page.url)
        # Do not return query/fragment, input values, cookies or HTML.
        return {"page_id": page_id, "url": f"{p.scheme}://{p.netloc}{p.path}",
                "title": page.title(), "text": page.locator("body").inner_text()[:6000],
                "controls": fields, "blocked_external_requests": len(e["blocked"])}
    def ref(self, e, ref):
        if ref not in e["refs"]:
            raise BridgeError("ref", "控件引用已失效，请先调用 browser_state。")
        return e["refs"][ref]
    def validate_password_input(self, e, handle):
        if origin(e["page"].url) not in e["origins"]:
            raise BridgeError("origin_denied", "页面地址不匹配。")
        info = handle.evaluate("""el => ({type:el.type,tag:el.tagName,action:el.form?el.form.action:location.href})""")
        if info["tag"] != "INPUT" or info["type"] != "password":
            raise BridgeError("password_field", "密码只能填入 password 类型输入框。")
        if origin(info["action"]) not in e["origins"]:
            raise BridgeError("form_origin", "表单会提交到未授权的网站，已拒绝填充。")
    def do_fill_login(self, page_id, password_ref, username_ref=""):
        e = self.entry(page_id)
        item = self.broker.get_item(e["item_id"])
        password = (item.get("login") or {}).get("password")
        if not password:
            raise BridgeError("password_missing", "此条目没有登录密码。")
        handle = self.ref(e, password_ref)
        self.validate_password_input(e, handle)
        if username_ref:
            self.ref(e, username_ref).fill((item.get("login") or {}).get("username") or "")
        handle.fill(password)
        # Recheck after typing to catch navigation or form changes during input.
        self.validate_password_input(e, handle)
        return {"filled": True, "page_id": page_id, "submitted": False}
    def do_fill_totp(self, page_id, ref):
        e = self.entry(page_id)
        handle = self.ref(e, ref)
        if handle.evaluate("el=>el.tagName") != "INPUT":
            raise BridgeError("otp_field", "TOTP 只能填入输入框。")
        info = handle.evaluate("el=>el.form?el.form.action:location.href")
        if origin(info) not in e["origins"]:
            raise BridgeError("form_origin", "验证码表单目标未授权。")
        handle.fill(self.broker.otp(e["item_id"]))
        return {"filled": True, "page_id": page_id, "submitted": False}
    def do_action(self, page_id, action, ref="", text=""):
        e = self.entry(page_id)
        handle = self.ref(e, ref)
        if action == "click":
            handle.click()
        elif action == "fill":
            if handle.evaluate("el=>el.type") == "password":
                raise BridgeError("use_secret_fill", "请使用 browser_fill_login 填写密码。")
            if len(text) > 4000:
                raise BridgeError("text_limit", "输入内容过长。")
            handle.fill(text)
        elif action == "press":
            if text not in ["Enter", "Tab", "Escape", "ArrowDown", "ArrowUp"]:
                raise BridgeError("key", "此按键未开放。")
            handle.press(text)
        else:
            raise BridgeError("action", "仅支持 click、fill、press。")
        e["refs"] = {}
        return {"performed": action, "page_id": page_id, "next": "调用 browser_state 获取最新页面"}
    def do_close_all(self):
        for context, profile in list(self.profiles.items()):
            context.close()
            self.remove_profile(profile)
            del self.profiles[context]
        if self.browser:
            self.browser.close()
        self.browser = None
        self.pages.clear()
        return {"closed": True}
