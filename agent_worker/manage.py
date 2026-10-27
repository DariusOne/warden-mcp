"""Interactive, local-only resume window. No MCP resume operation exists."""
import json
from pathlib import Path
import sys
import tkinter as tk
from tkinter import messagebox
from bridge_core import atomic_json


def main():
    root = Path(sys.argv[1]).resolve()
    window = tk.Tk()
    window.title('Vaultwarden → Codex · 本机接入管理')
    window.geometry('480x220')
    window.resizable(False, False)
    status = tk.StringVar()
    def refresh():
        try:
            p = json.loads((root/'access.json').read_text(encoding='utf-8-sig'))
            status.set('接入已启用' if p.get('enabled') else '接入已暂停')
        except Exception: status.set('请检查本机接入配置')
    def resume():
        try:
            if not (root/'state/auth.dpapi').is_file(): raise RuntimeError()
            p = json.loads((root/'access.json').read_text(encoding='utf-8-sig'))
            p['enabled'] = True
            atomic_json(root/'access.json',p)
            refresh()
            messagebox.showinfo('已恢复','已允许 Codex 按需解锁；无需在聊天中提供主密码。')
        except Exception: messagebox.showerror('未完成','本机授权文件不可用，请检查登记状态。')
    tk.Label(window,textvariable=status,font=('Microsoft YaHei UI',14)).pack(pady=20)
    tk.Label(window,text='仅供当前 Windows 用户本机操作。\n暂停请在 Codex 调用 pause_access，关闭浏览器并撤销会话。').pack()
    tk.Button(window,text='恢复接入',command=resume,width=18).pack(pady=20)
    refresh(); window.mainloop()


if __name__ == '__main__': main()
