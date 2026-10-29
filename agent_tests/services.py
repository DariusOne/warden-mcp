"""Loopback-only disposable SSH, MySQL and HTTPS fixtures."""
import base64
import http.server
import json
import logging
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import threading
import time
from urllib.parse import parse_qs
import paramiko
import pymysql
from harness_helpers import docker_command, valid_totp, isolated_environment
logging.getLogger('paramiko').setLevel(logging.CRITICAL)


class Services:
    def __init__(self, root, markers, docker, run_id):
        self.root, self.markers, self.docker, self.run_id = root, markers, docker, run_id
        self.closed = False
        self.web_received = []
        self.ssh_executed = 0
        self.ssh_auth = 0
        self.mysql_name = 'warden-agent-test-mysql-' + run_id
        self.mysql_started = False
        self.web = None
        self.sock = None

    def start(self):
        self.key = paramiko.RSAKey.generate(2048)
        self.sock = socket.socket()
        self.sock.bind(('127.0.0.1', 0)); self.sock.listen()
        self.sock.settimeout(0.5)
        self.ssh_port = self.sock.getsockname()[1]
        hostkeys = paramiko.HostKeys()
        hostkeys.add('[127.0.0.1]:' + str(self.ssh_port), self.key.get_name(), self.key)
        hostkeys.save(str(self.root / 'state' / 'known_hosts'))
        (self.root / 'state' / 'known_hosts').chmod(0o600)
        changed = paramiko.HostKeys()
        wrong = paramiko.RSAKey.generate(2048)
        changed.add('[127.0.0.1]:' + str(self.ssh_port), wrong.get_name(), wrong)
        changed.save(str(self.root / 'changed_known_hosts'))
        (self.root / 'changed_known_hosts').chmod(0o600)
        threading.Thread(target=self._ssh_loop, daemon=True).start()
        self._start_mysql()
        owner = self
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_GET(self):
                if self.path == '/__audit':
                    self.send_response(200); self.end_headers()
                    self.wfile.write(json.dumps({'submissions':len(owner.web_received), 'ssh_executed':owner.ssh_executed, 'ssh_auth':owner.ssh_auth}).encode())
                    return
                content = '<html><title>Agent fixture</title><body><form method="post" action="/login"><input name="user" aria-label="Username"><input name="password" type="password" aria-label="Password"><input name="otp" aria-label="OTP"><button>Sign in</button></form></body></html>'
                self.send_response(200); self.end_headers(); self.wfile.write(content.encode())
            def do_POST(self):
                body = parse_qs(self.rfile.read(int(self.headers['Content-Length'])).decode())
                owner.web_received.append({'password_ok':body.get('password',[''])[0] == owner.markers['password'], 'totp_valid': valid_totp(owner.markers['totp'], body.get('otp',[''])[0])})
                self.send_response(200); self.end_headers()
                self.wfile.write(('<html><title>Signed in</title><body>' + owner.markers['password'] + ' ' + body.get('otp',[''])[0] + '</body></html>').encode())
        self.web = http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.root / 'test-server.pem',self.root / 'test-server-key.pem')
        self.web.socket = ctx.wrap_socket(self.web.socket,server_side=True)
        threading.Thread(target=self.web.serve_forever,daemon=True).start()
        self.web_url = f'https://127.0.0.1:{self.web.server_port}/'

    def _ssh_loop(self):
        owner = self
        class Server(paramiko.ServerInterface):
            def check_auth_password(self, username, password):
                owner.ssh_auth += 1
                return paramiko.AUTH_SUCCESSFUL if username == 'tester' and password == owner.markers['password'] else paramiko.AUTH_FAILED
            def get_allowed_auths(self, username): return 'password'
            def check_channel_request(self, kind, chanid): return paramiko.OPEN_SUCCEEDED if kind == 'session' else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
            def check_channel_exec_request(self, channel, command):
                owner.ssh_executed += 1
                def reply():
                    time.sleep(0.05)
                    value = owner.markers['password']
                    channel.send(('synthetic service running\n' + value + '\n' + base64.b64encode(value.encode()).decode()).encode())
                    channel.send_stderr(owner.markers['ordinary'].encode())
                    channel.send_exit_status(0); channel.shutdown_write()
                threading.Thread(target=reply,daemon=True).start()
                return True
        def serve(conn):
            transport = paramiko.Transport(conn)
            try:
                transport.add_server_key(self.key); transport.start_server(server=Server())
                channel=transport.accept(10)
                deadline=time.monotonic()+20
                while channel is not None and transport.is_active() and time.monotonic()<deadline: time.sleep(0.05)
            except Exception: pass
            finally: transport.close()
        while not self.closed:
            try: conn,_=self.sock.accept()
            except (socket.timeout,OSError): continue
            threading.Thread(target=serve,args=(conn,),daemon=True).start()

    def _start_mysql(self):
        root_password=secrets.token_urlsafe(30)
        env=dict(isolated_environment(os.environ),MYSQL_ROOT_PASSWORD=root_password)
        args=[*docker_command(self.docker),'run','--detach','--pull=never',
              '--name',self.mysql_name,'--label','local.warden.test='+self.run_id,
              '--publish','127.0.0.1::3306','--tmpfs','/var/lib/mysql:rw,size=512m',
              '--env','MYSQL_ROOT_PASSWORD','--env','MYSQL_ROOT_HOST=%','mysql@sha256:4bc6bc963e6d8443453676cae56536f4b8156d78bae03c0145cbe47c2aad73bb']
        p=subprocess.run(args,env=env,capture_output=True)
        if p.returncode: raise RuntimeError('mysql_fixture_start')
        self.mysql_started=True
        port=subprocess.check_output([*docker_command(self.docker),'port',self.mysql_name,'3306'],text=True).strip()
        self.mysql_port=int(port.rsplit(':',1)[1])
        conn=None
        for _ in range(120):
            try:
                conn=pymysql.connect(host='127.0.0.1',port=self.mysql_port,user='root',password=root_password,connect_timeout=1,autocommit=True)
                break
            except Exception: time.sleep(0.5)
        if conn is None: raise RuntimeError('mysql_fixture_readiness')
        with conn:
            with conn.cursor() as cur:
                cur.execute('CREATE DATABASE agent_test')
                cur.execute("CREATE USER 'tester'@'%%' IDENTIFIED BY %s",(self.markers['password'],))
                cur.execute("GRANT SELECT ON agent_test.* TO 'tester'@'%'")
                cur.execute('CREATE TABLE agent_test.canaries (id INT, value TEXT)')
                cur.executemany('INSERT INTO agent_test.canaries VALUES (%s,%s)',[(i,self.markers['password']) for i in range(510)])

    def close(self):
        self.closed=True
        if self.sock: self.sock.close()
        if self.web: self.web.shutdown(); self.web.server_close()
        if self.mysql_started:
            p=subprocess.run([*docker_command(self.docker),'inspect','--format','{{ index .Config.Labels "local.warden.test" }}',self.mysql_name],capture_output=True,text=True)
            if p.returncode == 0 and p.stdout.strip() == self.run_id:
                subprocess.run([*docker_command(self.docker),'rm','-f',self.mysql_name],capture_output=True,check=True)
                remaining=subprocess.run([*docker_command(self.docker),'ps','-a','--filter','name=^/'+self.mysql_name+'$','--filter','label=local.warden.test='+self.run_id,'--format','{{.Names}}'],capture_output=True,text=True,check=True)
                if remaining.stdout.strip(): raise RuntimeError('mysql_fixture_cleanup')
            else:
                raise RuntimeError('mysql_fixture_cleanup_identity')
