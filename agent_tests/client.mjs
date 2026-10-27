import assert from 'node:assert/strict';
import {readFile,writeFile,readdir} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
import {AgentVault} from '../dist/agent-safe/vault.js';
import {spawn} from 'node:child_process';
const repo=resolve(fileURLToPath(new URL('..',import.meta.url)));
let input=''; for await (const chunk of process.stdin) input+=chunk;
const fixture=JSON.parse(input); input='';
const result={completed:false,checks:{}};
let stage='initialize',client,transport,raw='',diagnostics='';
let monitor,probePromise=Promise.resolve(),probeBusy=false,probeFailed=false,probeCount=0;
const secrets=[fixture.master,...Object.values(fixture.markers)];
const encodings=secrets.flatMap(s=>[s,encodeURIComponent(s),Buffer.from(s).toString('base64'),Buffer.from(s).toString('hex')]);
function noSecrets(value) { const text=typeof value==='string'?value:JSON.stringify(value); assert.ok(!encodings.some(s=>text.includes(s)),'secret_output'); }
async function start() {
  client=new Client({name:'isolated-agent-validation',version:'1'});
  transport=new StdioClientTransport({command:process.execPath,args:[join(repo,'dist/server.js'),'--agent-safe','--agent-root',fixture.root],env:{...process.env},stderr:'pipe'});
  transport.stderr?.on('data',x=>{diagnostics+=x;});
  await client.connect(transport);
  // Test-only observation of raw stdio, in addition to parsed MCP results.
  transport._process?.stdout?.on('data',x=>{raw+=x;});
  if (!monitor) monitor=setInterval(()=>{
    const rootPid=transport?._process?.pid;
    if(probeBusy||!rootPid)return;
    probeBusy=true;
    probePromise=new Promise(resolve=>{
      const child=spawn('powershell.exe',['-NoProfile','-File',join(repo,'agent_tests/process_probe.ps1')],{stdio:['pipe','pipe','pipe'],windowsHide:true});
      let text=''; child.stdout.on('data',x=>text+=x); child.stderr.on('data',()=>{});
      child.stdin.end(JSON.stringify({root_pid:rootPid,markers:encodings}));
      child.on('close',()=>{try {const p=JSON.parse(text);probeFailed ||= p.secret_args||p.session_argument;probeCount+=p.children_observed;}catch{probeFailed=true;}probeBusy=false;resolve();});
      child.on('error',()=>{probeFailed=true;probeBusy=false;resolve();});
    });
  },1200);
}
async function call(name,args={}) {
  const response=await client.callTool({name,arguments:args},undefined,{timeout:120000});
  noSecrets(response);
  if(response.isError) return {protocolError:true};
  const data=response.structuredContent;
  assert.deepEqual(JSON.parse(response.content[0].text),data);
  return data;
}
async function ok(name,args={}) { const value=await call(name,args); assert.equal(value.ok,true,name+':'+(value.error??'')); return value; }
try {
  await start();
  stage='tool-contract';
  const names=(await client.listTools()).tools.map(x=>x.name);
  assert.equal(names.length,12);
  await ok('status');
  const found=await ok('search'); assert.equal(found.count,4);
  assert.ok(found.items.every(x=>!('fields' in x)&&!('notes' in x)));
  await ok('sync');
  for(const name of ['keychain_get_password','keychain_get_item','keychain_get_totp','keychain_get_attachment','keychain_receive','keychain_send_get','credentials','resume_access']) assert.equal((await call(name)).protocolError,true);
  result.checks.contract_and_search=true;
  stage='ssh';
  const ssh=await ok('ssh_exec',{item_id:fixture.ids.ssh,command:'list-fixture-services'});
  assert.equal(ssh.exit_code,0); assert.ok(ssh.stdout.includes('synthetic service running'));
  assert.ok(ssh.stdout.includes('[REDACTED]')); assert.ok(ssh.stderr.includes('[REDACTED]'));
  const kh=join(fixture.root,'state/known_hosts'),saved=await readFile(kh);
  await writeFile(kh,'');
  try { assert.equal((await call('ssh_exec',{item_id:fixture.ids.ssh,command:'must-not-run'})).ok,false); }
  finally { await writeFile(kh,saved); }
  result.checks.ssh_exec_redaction_and_unknown_host_rejection=true;
  stage='mysql';
  const mysql=await ok('mysql_query',{item_id:fixture.ids.mysql,sql:'SELECT value FROM canaries',max_rows:900});
  assert.equal(mysql.rows.length,500); assert.equal(mysql.truncated,true);
  assert.ok(mysql.rows.every(row=>row[0]==='[REDACTED]'));
  const denied=await call('mysql_query',{item_id:fixture.ids.mysql,sql:'DELETE FROM canaries'}); assert.equal(denied.ok,false);
  const count=await ok('mysql_query',{item_id:fixture.ids.mysql,sql:'SELECT COUNT(*) AS n FROM canaries'}); assert.equal(count.rows[0][0],'510');
  result.checks.mysql_readonly_limit_and_redaction=true;
  stage='browser';
  assert.equal((await call('browser_open',{item_id:fixture.ids.web,url:'https://example.invalid/'})).ok,false);
  const page=await ok('browser_open',{item_id:fixture.ids.web});
  const refs=Object.fromEntries(page.controls.map(x=>[x.label,x.ref]));
  await ok('browser_fill_login',{page_id:page.page_id,password_ref:refs.Password,username_ref:refs.Username});
  await ok('browser_fill_totp',{page_id:page.page_id,ref:refs.OTP});
  const state=await ok('browser_state',{page_id:page.page_id});
  assert.ok(state.controls.every(x=>!('value' in x)));
  const button=state.controls.find(x=>x.label==='Sign in');
  await ok('browser_action',{page_id:page.page_id,action:'click',ref:button.ref});
  const signed=await ok('browser_state',{page_id:page.page_id});
  assert.equal(signed.title,'Signed in'); assert.ok(signed.text.includes('[REDACTED]'));
  assert.ok(!/\b\d{6,8}\b/.test(signed.text));
  await ok('browser_close');
  result.checks.browser_password_totp_submit_separation_and_echo_filter=true;
  stage='pause-restart';
  await ok('pause_access'); assert.equal((await call('search')).error,'disabled');
  await client.close();
  await start(); assert.equal((await call('search')).error,'disabled');
  await client.close();
  // Simulates the local management GUI, never exposed through MCP.
  await writeFile(join(fixture.root,'access.json'),JSON.stringify({enabled:true,allow_all:true,items:[]}));
  await start(); assert.equal((await ok('search')).count,4);
  await client.close();
  result.checks.pause_persists_and_restart_auto_unlock=true;
  stage='idle-revocation';
  const cfg=JSON.parse(await readFile(join(fixture.root,'config.json'),'utf8'));
  process.env.BW_BIN=fixture.bw; process.env.WARDEN_AGENT_SAFE_PROCESS='1';
  const idleVault=new AgentVault(fixture.root,cfg,100);
  let revocations=0;
  const revoke=idleVault.revoke.bind(idleVault);
  idleVault.revoke=async()=>{revocations++;await revoke();};
  assert.equal((await idleVault.invoke('search',{})).ok,true);
  await new Promise(resolve=>setTimeout(resolve,1200));
  assert.ok(revocations>=1);
  assert.equal((await idleVault.invoke('search',{})).ok,true);
  await idleVault.revoke();
  result.checks.idle_revoke_and_reunlock=true;
  stage='filesystem-and-protocol-leaks';
  const files=await readdir(join(fixture.root,'state'),{recursive:true});
  assert.ok(!files.some(f=>f.includes('.warden-mcp-session.json')));
  for(const file of await readdir(join(fixture.root,'logs'))) noSecrets(await readFile(join(fixture.root,'logs',file),'utf8'));
  noSecrets(raw); noSecrets(diagnostics);
  clearInterval(monitor); monitor=undefined; await probePromise;
  assert.equal(probeFailed,false); assert.ok(probeCount>0);
  result.checks.live_process_arguments_have_no_secrets_or_session_flags=true;
  noSecrets(await readFile(join(fixture.root,'config.json'),'utf8'));
  result.checks.no_plain_session_or_secret_logs=true;
  result.completed=true;
} catch(error) {
  result.failure_stage=stage;
  result.failure_kind=error?.name ?? 'Error';
  // Only synthetic fixture errors reach this report; redact before returning.
  let message=String(error?.message ?? '').slice(0,400);
  for(const value of encodings) message=message.replaceAll(value,'[REDACTED]');
  result.message=message;
} finally { clearInterval(monitor); await probePromise; if(client) await client.close().catch(()=>{}); }
process.stdout.write(JSON.stringify(result));
