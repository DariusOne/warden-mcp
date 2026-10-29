import assert from 'node:assert/strict';
import {readFile,writeFile,readdir,rename,chmod} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
import {ElicitRequestSchema} from '@modelcontextprotocol/sdk/types.js';
import {AgentVault} from '../dist/agent-safe/vault.js';
import {configureBwCliContainment} from '../dist/bw/bwCli.js';
import {spawn} from 'node:child_process';
const repo=resolve(fileURLToPath(new URL('..',import.meta.url)));
let input=''; for await (const chunk of process.stdin) input+=chunk;
const fixture=JSON.parse(input); input='';
const result={completed:false,checks:{}};
const successes=new Set(),errors=new Set(),identities=new Map();
let stage='initialize',client,transport,idleVault,raw='',diagnostics='';
let hostDecision='decline',hostPrompts=0;
let monitor,probePromise=Promise.resolve(),probeBusy=false,probeFailed=false,probeCount=0;
const secrets=[fixture.master,...Object.values(fixture.markers)];
const encodings=secrets.flatMap(s=>[s,encodeURIComponent(s),Buffer.from(s).toString('base64'),Buffer.from(s).toString('hex')]);
function noSecrets(value) { const text=typeof value==='string'?value:JSON.stringify(value); assert.ok(!encodings.some(s=>text.includes(s)),'secret_output'); }
async function localPolicy(enabled) {
  // Match linux_manage.write_policy's atomic inode replacement, never MCP resume.
  const temporary=join(fixture.root,'test-local-policy-'+process.pid);
  await writeFile(temporary,JSON.stringify({enabled,allow_all:true,items:[]}),{mode:0o600});
  await chmod(temporary,0o600);
  await rename(temporary,join(fixture.root,'access.json'));
}
async function audit() {return (await fetch(new URL('__audit',fixture.webUrl))).json();}
async function linuxProbe(request) {
  return new Promise((resolve,reject)=>{
    const child=spawn(fixture.python,[join(repo,'agent_tests/process_probe.py')],{stdio:['pipe','pipe','pipe']});
    let text='';child.stdout.on('data',x=>text+=x);child.stderr.on('data',()=>{});
    child.stdin.end(JSON.stringify(request));child.on('error',reject);
    child.on('close',code=>{try {if(code)throw new Error('probe_exit');resolve(JSON.parse(text));}catch(error){reject(error);}});
  });
}
async function start() {
  client=new Client({name:'isolated-agent-validation',version:'1'}, {capabilities:{elicitation:{form:{}}}});
  client.setRequestHandler(ElicitRequestSchema, async request=>{
    noSecrets(request); hostPrompts++;
    assert.equal(request.params.mode,'form');
    assert.deepEqual(request.params.requestedSchema,{type:'object',properties:{}});
    assert.match(request.params.message,/SHA256:[A-Za-z0-9+/]{43}/);
    assert.equal((await audit()).ssh_auth,(await audit()).ssh_executed);
    return {action:hostDecision,content:{}};
  });
  const args=process.platform==='win32'?[join(repo,'dist/server.js'),'--agent-safe','--agent-root',fixture.root]:[join(repo,'agent_tests/fixture_server.mjs'),fixture.root];
  transport=new StdioClientTransport({command:process.execPath,args,env:{...process.env},stderr:'pipe'});
  transport.stderr?.on('data',x=>{diagnostics+=x;});
  const originalStart=transport.start.bind(transport);
  transport.start=async()=>{await originalStart();transport._process?.stdout?.on('data',x=>{raw+=x;});};
  await client.connect(transport);
  if (!monitor) monitor=setInterval(()=>{
    const rootPid=process.platform==='linux'?process.pid:transport?._process?.pid;
    if(probeBusy||!rootPid)return;
    probeBusy=true;
    probePromise=new Promise(resolve=>{
      const command=process.platform==='win32'?'powershell.exe':fixture.python;
      const args=process.platform==='win32'?['-NoProfile','-File',join(repo,'agent_tests/process_probe.ps1')]:[join(repo,'agent_tests/process_probe.py')];
      const child=spawn(command,args,{stdio:['pipe','pipe','pipe'],windowsHide:true});
      let text=''; child.stdout.on('data',x=>text+=x); child.stderr.on('data',()=>{});
      child.stdin.end(JSON.stringify({root_pid:rootPid,markers:encodings}));
      child.on('close',()=>{try {const p=JSON.parse(text);probeFailed ||= p.secret_args||p.session_argument||p.unsafe_browser_argument===true;probeCount+=p.children_observed;for(const identity of p.identities??[])if(identity.pid!==process.pid)identities.set(identity.pid+':'+identity.start,identity);}catch{probeFailed=true;}probeBusy=false;resolve();});
      child.on('error',()=>{probeFailed=true;probeBusy=false;resolve();});
    });
  },1200);
}
async function call(name,args={}) {
  const response=await client.callTool({name,arguments:args},undefined,{timeout:120000});
  noSecrets(response);
  if(response.isError) {errors.add(name);return {protocolError:true};}
  const data=response.structuredContent;
  assert.deepEqual(JSON.parse(response.content[0].text),data);
  if(data.ok===false)errors.add(name);
  return data;
}
async function ok(name,args={}) { const value=await call(name,args); assert.equal(value.ok,true,name+':'+(value.error??''));successes.add(name); return value; }
try {
  await start();
  stage='tool-contract';
  const names=(await client.listTools()).tools.map(x=>x.name);
  const expected=['status','search','sync','browser_open','browser_state','browser_fill_login','browser_fill_totp','browser_action','mysql_query','ssh_exec','browser_close','pause_access'];
  assert.deepEqual(names.sort(),expected.sort());
  for(const name of names) assert.equal((await call(name,{[fixture.markers.hidden]:fixture.markers.password})).protocolError,true);
  result.checks.all_12_strict_schema_errors=true;
  await ok('status');
  const found=await ok('search'); assert.equal(found.count,4);
  assert.ok(found.items.every(x=>!('fields' in x)&&!('notes' in x)));
  const seeded=found.items.find(x=>x.id===fixture.itemId);
  assert.ok(seeded.name.includes('[REDACTED]'));
  assert.ok(seeded.username.includes('[REDACTED]'));
  await ok('sync');
  for(const name of ['keychain_get_password','keychain_get_item','keychain_get_totp','keychain_get_attachment','keychain_receive','keychain_send_get','credentials','resume_access']) assert.equal((await call(name)).protocolError,true);
  result.checks.contract_search_and_metadata_redaction=true;
  stage='ssh';
  const ssh=await ok('ssh_exec',{item_id:fixture.ids.ssh,command:'list-fixture-services'});
  assert.equal(ssh.exit_code,0); assert.ok(ssh.stdout.includes('synthetic service running'));
  assert.ok(ssh.stdout.includes('[REDACTED]')); assert.ok(ssh.stderr.includes('[REDACTED]'));
  const kh=join(fixture.root,'state/known_hosts'),saved=await readFile(kh);
  await writeFile(kh,'');
  try {
    assert.equal((await call('ssh_exec',{item_id:fixture.ids.ssh,command:'must-not-run'})).error,'ssh_confirmation_denied');
    assert.equal((await audit()).ssh_auth,1); assert.equal((await audit()).ssh_executed,1);
    hostDecision='accept';
    await ok('ssh_exec',{item_id:fixture.ids.ssh,command:'confirmed-fixture'});
    assert.equal(hostPrompts,2); assert.equal((await readFile(kh)).toString().trim(),saved.toString().trim());
    await client.close(); await start();
    await ok('ssh_exec',{item_id:fixture.ids.ssh,command:'confirmed-after-restart'});
    assert.equal(hostPrompts,2);
  }
  finally { await writeFile(kh,saved); }
  await writeFile(kh,await readFile(join(fixture.root,'changed_known_hosts')));
  try { assert.equal((await call('ssh_exec',{item_id:fixture.ids.ssh,command:'must-not-run-changed-key'})).ok,false); }
  finally { await writeFile(kh,saved); }
  assert.equal((await audit()).ssh_executed,3);
  assert.equal((await audit()).ssh_auth,3);
  result.checks.ssh_first_trust_decline_accept_restart_and_changed_rejection=true;
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
  for(const [name,args] of [
    ['browser_state',{page_id:'missing'}],
    ['browser_fill_login',{page_id:page.page_id,password_ref:'missing'}],
    ['browser_fill_totp',{page_id:page.page_id,ref:'missing'}],
    ['browser_action',{page_id:page.page_id,action:'click',ref:'missing'}],
  ])assert.equal((await call(name,args)).ok,false);
  await ok('browser_fill_login',{page_id:page.page_id,password_ref:refs.Password,username_ref:refs.Username});
  assert.equal((await audit()).submissions,0);
  await ok('browser_fill_totp',{page_id:page.page_id,ref:refs.OTP});
  assert.equal((await audit()).submissions,0);
  const state=await ok('browser_state',{page_id:page.page_id});
  assert.ok(state.controls.every(x=>!('value' in x)));
  const button=state.controls.find(x=>x.label==='Sign in');
  await ok('browser_action',{page_id:page.page_id,action:'click',ref:button.ref});
  assert.equal((await audit()).submissions,1);
  const signed=await ok('browser_state',{page_id:page.page_id});
  assert.equal(signed.title,'Signed in'); assert.ok(signed.text.includes('[REDACTED]'));
  assert.ok(!/\b\d{6,8}\b/.test(signed.text));
  await ok('browser_close');
  assert.equal((await call('browser_state',{page_id:page.page_id})).ok,false);
  result.checks.browser_password_totp_submit_separation_and_echo_filter=true;
  stage='pause-restart';
  const revokedPage=await ok('browser_open',{item_id:fixture.ids.web});
  await ok('pause_access'); assert.equal((await call('search')).error,'disabled');
  assert.equal((await call('browser_state',{page_id:revokedPage.page_id})).ok,false);
  await localPolicy(true);
  assert.equal((await ok('search')).count,4);
  assert.equal((await call('browser_state',{page_id:revokedPage.page_id})).ok,false);
  const localPage=await ok('browser_open',{item_id:fixture.ids.web});
  await localPolicy(false);
  // No MCP call triggers this revocation: the live policy monitor must do it.
  await new Promise(resolve=>setTimeout(resolve,600));
  await localPolicy(true);
  assert.equal((await call('browser_state',{page_id:localPage.page_id})).ok,false);
  assert.equal((await ok('search')).count,4);
  result.checks.same_process_local_pause_resume_revokes_prior_pages=true;
  await ok('pause_access');
  await client.close();
  await start(); assert.equal((await call('search')).error,'disabled');
  await client.close();
  await localPolicy(true);
  await start(); assert.equal((await ok('search')).count,4);
  await client.close();
  result.checks.pause_persists_and_restart_auto_unlock=true;
  stage='idle-revocation';
  const cfg=JSON.parse(await readFile(join(fixture.root,'config.json'),'utf8'));
  process.env.BW_BIN=fixture.bw; process.env.WARDEN_AGENT_SAFE_PROCESS='1';
  await configureBwCliContainment(cfg.python,join(repo,'agent_worker/worker.py'));
  idleVault=new AgentVault(fixture.root,cfg,300);
  let revocations=0;
  const revoke=idleVault.revoke.bind(idleVault);
  idleVault.revoke=async()=>{revocations++;await revoke();};
  const idleSearch=await idleVault.invoke('search',{});
  noSecrets(idleSearch);assert.equal(idleSearch.ok,true,'idle initial search:'+idleSearch.error);
  const idlePage=await idleVault.invoke('browser_open',{item_id:fixture.ids.web});
  noSecrets(idlePage);assert.equal(idlePage.ok,true,'idle browser_open:'+idlePage.error);
  await new Promise(resolve=>setTimeout(resolve,1200));
  assert.ok(revocations>=1);
  assert.equal((await idleVault.invoke('browser_state',{page_id:idlePage.page_id})).ok,false);
  const reunlock=await idleVault.invoke('search',{});
  noSecrets(reunlock);assert.equal(reunlock.ok,true,'idle reunlock:'+reunlock.error);
  await idleVault.revoke();idleVault=undefined;
  result.checks.idle_browser_revoke_and_reunlock=true;
  stage='filesystem-and-protocol-leaks';
  const files=await readdir(join(fixture.root,'state'),{recursive:true});
  assert.ok(!files.some(f=>f.includes('.warden-mcp-session.json')));
  for(const file of await readdir(join(fixture.root,'logs'))) noSecrets(await readFile(join(fixture.root,'logs',file),'utf8'));
  noSecrets(raw); noSecrets(diagnostics);
  clearInterval(monitor); monitor=undefined; await probePromise;
  assert.equal(probeFailed,false); assert.ok(probeCount>0);
  if(process.platform==='linux') {
    let alive=[];
    for(let i=0;i<50;i++) {alive=(await linuxProbe({identities:[...identities.values()]})).alive;if(!alive.length)break;await new Promise(resolve=>setTimeout(resolve,100));}
    assert.deepEqual(alive,[],'descendant_process_cleanup');
    result.checks.observed_process_tree_cleanup=true;
    let profiles=[];
    for(let i=0;i<50;i++) {
      profiles=await readdir(join(fixture.root,'state/browser')).catch(error=>{if(error.code==='ENOENT')return [];throw error;});
      if(!profiles.length)break;
      await new Promise(resolve=>setTimeout(resolve,100));
    }
    assert.deepEqual(profiles,[],'owned_browser_profiles_removed_after_teardown');
    result.checks.owned_browser_profiles_reclaimed=true;
  }
  result.checks.live_process_arguments_have_no_secrets_or_session_flags=true;
  if(process.platform==='linux')result.checks.no_sandbox_bypass_or_debug_port_arguments=true;
  noSecrets(await readFile(join(fixture.root,'config.json'),'utf8'));
  result.checks.no_plain_session_or_secret_logs=true;
  assert.deepEqual([...successes].sort(),expected);
  assert.ok(expected.every(name=>errors.has(name)));
  result.checks.all_12_tool_successes_and_errors=true;
  result.tool_successes=[...successes].sort();result.tool_errors=[...errors].sort();
  result.completed=true;
} catch(error) {
  result.failure_stage=stage;
  result.failure_kind=error?.name ?? 'Error';
  result.failure_location=String(error?.stack??'').match(/client\.mjs:\d+:\d+/)?.[0];
  // Only synthetic fixture errors reach this report; redact before returning.
  let message=String(error?.message ?? '').slice(0,400);
  for(const value of encodings) message=message.replaceAll(value,'[REDACTED]');
  result.message=message;
} finally { clearInterval(monitor); await probePromise; if(client) await client.close().catch(()=>{});if(idleVault)await idleVault.revoke().catch(()=>{}); }
process.stdout.write(JSON.stringify(result));
