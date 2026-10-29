// Test-only bootstrap: actual AgentVault/tool registration, private synthetic socket.
// Deliberately NOT validation of production root-owned config/credential provisioning.
import {basename,join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {readFile,mkdir} from 'node:fs/promises';
import {McpServer} from '@modelcontextprotocol/sdk/server/mcp.js';
import {StdioServerTransport} from '@modelcontextprotocol/sdk/server/stdio.js';
import {AgentVault} from '../dist/agent-safe/vault.js';
import {registerAgentTools} from '../dist/agent-safe/server.js';
import {configureBwCliContainment} from '../dist/bw/bwCli.js';

export function fixtureEnvironment(root,environment) {
  if(!basename(root).startsWith('fixtures-')) throw new Error('fixture_root');
  return Object.fromEntries(Object.entries(environment).filter(([key])=>! /^(BW_|BITWARDEN|KEYCHAIN_|NODE_OPTIONS$)/i.test(key)));
}
async function main() {
  const root=resolve(process.argv[2]);
  const env=fixtureEnvironment(root,process.env);
  for(const key of Object.keys(process.env)) delete process.env[key];
  Object.assign(process.env,env);
  const cfg=JSON.parse(await readFile(join(root,'config.json'),'utf8'));
  process.env.WARDEN_AGENT_SAFE_PROCESS='1';process.env.BW_BIN=cfg.bw;
  await configureBwCliContainment(cfg.python,fileURLToPath(new URL('../agent_worker/worker.py',import.meta.url)));
  await mkdir(join(root,'state/cli'),{recursive:true,mode:0o700});
  const vault=new AgentVault(root,cfg);
  const server=new McpServer({name:'synthetic-linux-fixture',version:'1'});
  registerAgentTools(server,vault);
  const transport=new StdioServerTransport();
  const closed=new Promise(resolve=>{transport.onclose=resolve;});
  await server.connect(transport);
  try {await closed;} finally {await vault.revoke();}
}
if(process.argv[1] && resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  main().catch(()=>{process.stderr.write('fixture_bootstrap_failed\n');process.exitCode=1;});
}
