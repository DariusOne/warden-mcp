import test from 'node:test';
import assert from 'node:assert/strict';
import {fixtureEnvironment} from './fixture_server.mjs';
test('fixture server isolates session credentials and rejects non-fixture roots',()=>{
  assert.throws(()=>fixtureEnvironment('/production',{}));
  const env=fixtureEnvironment('/tmp/fixtures-abc',{BW_SESSION:'secret',BITWARDENCLI_APPDATA_DIR:'/daily',NODE_OPTIONS:'bad',KEYCHAIN_DEBUG_HTTP:'true',PATH:'/bin'});
  assert.equal(env.BW_SESSION,undefined);
  assert.equal(env.BITWARDENCLI_APPDATA_DIR,undefined);
  assert.equal(env.NODE_OPTIONS,undefined);
  assert.equal(env.KEYCHAIN_DEBUG_HTTP,undefined);
  assert.equal(env.PATH,'/bin');
});
