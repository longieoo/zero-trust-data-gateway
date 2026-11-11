// Exercise delayed network responses across logout using the real UI script.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

const source = fs.readFileSync(path.join(__dirname, '../../ui/gateway/gateway.js'), 'utf8');
function setup(fetch) {
  const elements = new Map();
  function element() {
    return {value:'', textContent:'', children:[], handlers:{},
      addEventListener(name, handler) { this.handlers[name] = handler; },
      replaceChildren() { this.children = []; }, append(child) { this.children.push(child); }};
  }
  const document = {getElementById(id) {
    if (!elements.has(id)) elements.set(id, element());
    return elements.get(id);
  }, createElement: element};
  vm.runInNewContext(source, {document, fetch});
  return id => document.getElementById(id);
}
const response = (data) => ({ok:true, status:200, json:async () => data});
async function main() {
  let releaseRead;
  const get = setup(async url => {
    if (url === '/auth/login') return response({access_token:'fixture-token'});
    if (url === '/auth/logout') return response({revoked:true});
    return await new Promise(resolve => { releaseRead = resolve; });
  });
  await get('login').handlers.submit({preventDefault(){}});
  const pending = get('read').handlers.click();
  await get('logout').handlers.click();
  releaseRead(response({data:[{id:1}], obligations:{columns:['id']}}));
  await pending;
  assert.equal(get('data').children.length, 0, 'late protected data must not reappear after logout');
  assert.equal(get('evidence').textContent, '', 'late evidence must not reappear');

  let releaseLogin, reads = 0;
  const next = setup(async url => {
    if (url === '/auth/login') return await new Promise(resolve => { releaseLogin = resolve; });
    reads++;
    return response({});
  });
  const signingIn = next('login').handlers.submit({preventDefault(){}});
  await next('logout').handlers.click();
  releaseLogin(response({access_token:'fixture-token'}));
  await signingIn;
  await next('read').handlers.click();
  assert.equal(reads, 0, 'late login must not restore authentication after logout');
  assert.equal(next('status').textContent, 'Bạn cần đăng nhập trước');
  const pendingReads = [];
  const latest = setup(async url => {
    if (url === '/auth/login') return response({access_token:'fixture-token'});
    return new Promise(resolve => pendingReads.push(resolve));
  });
  await latest('login').handlers.submit({preventDefault(){}});
  const olderRead = latest('read').handlers.click();
  const newerRead = latest('read').handlers.click();
  pendingReads[1](response({data:[{id:2}],obligations:{columns:['id']},reason_code:'NEWER'}));
  await newerRead;
  pendingReads[0](response({data:[{id:1}],obligations:{columns:['id']},reason_code:'OLDER'}));
  await olderRead;
  assert(latest('evidence').textContent.includes('NEWER'), 'older reads must not replace the latest decision');

  let releaseAudit;
  const timeline = setup(async url => {
    if (url === '/auth/login') return response({access_token:'fixture-token'});
    if (url === '/auth/logout') return response({revoked:true});
    return new Promise(resolve => {releaseAudit=resolve;});
  });
  await timeline('login').handlers.submit({preventDefault(){}});
  const pendingAudit = timeline('refresh-audit').handlers.click();
  await timeline('logout').handlers.click();
  releaseAudit(response({events:[{request_id:'old',route:'/api/v1/data/{resource}'}]}));
  await pendingAudit;
  assert.equal(timeline('audit-list').children.length,0,'late history must not return after logout');
  console.log('4/4 delayed-response UI security checks passed');
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
