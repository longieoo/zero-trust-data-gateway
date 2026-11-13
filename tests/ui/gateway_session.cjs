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

  let releaseCatalog;
  const catalog = setup(async url => {
    if (url === '/auth/login') return response({access_token:'fixture-token'});
    if (url === '/auth/logout') return response({revoked:true});
    return new Promise(resolve => {releaseCatalog=resolve;});
  });
  await catalog('login').handlers.submit({preventDefault(){}});
  const pendingCatalog = catalog('load-catalog').handlers.click();
  await catalog('logout').handlers.click();
  releaseCatalog(response({resources:[{id:'customers',classification:'confidential'}]}));
  await pendingCatalog;
  assert.equal(catalog('catalog').children.length,0,'late catalog must remain cleared after logout');

  let releaseAccess;
  const access = setup(async url => {
    if (url === '/auth/login') return response({access_token:'fixture-token',role:'admin'});
    if (url === '/auth/logout') return response({revoked:true});
    return new Promise(resolve => {releaseAccess=resolve;});
  });
  await access('login').handlers.submit({preventDefault(){}});
  const pendingAccess = access('refresh-access').handlers.click();
  await access('logout').handlers.click();
  releaseAccess(response({requests:[{requester:'analyst',purpose:'secret test purpose',status:'PENDING'}]}));
  await pendingAccess;
  assert.equal(access('access-list').children.length,0,'late access purposes must remain cleared after logout');

  let releaseChanged;
  const changed = setup(async url => {
    if (url === '/auth/login') return response({access_token:'fixture-token'});
    return new Promise(resolve => {releaseChanged=resolve;});
  });
  await changed('login').handlers.submit({preventDefault(){}});
  const pendingChanged = changed('read').handlers.click();
  changed('resource').value='financial';
  changed('resource').handlers.change();
  releaseChanged(response({data:[{id:1}],obligations:{columns:['id']},pagination:{next_cursor:'stale'}}));
  await pendingChanged;
  assert.equal(changed('data').children.length,0,'changing resource cancels the previous protected read');
  assert.equal(changed('next-page').disabled,true,'cancelled response cannot restore its cursor');

  const urls=[];
  const pages=setup(async url => {
    if (url === '/auth/login') return response({access_token:'fixture-token'});
    urls.push(url);
    return response({data:[{id:urls.length}],obligations:{columns:['id']},
      pagination:{next_cursor:urls.length===1?'opaque+/cursor':null}});
  });
  pages('resource').value='customers'; pages('page-size').value='25';
  await pages('login').handlers.submit({preventDefault(){}});
  await pages('read').handlers.click();
  assert.equal(pages('next-page').disabled,false);
  await pages('next-page').handlers.click();
  assert.equal(urls[1],'/api/v1/data/customers?page_size=25&cursor=opaque%2B%2Fcursor');
  assert(pages('page-info').textContent.includes('Trang 2'));
  assert.equal(pages('next-page').disabled,true,'last page disables continuation');
  pages('page-size').value='50'; pages('page-size').handlers.change();
  await pages('next-page').handlers.click();
  assert.equal(urls.length,2,'reset cursor cannot send a stale continuation');
  assert.equal(pages('data').children.length,0);

  const payloads=[];
  const unsafePurpose='<img src=x onerror=alert(1)> review';
  const workflow=setup(async (url, options) => {
    if (url === '/auth/login') return response({access_token:'fixture-token',role:'admin',tenant_id:'demo'});
    if (options?.method === 'POST') {
      payloads.push({url,body:options.body&&JSON.parse(options.body)});
      return response({request_id:'request-1',status:options.body?'PENDING':'APPROVED'});
    }
    return response({tenant_id:'demo',requests:[{request_id:'request-1',requester:'analyst',resource:'production',purpose:unsafePurpose,status:'PENDING'}]});
  });
  workflow('username').value='data_owner';
  await workflow('login').handlers.submit({preventDefault(){}});
  workflow('access-resource').value='production';workflow('purpose').value=unsafePurpose;workflow('duration').value='900';
  await workflow('access-form').handlers.submit({preventDefault(){}});
  assert.deepEqual(payloads[0].body,{resource:'production',purpose:unsafePurpose,duration_seconds:900},'identity and tenant never come from the browser form');
  const requestRow=workflow('access-list').children[0].children[1];
  assert.equal(requestRow.children[2].textContent,unsafePurpose,'untrusted purpose is rendered as literal text');
  assert.equal(requestRow.children[5].children[0].textContent,'Phê duyệt');
  await requestRow.children[5].children[0].handlers.click();
  assert.equal(payloads[1].url,'/api/v1/access-requests/request-1/approve');

  const self=setup(async url => url==='/auth/login'
    ? response({access_token:'fixture-token',role:'admin'})
    : response({tenant_id:'demo',requests:[{request_id:'own',requester:'data_owner',resource:'production',purpose:'Own reviewed request',status:'PENDING'}]}));
  self('username').value='data_owner';
  await self('login').handlers.submit({preventDefault(){}});
  await self('refresh-access').handlers.click();
  const buttons=self('access-list').children[0].children[1].children[5].children;
  assert.deepEqual(buttons.map(button=>button.textContent),['Thu hồi'],'own pending request offers no self-approval action');
  console.log('10/10 UI security and governance checks passed');
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
