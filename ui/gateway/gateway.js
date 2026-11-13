let token = null;
let sessionGeneration = 0;
let readGeneration = 0;
let nextCursor = null;
let pageNumber = 0;
let currentRole = null;
let currentUser = null;
let actionGenerations = {};
const byId = id => document.getElementById(id);
function resetPage() {
  nextCursor = null; pageNumber = 0;
  byId('next-page').disabled = true;
  byId('page-info').textContent = 'Chưa đọc dữ liệu';
}
function clearInsights() {
  for (const id of ['audit-list','replay-result','policy-info','impact-result','access-list','access-result','catalog']) byId(id).replaceChildren();
  byId('purpose').value = '';
  resetPage();
}
function tableFor(rows, columns) {
  const table = document.createElement('table');
  const heading = document.createElement('tr');
  for (const column of columns) { const th = document.createElement('th'); th.textContent = column; heading.append(th); }
  table.append(heading);
  for (const values of rows) {
    const row = document.createElement('tr');
    for (const value of values) { const td = document.createElement('td'); td.textContent = value ?? '—'; row.append(td); }
    table.append(row);
  }
  return table;
}
byId('login').addEventListener('submit', async event => {
  event.preventDefault();
  const generation = ++sessionGeneration;
  const username = byId('username').value;
  token = null; currentRole = null; currentUser = null; clearInsights(); ++readGeneration;
  byId('data').replaceChildren(); byId('evidence').textContent = '';
  byId('status').className = ''; byId('status').textContent = 'Đang xác thực danh tính…';
  try {
    const response = await fetch('/auth/login', {method:'POST', headers:{'Content-Type':'application/json'},
      body:JSON.stringify({username,password:byId('password').value})});
    const result = await response.json();
    if (generation !== sessionGeneration) return;
    token = response.ok ? result.access_token : null;
    currentRole = response.ok ? result.role : null; currentUser = response.ok ? username : null;
    byId('session').textContent = response.ok ? `Đã đăng nhập: ${username} · Tenant ${result.tenant_id || '—'} · Phiên 10 phút` : 'Đăng nhập thất bại';
    byId('status').textContent = response.ok ? 'Chọn nguồn dữ liệu và bấm Đọc dữ liệu.' : 'Bạn cần đăng nhập trước';
  } catch { if (generation === sessionGeneration) { token = null; byId('session').textContent = 'Không thể kết nối máy chủ'; } }
  byId('password').value = '';
});
byId('logout').addEventListener('click', async () => {
  const generation = ++sessionGeneration;
  const previous = token; token = null; currentRole = null; currentUser = null;
  clearInsights(); ++readGeneration;
  byId('data').replaceChildren(); byId('evidence').textContent = '';
  byId('status').className = ''; byId('status').textContent = 'Phiên trên trang đã được xóa.';
  try {
    const response = previous && await fetch('/auth/logout',{method:'POST',headers:{Authorization:`Bearer ${previous}`}});
    if (generation !== sessionGeneration) return;
    byId('session').textContent = !previous || response.ok ? 'Đã đăng xuất và thu hồi phiên' : 'Đã xóa phiên trên trang; máy chủ chưa xác nhận thu hồi';
  } catch { if (generation === sessionGeneration) byId('session').textContent = 'Đã xóa phiên trên trang; máy chủ chưa xác nhận thu hồi'; }
});
async function readData(reset) {
  byId('data').replaceChildren(); byId('evidence').textContent = '';
  if (!token) { byId('status').textContent = 'Bạn cần đăng nhập trước'; return; }
  if (!reset && !nextCursor) return;
  const generation = sessionGeneration;
  const readId = ++readGeneration;
  const cursor = reset ? null : nextCursor;
  const size = byId('page-size').value || '25';
  const resource = byId('resource').value;
  byId('next-page').disabled = true;
  byId('status').className = '';
  byId('status').textContent = 'Đang kiểm tra quyền truy cập…';
  try {
    const query = `?page_size=${encodeURIComponent(size)}` + (cursor ? `&cursor=${encodeURIComponent(cursor)}` : '');
    const response = await fetch(`/api/v1/data/${resource}${query}`,{headers:{Authorization:`Bearer ${token}`}});
    const result = await response.json();
    if (generation !== sessionGeneration || readId !== readGeneration) return;
    byId('status').textContent = response.ok ? `ĐƯỢC PHÉP · ${result.data.length} bản ghi` : `TỪ CHỐI · ${result.reason_code || result.detail || response.status}`;
    byId('status').className = response.ok ? 'allow' : 'deny';
    byId('evidence').textContent = JSON.stringify({...result,data:undefined},null,2);
    if (response.status === 401) token = null;
    if (response.ok) {
      pageNumber = reset ? 1 : pageNumber + 1;
      nextCursor = result.pagination?.next_cursor || null;
      byId('next-page').disabled = !nextCursor;
      byId('page-info').textContent = `Trang ${pageNumber} · ${result.data.length} dòng` + (nextCursor ? ' · Còn dữ liệu' : ' · Hết dữ liệu');
      if (result.data.length) byId('data').append(tableFor(result.data.map(row => result.obligations.columns.map(column => row[column])), result.obligations.columns));
    } else resetPage();
  } catch { if (generation === sessionGeneration && readId === readGeneration) { resetPage(); byId('status').textContent = 'Không thể xác minh quyền; không trả dữ liệu'; } }
}
byId('read').addEventListener('click', () => readData(true));
byId('next-page').addEventListener('click', () => readData(false));
for (const id of ['resource','page-size']) byId(id).addEventListener('change', () => {
  ++readGeneration; resetPage(); byId('data').replaceChildren(); byId('evidence').textContent = '';
  byId('status').className = '';
  byId('status').textContent = 'Đã đổi lựa chọn; bấm Đọc dữ liệu để bắt đầu lại.';
});
async function authorizedAction(destination, operation) {
  if (!token) { byId(destination).textContent = 'Bạn cần đăng nhập trước'; return; }
  const generation = sessionGeneration;
  const sequence = (actionGenerations[destination] || 0) + 1;
  actionGenerations[destination] = sequence;
  const auth = token;
  byId(destination).textContent = 'Đang xử lý…';
  try {
    const result = await operation(auth);
    if (generation !== sessionGeneration || actionGenerations[destination] !== sequence) return;
    byId(destination).textContent = JSON.stringify(result, null, 2);
    return result;
  } catch {
    if (generation === sessionGeneration && actionGenerations[destination] === sequence) byId(destination).textContent = 'Không thể hoàn tất yêu cầu; không có kết quả được xác nhận.';
  }
}
byId('policy-status').addEventListener('click', () => authorizedAction('policy-info', async auth => {
  const response = await fetch('/api/v1/policy', {headers:{Authorization:`Bearer ${auth}`}});
  return response.json();
}));
byId('load-catalog').addEventListener('click', async () => {
  const generation = sessionGeneration;
  const result = await authorizedAction('catalog', async auth => {
    const response = await fetch('/api/v1/catalog', {headers:{Authorization:`Bearer ${auth}`}});
    return response.json();
  });
  if (generation !== sessionGeneration || !result?.resources) return;
  byId('catalog').replaceChildren();
  byId('catalog').append(tableFor(result.resources.map(r => [r.id,r.department,r.sensitivity, (r.pii_columns || []).join(', '),r.grant_required ? 'Cần phê duyệt thêm' : 'Theo ABAC']), ['Dữ liệu','Phòng ban','Độ nhạy','PII','Điều kiện']));
});
byId('refresh-audit').addEventListener('click', async () => {
  const generation = sessionGeneration;
  const result = await authorizedAction('replay-result', async auth => {
    const response = await fetch('/api/v1/audit?limit=20', {headers:{Authorization:`Bearer ${auth}`}});
    return response.json();
  });
  if (generation !== sessionGeneration || !result?.events) return;
  byId('audit-list').replaceChildren();
  const table = document.createElement('table');
  const heading = document.createElement('tr');
  for (const name of ['Thời điểm','Quyết định','HTTP','Request ID','Tái lập']) { const th=document.createElement('th'); th.textContent=name; heading.append(th); }
  table.append(heading);
  for (const event of result.events) {
    const row = document.createElement('tr');
    for (const value of [event.recorded_at,event.decision,event.http_status,event.request_id]) { const cell=document.createElement('td'); cell.textContent=value; row.append(cell); }
    const cell=document.createElement('td');
    if (event.route === '/api/v1/data/{resource}') {
      const button=document.createElement('button'); button.textContent='Replay';
      button.addEventListener('click', () => authorizedAction('replay-result', async auth => {
        const response=await fetch(`/api/v1/audit/${encodeURIComponent(event.request_id)}/replay`,{method:'POST',headers:{Authorization:`Bearer ${auth}`}});
        return response.json();
      })); cell.append(button);
    } else cell.textContent='—';
    row.append(cell); table.append(row);
  }
  byId('audit-list').append(table);
  byId('replay-result').textContent=`${result.events.length} sự kiện · Tenant ${result.tenant_id}. Chọn Replay để tái lập.`;
});
byId('impact').addEventListener('click', () => authorizedAction('impact-result', async auth => {
  const revision=byId('candidate').value.trim();
  if (!/^[0-9a-f]{64}$/.test(revision)) return {error:'Revision phải là SHA-256 gồm 64 ký tự hex.'};
  const response=await fetch('/api/v1/policies/impact',{method:'POST',headers:{Authorization:`Bearer ${auth}`,'Content-Type':'application/json'},body:JSON.stringify({revision,limit:20})});
  return response.json();
}));
async function refreshAccess() {
  const generation=sessionGeneration;
  const result=await authorizedAction('access-result', async auth => {
    const response=await fetch('/api/v1/access-requests?limit=50',{headers:{Authorization:`Bearer ${auth}`}});
    return response.json();
  });
  if (generation !== sessionGeneration || !result?.requests) return;
  byId('access-list').replaceChildren();
  const table=document.createElement('table'); const heading=document.createElement('tr');
  for (const title of ['Người yêu cầu','Dữ liệu','Mục đích','Trạng thái','Hết hạn','Thao tác']) { const th=document.createElement('th'); th.textContent=title; heading.append(th); }
  table.append(heading);
  for (const item of result.requests) {
    const row=document.createElement('tr');
    for (const value of [item.requester,item.resource,item.purpose,item.status,item.expires_at]) { const td=document.createElement('td'); td.textContent=value || '—'; row.append(td); }
    const cell=document.createElement('td');
    if (currentRole === 'admin' && ['PENDING','APPROVED'].includes(item.status)) {
      const operations=item.status === 'PENDING' && item.requester !== currentUser ? ['approve','revoke'] : ['revoke'];
      for (const operation of operations) {
        const button=document.createElement('button'); button.textContent=operation === 'approve' ? 'Phê duyệt' : 'Thu hồi';
        button.addEventListener('click', async () => {
          const current=sessionGeneration;
          const answer=await authorizedAction('access-result', async auth => {
            const response=await fetch(`/api/v1/access-requests/${encodeURIComponent(item.request_id)}/${operation}`,{method:'POST',headers:{Authorization:`Bearer ${auth}`}});
            return response.json();
          });
          if (current === sessionGeneration && answer?.status) await refreshAccess();
        }); cell.append(button);
      }
    } else cell.textContent='—';
    row.append(cell); table.append(row);
  }
  byId('access-list').append(table);
  byId('access-result').textContent=`${result.requests.length} yêu cầu · Tenant ${result.tenant_id}. Phê duyệt vẫn phải đáp ứng chính sách truy cập.`;
}
byId('refresh-access').addEventListener('click', refreshAccess);
byId('access-form').addEventListener('submit', async event => {
  event.preventDefault();
  const generation=sessionGeneration;
  const result=await authorizedAction('access-result', async auth => {
    const response=await fetch('/api/v1/access-requests',{method:'POST',headers:{Authorization:`Bearer ${auth}`,'Content-Type':'application/json'},body:JSON.stringify({resource:byId('access-resource').value,purpose:byId('purpose').value,duration_seconds:Number(byId('duration').value || 900)})});
    return response.json();
  });
  if (generation === sessionGeneration && result?.request_id) { byId('purpose').value=''; await refreshAccess(); }
});
