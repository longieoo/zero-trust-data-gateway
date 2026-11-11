let token = null;
let sessionGeneration = 0;
let readGeneration = 0;
function clearInsights() {
  for (const id of ["audit-list", "replay-result", "policy-info", "impact-result"]) byId(id).replaceChildren();
}
const byId = id => document.getElementById(id);
byId('login').addEventListener('submit', async event => {
  event.preventDefault();
  const generation = ++sessionGeneration;
  token = null; clearInsights(); ++readGeneration; byId('data').replaceChildren(); byId('evidence').textContent = '';
  try {
    const response = await fetch('/auth/login', {method:'POST', headers:{'Content-Type':'application/json'},
      body:JSON.stringify({username:byId('username').value,password:byId('password').value})});
    const result = await response.json();
    if (generation !== sessionGeneration) return;
    token = response.ok ? result.access_token : null;
    byId('session').textContent = response.ok ? `Đã đăng nhập: ${byId('username').value} · Tenant ${result.tenant_id || "—"} · Phiên 10 phút` : 'Đăng nhập thất bại';
  } catch { if (generation === sessionGeneration) { token = null; byId('session').textContent = 'Không thể kết nối máy chủ'; } }
  byId('password').value = '';
});
byId('logout').addEventListener('click', async () => {
  const generation = ++sessionGeneration;
  const previous = token; token = null; clearInsights(); ++readGeneration;
  byId('data').replaceChildren(); byId('evidence').textContent = '';
  try {
    const response = previous && await fetch('/auth/logout',{method:'POST',headers:{Authorization:`Bearer ${previous}`}});
    if (generation !== sessionGeneration) return;
    byId('session').textContent = !previous || response.ok ? 'Đã đăng xuất và thu hồi phiên' : 'Đã xóa phiên trên trang; máy chủ chưa xác nhận thu hồi';
  } catch { if (generation === sessionGeneration) byId('session').textContent = 'Đã xóa phiên trên trang; máy chủ chưa xác nhận thu hồi'; }
});
byId('read').addEventListener('click', async () => {
  byId('data').replaceChildren();
  if (!token) { byId('status').textContent = 'Bạn cần đăng nhập trước'; return; }
  const generation = sessionGeneration;
  const readId = ++readGeneration;
  byId('status').textContent = 'Đang kiểm tra quyền truy cập…';
  try {
    const response = await fetch(`/api/v1/data/${byId('resource').value}`,{headers:{Authorization:`Bearer ${token}`}});
    const result = await response.json();
    if (generation !== sessionGeneration || readId !== readGeneration) return;
    byId('status').textContent = response.ok ? `ĐƯỢC PHÉP · ${result.data.length} bản ghi` : `TỪ CHỐI · ${result.reason_code || result.detail || response.status}`;
    byId('status').className = response.ok ? 'allow' : 'deny';
    byId('evidence').textContent = JSON.stringify({...result,data:undefined},null,2);
    if (response.status === 401) token = null;
    if (response.ok && result.data.length) {
      const table = document.createElement('table');
      const columns = result.obligations.columns;
      const heading = document.createElement('tr');
      for (const column of columns) { const cell = document.createElement('th'); cell.textContent = column; heading.append(cell); }
      table.append(heading);
      for (const row of result.data) { const tr = document.createElement('tr');
        for (const column of columns) { const td = document.createElement('td'); td.textContent = row[column] ?? ''; tr.append(td); } table.append(tr); }
      byId('data').append(table);
    }
  } catch { if (generation === sessionGeneration && readId === readGeneration) byId('status').textContent = 'Không thể xác minh quyền; không trả dữ liệu'; }
});

async function authorizedAction(destination, operation) {
  if (!token) { byId(destination).textContent = 'Bạn cần đăng nhập trước'; return; }
  const generation = sessionGeneration;
  const auth = token;
  byId(destination).textContent = 'Đang xử lý…';
  try {
    const result = await operation(auth);
    if (generation !== sessionGeneration) return;
    byId(destination).textContent = JSON.stringify(result, null, 2);
    return result;
  } catch {
    if (generation === sessionGeneration) byId(destination).textContent = 'Không thể hoàn tất yêu cầu; không có kết quả được xác nhận.';
  }
}
byId('policy-status').addEventListener('click', () => authorizedAction('policy-info', async auth => {
  const response = await fetch('/api/v1/policy', {headers:{Authorization:`Bearer ${auth}`}});
  return response.json();
}));
byId('refresh-audit').addEventListener('click', async () => {
  const generation = sessionGeneration;
  const result = await authorizedAction('replay-result', async auth => {
    const response = await fetch('/api/v1/audit?limit=20', {headers:{Authorization:`Bearer ${auth}`}});
    return response.json();
  });
  if (generation !== sessionGeneration || !result || !result.events) return;
  byId('audit-list').replaceChildren();
  const table = document.createElement('table');
  const heading = document.createElement('tr');
  for (const name of ['Thời điểm', 'Quyết định', 'HTTP', 'Request ID', 'Tái lập']) {
    const th = document.createElement('th'); th.textContent = name; heading.append(th);
  }
  table.append(heading);
  for (const event of result.events) {
    const row = document.createElement('tr');
    for (const value of [event.recorded_at, event.decision, event.http_status, event.request_id]) {
      const cell = document.createElement('td'); cell.textContent = value; row.append(cell);
    }
    const cell = document.createElement('td');
    if (event.route === '/api/v1/data/{resource}') {
      const button = document.createElement('button'); button.textContent = 'Replay';
      button.addEventListener('click', () => authorizedAction('replay-result', async auth => {
        const response = await fetch(`/api/v1/audit/${encodeURIComponent(event.request_id)}/replay`,
          {method:'POST',headers:{Authorization:`Bearer ${auth}`}});
        return response.json();
      })); cell.append(button);
    } else cell.textContent = '—';
    row.append(cell); table.append(row);
  }
  byId('audit-list').append(table);
  byId('replay-result').textContent = `${result.events.length} sự kiện · Tenant ${result.tenant_id}. Chọn Replay để tái lập.`;
});
byId('impact').addEventListener('click', () => authorizedAction('impact-result', async auth => {
  const revision = byId('candidate').value.trim();
  if (!/^[0-9a-f]{64}$/.test(revision)) return {error:'Revision phải là SHA-256 gồm 64 ký tự hex.'};
  const response = await fetch('/api/v1/policies/impact', {method:'POST',
    headers:{Authorization:`Bearer ${auth}`,'Content-Type':'application/json'}, body:JSON.stringify({revision,limit:20})});
  return response.json();
}));
