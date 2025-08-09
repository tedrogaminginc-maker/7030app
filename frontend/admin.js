const B = window.APP_CONFIG.BACKEND_BASE;

const el = {
  email: document.getElementById('admin-email'),
  pass: document.getElementById('admin-password'),
  login: document.getElementById('admin-login'),
  msg: document.getElementById('admin-msg'),
  content: document.getElementById('admin-content'),
  statUsers: document.getElementById('stat-users'),
  statPaid: document.getElementById('stat-paid'),
  statViewsToday: document.getElementById('stat-views-today'),
  lookupEmail: document.getElementById('lookup-email'),
  lookupBtn: document.getElementById('lookup-btn'),
  lookupJson: document.getElementById('lookup-json'),
};

let adminToken = '';

async function api(path, opts={}) {
  const headers = Object.assign({'Content-Type':'application/json'}, opts.headers||{});
  if (adminToken) headers['Authorization'] = `Bearer ${adminToken}`;
  const res = await fetch(`${B}${path}`, { ...opts, headers });
  const text = await res.text();
  let data;
  try { data = text ? JSON.parse(text) : {}; } catch { data = { error: text || 'Parse error' }; }
  if (!res.ok) throw new Error(data.error || data.message || res.statusText);
  return data;
}

el.login.onclick = async () => {
  el.msg.textContent = 'Signing in...';
  try {
    const out = await api('/api/admin/login', { method:'POST', body: JSON.stringify({ email: el.email.value.trim(), password: el.pass.value }) });
    adminToken = out.token;
    el.msg.textContent = 'OK';
    el.content.classList.remove('hidden');

    const met = await api('/api/admin/metrics');
    el.statUsers.textContent = met.users ?? 0;
    el.statPaid.textContent = Number(met.totalPaid ?? 0).toFixed(2);
    el.statViewsToday.textContent = met.viewsToday ?? 0;
  } catch (e) {
    el.msg.textContent = e.message || 'Admin login failed';
  }
};

el.lookupBtn.onclick = async () => {
  el.lookupJson.textContent = 'Loading...';
  try {
    const u = await api(`/api/admin/user?email=${encodeURIComponent(el.lookupEmail.value.trim())}`);
    el.lookupJson.textContent = JSON.stringify(u, null, 2);
  } catch (e) {
    el.lookupJson.textContent = e.message || 'Lookup failed';
  }
};
