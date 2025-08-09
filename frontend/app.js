const B = window.APP_CONFIG.BACKEND_BASE;
const CPX_APP_ID = window.APP_CONFIG.CPX_APP_ID;

const els = {
  authPanel: document.getElementById('auth-panel'),
  appPanel: document.getElementById('app-panel'),
  loginEmail: document.getElementById('login-email'),
  loginPass: document.getElementById('login-password'),
  remember: document.getElementById('remember-me'),
  loginBtn: document.getElementById('login-btn'),
  loginMsg: document.getElementById('login-msg'),
  gotoCreate: document.getElementById('goto-create'),
  gotoForgot: document.getElementById('goto-forgot'),
  createCard: document.getElementById('create-card'),
  createEmail: document.getElementById('create-email'),
  createPass: document.getElementById('create-password'),
  createBtn: document.getElementById('create-btn'),
  createMsg: document.getElementById('create-msg'),
  forgotCard: document.getElementById('forgot-card'),
  forgotEmail: document.getElementById('forgot-email'),
  forgotSend: document.getElementById('forgot-send'),
  verifyBlock: document.getElementById('verify-block'),
  forgotCode: document.getElementById('forgot-code'),
  forgotNewPass: document.getElementById('forgot-newpass'),
  forgotVerify: document.getElementById('forgot-verify'),
  forgotMsg: document.getElementById('forgot-msg'),
  back1: document.getElementById('back-to-login-1'),
  back2: document.getElementById('back-to-login-2'),
  userEmail: document.getElementById('user-email'),
  userBalance: document.getElementById('user-balance'),
  viewsToday: document.getElementById('views-today'),
  btnWatch: document.getElementById('btn-watch'),
  btnCPX: document.getElementById('btn-cpx'),
  btnAdGem: document.getElementById('btn-adgem'),
  btnLogout: document.getElementById('btn-logout'),
  btnAdmin: document.getElementById('btn-admin'),
  watchMsg: document.getElementById('watch-msg'),
  cpxMsg: document.getElementById('cpx-msg'),
  adgemMsg: document.getElementById('adgem-msg'),
};

function saveToken(t, remember) {
  if (remember) localStorage.setItem('token', t);
  else sessionStorage.setItem('token', t);
}
function getToken() {
  return localStorage.getItem('token') || sessionStorage.getItem('token');
}
function clearToken() {
  localStorage.removeItem('token'); sessionStorage.removeItem('token');
}
async function api(path, opts={}) {
  const token = getToken();
  const headers = Object.assign({'Content-Type':'application/json'}, opts.headers||{});
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const res = await fetch(`${B}${path}`, { ...opts, headers });
  const text = await res.text();
  let data;
  try { data = text ? JSON.parse(text) : {}; } catch { data = { error: text || 'Parse error' }; }
  if (!res.ok) throw new Error(data.error || data.message || res.statusText);
  return data;
}

function setView(auth) {
  els.authPanel.classList.toggle('hidden', !auth);
  els.appPanel.classList.toggle('hidden', auth);
}

async function initSession() {
  const token = getToken();
  if (!token) return setView(true);
  try {
    const me = await api('/api/user/me');
    els.userEmail.textContent = me.email;
    await refreshBalance();
    await refreshViews();
    setView(false);
  } catch {
    clearToken();
    setView(true);
  }
}

async function refreshBalance() {
  try {
    const b = await api('/api/user/balance');
    els.userBalance.textContent = Number(b.balance || 0).toFixed(2);
  } catch (e) { console.warn(e); }
}
async function refreshViews() {
  try {
    const v = await api('/api/ads/daily-count');
    els.viewsToday.textContent = v.count ?? 0;
  } catch (e) { console.warn(e); }
}

els.loginBtn.onclick = async () => {
  els.loginMsg.textContent = 'Logging in...';
  try {
    const body = { email: els.loginEmail.value.trim(), password: els.loginPass.value };
    const out = await api('/api/auth/login', { method:'POST', body: JSON.stringify(body) });
    saveToken(out.token, els.remember.checked);
    els.loginMsg.textContent = 'OK';
    await initSession();
  } catch (e) {
    els.loginMsg.textContent = e.message || 'Login failed';
  }
};

els.gotoCreate.onclick = () => {
  document.getElementById('login-card').classList.add('hidden');
  els.createCard.classList.remove('hidden');
};
els.gotoForgot.onclick = () => {
  document.getElementById('login-card').classList.add('hidden');
  els.forgotCard.classList.remove('hidden');
};
els.back1.onclick = els.back2.onclick = () => {
  els.createCard.classList.add('hidden');
  els.forgotCard.classList.add('hidden');
  document.getElementById('login-card').classList.remove('hidden');
};

els.createBtn.onclick = async () => {
  els.createMsg.textContent = 'Creating...';
  try {
    const body = { email: els.createEmail.value.trim(), password: els.createPass.value };
    const out = await api('/api/auth/register', { method:'POST', body: JSON.stringify(body) });
    saveToken(out.token, true);
    els.createMsg.textContent = 'Account created';
    await initSession();
  } catch (e) {
    els.createMsg.textContent = e.message || 'Failed to create';
  }
};

let forgotEmailCache = '';
els.forgotSend.onclick = async () => {
  els.forgotMsg.textContent = 'Sending code...';
  try {
    forgotEmailCache = els.forgotEmail.value.trim();
    await api('/api/auth/reset/request', { method:'POST', body: JSON.stringify({ email: forgotEmailCache }) });
    els.verifyBlock.classList.remove('hidden');
    els.forgotMsg.textContent = 'Code sent';
  } catch (e) {
    els.forgotMsg.textContent = e.message || 'Failed to send';
  }
};
els.forgotVerify.onclick = async () => {
  els.forgotMsg.textContent = 'Verifying...';
  try {
    const body = { email: forgotEmailCache, code: els.forgotCode.value.trim(), newPassword: els.forgotNewPass.value };
    await api('/api/auth/reset/verify', { method:'POST', body: JSON.stringify(body) });
    els.forgotMsg.textContent = 'Password reset';
  } catch (e) {
    els.forgotMsg.textContent = e.message || 'Reset failed';
  }
};

els.btnLogout.onclick = async () => {
  try { await api('/api/auth/logout', { method:'POST' }); } catch {}
  clearToken();
  setView(true);
};

els.btnWatch.onclick = async () => {
  els.watchMsg.textContent = 'Checking limit...';
  try {
    const v = await api('/api/ads/daily-count');
    if ((v.count ?? 0) >= 30) {
      els.watchMsg.textContent = 'Daily limit reached (30/30).';
      return;
    }
    // Simulated ad gate. In production, replace with actual ad SDK or VAST viewer.
    els.watchMsg.textContent = 'Playing ad...';
    await new Promise(r => setTimeout(r, 3500)); // 3.5s demo

    const res = await api('/api/ads/watch', { method:'POST' });
    els.watchMsg.textContent = res.message || 'Recorded';
    await refreshViews();
    await refreshBalance();
  } catch (e) {
    els.watchMsg.textContent = e.message || 'Failed to record view';
  }
};

els.btnCPX.onclick = async () => {
  els.cpxMsg.textContent = 'Opening CPX...';
  try {
    const me = await api('/api/user/me');
    const sig = await api(`/api/cpx/sign?ext_user_id=${encodeURIComponent(me.id || me.email)}`);
    const url = `https://offers.cpx-research.com/index.php?app_id=${encodeURIComponent(CPX_APP_ID)}&ext_user_id=${encodeURIComponent(me.id || me.email)}&secure_hash=${encodeURIComponent(sig.secure_hash)}`;
    window.location.href = url;
  } catch (e) {
    els.cpxMsg.textContent = e.message || 'CPX error';
  }
};

els.btnAdGem.onclick = async () => {
  els.adgemMsg.textContent = 'Opening AdGem...';
  try {
    const me = await api('/api/user/me');
    // If your backend issues a signed URL for AdGem, fetch it here instead:
    const ag = await api(`/api/adgem/url?ext_user_id=${encodeURIComponent(me.id || me.email)}`);
    window.location.href = ag.url;
  } catch (e) {
    els.adgemMsg.textContent = e.message || 'AdGem error';
  }
};

document.getElementById('btn-admin').onclick = () => { window.location.href = './admin.html'; };

initSession();
