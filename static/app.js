/**
 * app.js - SSH 连接器 Web 管理界面
 * 单文件原生 JS, 无需构建步骤。
 * 通过同源请求连接本地 axum daemon。
 */

// ── State ──────────────────────────────────────────────────────
const state = {
  vaultInitialized: false,
  vaultUnlocked: false,
  currentView: 'hosts',
  hosts: [],
  sessions: [],
  sessionsPollerHandle: null,
  termSocket: null,
  termInstance: null,
  termFitAddon: null,
  activeTermSessionId: null,
  inflightButtons: new Set(),
};

// ── DOM refs ────────────────────────────────────────────────────
const $ = (id) => document.getElementById(id);
const el = {
  lockScreen:       () => $('lock-screen'),
  app:              () => $('app'),
  lockForm:         () => $('lock-form'),
  lockSubmit:       () => $('lock-submit'),
  lockError:        () => $('lock-error'),
  lockSubtitle:     () => $('lock-subtitle'),
  mpInput:          () => $('mp-input'),
  mpConfirmWrap:    () => $('mp-confirm-wrap'),
  mpConfirm:        () => $('mp-confirm'),
  lockBtn:          () => $('lock-btn'),
  navItems:         () => document.querySelectorAll('.nav-item'),
  toastRegion:      () => $('toast-region'),
  // Hosts
  hostsStatus:      () => $('hosts-status'),
  hostsLoading:     () => $('hosts-loading'),
  hostsEmpty:       () => $('hosts-empty'),
  hostsTableWrap:   () => $('hosts-table-wrap'),
  hostsBody:        () => $('hosts-body'),
  addHostBtn:       () => $('add-host-btn'),
  // Sessions
  sessionsStatus:   () => $('sessions-status'),
  sessionsLoading:  () => $('sessions-loading'),
  sessionsEmpty:    () => $('sessions-empty'),
  sessionsTableWrap:() => $('sessions-table-wrap'),
  sessionsBody:     () => $('sessions-body'),
  sessionsRefresh:  () => $('sessions-refresh'),
  termPanel:        () => $('terminal-panel'),
  termLabel:        () => $('terminal-label'),
  termClose:        () => $('terminal-close'),
  xtermContainer:   () => $('xterm-container'),
  // Audit
  auditStatus:      () => $('audit-status'),
  auditLoading:     () => $('audit-loading'),
  auditEmpty:       () => $('audit-empty'),
  auditList:        () => $('audit-list'),
  auditRefresh:     () => $('audit-refresh'),
  // Host modal
  hostModal:        () => $('host-modal'),
  hostModalTitle:   () => $('host-modal-title'),
  hostModalClose:   () => $('host-modal-close'),
  hostModalCancel:  () => $('host-modal-cancel'),
  hostForm:         () => $('host-form'),
  hostFormSubmit:   () => $('host-form-submit'),
  hostFormError:    () => $('host-form-error'),
  hostIdField:      () => $('host-id-field'),
  hfAlias:          () => $('hf-alias'),
  hfHost:           () => $('hf-host'),
  hfPort:           () => $('hf-port'),
  hfUser:           () => $('hf-user'),
  hfNotes:          () => $('hf-notes'),
  hfPassword:       () => $('hf-password'),
  hfKeyPem:         () => $('hf-key-pem'),
  hfKeyPassphrase:  () => $('hf-key-passphrase'),
  hfKiAnswers:      () => $('hf-ki-answers'),
  hfBecomeRootEnabled: () => $('hf-become-root-enabled'),
  hfBecomeRootFields:  () => $('become-root-fields'),
  hfBecomeRootCommand: () => $('hf-become-root-command'),
  hfBecomeRootPassword:() => $('hf-become-root-password'),
  hfBecomeRootTimeout: () => $('hf-become-root-timeout'),
  authPasswordFields: () => $('auth-password-fields'),
  authKeyFields:    () => $('auth-key-fields'),
  authKiFields:     () => $('auth-ki-fields'),
  jumpHostsList:    () => $('jump-hosts-list'),
  addJumpBtn:       () => $('add-jump-btn'),
  envVarsList:      () => $('env-vars-list'),
  addEnvBtn:        () => $('add-env-btn'),
  // Reveal modal
  revealModal:      () => $('reveal-modal'),
  revealModalClose: () => $('reveal-modal-close'),
  revealCancel:     () => $('reveal-cancel'),
  revealSubmit:     () => $('reveal-submit'),
  revealError:      () => $('reveal-error'),
  revealResult:     () => $('reveal-result'),
  revealContent:    () => $('reveal-content'),
};

// ── API helpers ─────────────────────────────────────────────────
async function apiFetch(method, path, body) {
  const opts = {
    method,
    headers: { 'Content-Type': 'application/json' },
  };
  if (body !== undefined) opts.body = JSON.stringify(body);
  const res = await fetch('/vault/api' + path, opts);
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { data = { message: text || res.statusText }; }
  if (!res.ok) {
    const msg = data?.message || data?.code || `HTTP ${res.status}`;
    const err = new Error(msg);
    err.code = data?.code;
    err.status = res.status;
    throw err;
  }
  return data;
}

const api = {
  status:          ()       => apiFetch('GET',    '/status'),
  vaultInit:       (mp)     => apiFetch('POST',   '/vault/init',   { master_password: mp }),
  vaultUnlock:     (mp)     => apiFetch('POST',   '/vault/unlock', { master_password: mp }),
  getHosts:        ()       => apiFetch('GET',    '/hosts'),
  addHost:         (body)   => apiFetch('POST',   '/hosts',        body),
  updateHost:      (id, b)  => apiFetch('PUT',    `/hosts/${id}`,  b),
  deleteHost:      (id)     => apiFetch('DELETE', `/hosts/${id}`),
  connectHost:     (id)     => apiFetch('POST',   `/hosts/${id}/connect`),
  disconnectHost:  (id)     => apiFetch('POST',   `/hosts/${id}/disconnect`),
  getSessions:     ()       => apiFetch('GET',    '/sessions'),
  closeSession:    (id)     => apiFetch('POST',   `/sessions/${id}/close`),
  getAudit:        ()       => apiFetch('GET',    '/audit?limit=200'),
};

// ── Toast notifications ─────────────────────────────────────────
function showToast(message, type = 'info', durationMs = 4000) {
  const region = el.toastRegion();
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.textContent = message;
  toast.setAttribute('role', 'alert');
  region.appendChild(toast);
  // Animate in
  requestAnimationFrame(() => toast.classList.add('toast-visible'));
  setTimeout(() => {
    toast.classList.remove('toast-visible');
    toast.addEventListener('transitionend', () => toast.remove(), { once: true });
    setTimeout(() => toast.remove(), 400);
  }, durationMs);
}

// ── View switching ──────────────────────────────────────────────
function switchView(viewName) {
  state.currentView = viewName;
  // Update nav
  el.navItems().forEach((btn) => {
    const active = btn.dataset.view === viewName;
    btn.classList.toggle('active', active);
    btn.setAttribute('aria-current', active ? 'page' : 'false');
  });
  // Show/hide sections
  document.querySelectorAll('.view').forEach((sec) => {
    sec.classList.toggle('hidden', sec.id !== `view-${viewName}`);
  });
  // Load data for the view
  if (viewName === 'registry') loadRegistry();
  if (viewName === 'hosts')    loadHosts();
  if (viewName === 'sessions') loadSessions();
  if (viewName === 'audit')    loadAudit();
  if (viewName === 'settings') loadSettings();
  // Stop sessions poller when leaving sessions view
  if (viewName !== 'sessions') stopSessionsPoller();
}

// ── Lock screen logic ───────────────────────────────────────────
async function checkVaultStatus() {
  try {
    const s = await api.status();
    state.vaultInitialized = s.vault_initialized;
    state.vaultUnlocked    = s.vault_unlocked;
  } catch (e) {
    showToast('无法连接本地服务: ' + describeError(e), 'error');
    state.vaultInitialized = false;
    state.vaultUnlocked    = false;
  }
}

function showLockScreen() {
  el.app().classList.add('hidden');
  el.lockScreen().classList.remove('hidden');
  const isInit = !state.vaultInitialized;
  el.lockSubtitle().textContent = isInit
    ? '首次运行: 设置主密码以初始化凭据库。'
    : '凭据库已锁定。输入主密码继续。';
  el.lockSubmit().textContent = isInit ? '初始化凭据库' : '解锁';
  el.mpConfirmWrap().classList.toggle('hidden', !isInit);
  el.lockError().classList.add('hidden');
  el.mpInput().value = '';
  if (el.mpConfirm()) el.mpConfirm().value = '';
  el.mpInput().focus();
}

function showApp() {
  el.lockScreen().classList.add('hidden');
  el.app().classList.remove('hidden');
  switchView('registry');
  refreshGrant();
}

async function handleLockSubmit(e) {
  e.preventDefault();
  const mp = el.mpInput().value.trim();
  if (!mp) { showLockError('请输入主密码。'); return; }
  if (!state.vaultInitialized) {
    const confirm = el.mpConfirm().value.trim();
    if (mp !== confirm) { showLockError('两次输入的主密码不一致。'); return; }
  }
  setLockBusy(true);
  try {
    if (!state.vaultInitialized) {
      await api.vaultInit(mp);
      state.vaultInitialized = true;
    }
    await api.vaultUnlock(mp);
    state.vaultUnlocked = true;
    showApp();
  } catch (err) {
    showLockError(describeError(err));
  } finally {
    setLockBusy(false);
  }
}

function showLockError(msg) {
  const errEl = el.lockError();
  errEl.textContent = msg;
  errEl.classList.remove('hidden');
}

function setLockBusy(busy) {
  el.lockSubmit().disabled = busy;
  el.lockSubmit().textContent = busy ? '请稍候…'
    : (!state.vaultInitialized ? '初始化凭据库' : '解锁');
}

// ── Hosts view ──────────────────────────────────────────────────
async function loadHosts() {
  el.hostsLoading().classList.remove('hidden');
  el.hostsEmpty().classList.add('hidden');
  el.hostsTableWrap().classList.add('hidden');
  el.hostsStatus().classList.add('hidden');
  try {
    const data = await api.getHosts();
    state.hosts = Array.isArray(data) ? data : (data.hosts || []);
    renderHosts();
  } catch (e) {
    showStatus(el.hostsStatus(), describeError(e), 'error');
  } finally {
    el.hostsLoading().classList.add('hidden');
  }
}

function renderHosts() {
  const hosts = state.hosts;
  if (!hosts.length) {
    el.hostsEmpty().classList.remove('hidden');
    el.hostsTableWrap().classList.add('hidden');
    return;
  }
  el.hostsEmpty().classList.add('hidden');
  el.hostsTableWrap().classList.remove('hidden');
  const list = el.hostsBody();
  list.innerHTML = '';
  hosts.forEach((h) => {
    // 卡片而不是表格行：字段与操作按钮保持原样，只换承载方式
    const card = document.createElement('article');
    card.className = 'host-card';
    card.dataset.hostId = h.host_id;
    card.innerHTML = `
      <div class="host-card-head">
        <h3>${escHtml(h.alias)}</h3>
        ${statusBadge(h.status)}
      </div>
      <dl class="host-card-fields">
        <dt>主机</dt><dd class="mono">${escHtml(h.host)}</dd>
        <dt>端口</dt><dd>${h.port}</dd>
        <dt>用户</dt><dd class="mono">${escHtml(h.user)}</dd>
        <dt>认证</dt><dd><span class="badge-auth">${escHtml(authLabel(h.auth_kind))}</span></dd>
        <dt>跳板</dt><dd>${h.jump_count || 0}</dd>
      </dl>
      <div class="host-card-actions">
        ${hostConnectionButton(h)}
        <button class="btn btn-sm btn-host-edit" data-id="${h.host_id}">编辑</button>
        <button class="btn btn-sm btn-host-reveal" data-id="${h.host_id}">查看凭据</button>
        <button class="btn btn-sm btn-danger btn-host-delete" data-id="${h.host_id}">删除</button>
      </div>`;
    list.appendChild(card);
  });
}

function hostConnectionButton(host) {
  if (host.status === 'connected') {
    return `<button class="btn btn-sm btn-host-disconnect" data-id="${host.host_id}">断开</button>`;
  }
  const disabled = host.status === 'connecting' ? 'disabled' : '';
  const label = host.status === 'connecting' ? '连接中…' : '连接';
  return `<button class="btn btn-sm btn-host-connect" data-id="${host.host_id}" ${disabled}>${label}</button>`;
}

function statusBadge(status) {
  const cls = { connected: 'badge-connected', disconnected: 'badge-disconnected', connecting: 'badge-connecting' };
  return `<span class="badge ${cls[status] || 'badge-disconnected'}">${escHtml(statusLabel(status))}</span>`;
}

function statusLabel(status) {
  return {
    connected: '已连接',
    disconnected: '未连接',
    connecting: '连接中',
  }[status] || '未连接';
}

function authLabel(authKind) {
  return {
    password: '密码',
    private_key: '私钥',
    keyboard_interactive: '键盘交互',
  }[authKind] || authKind || '未知';
}

function sessionKindLabel(kind) {
  return {
    pty: '终端',
  }[kind] || kind || '未知';
}

async function handleHostsTableClick(e) {
  const btn = e.target.closest('button[data-id]');
  if (!btn) return;
  const id = btn.dataset.id;
  if (btn.classList.contains('btn-host-connect')) await handleConnect(id, btn);
  else if (btn.classList.contains('btn-host-disconnect')) await handleDisconnect(id, btn);
  else if (btn.classList.contains('btn-host-edit'))   handleEditHost(id);
  else if (btn.classList.contains('btn-host-reveal')) handleReveal(id);
  else if (btn.classList.contains('btn-host-delete')) await handleDeleteHost(id, btn);
}

async function handleDisconnect(hostId, btn) {
  if (state.inflightButtons.has(btn)) return;
  state.inflightButtons.add(btn);
  btn.disabled = true; btn.textContent = '断开中…';
  try {
    await api.disconnectHost(hostId);
    showToast('已断开连接。', 'info');
    await loadHosts();
  } catch (e) {
    showToast('断开失败: ' + describeError(e), 'error');
    btn.disabled = false; btn.textContent = '断开';
  } finally {
    state.inflightButtons.delete(btn);
  }
}

async function handleConnect(hostId, btn) {
  if (state.inflightButtons.has(btn)) return;
  state.inflightButtons.add(btn);
  btn.disabled = true; btn.textContent = '连接中…';
  try {
    await api.connectHost(hostId);
    showToast('连接成功。', 'success');
    await loadHosts();
  } catch (e) {
    showToast('连接失败: ' + describeError(e), 'error');
    btn.disabled = false; btn.textContent = '连接';
  } finally {
    state.inflightButtons.delete(btn);
  }
}

async function handleDeleteHost(hostId, btn) {
  if (!confirm('确定删除这台主机吗？此操作不可撤销。')) return;
  if (state.inflightButtons.has(btn)) return;
  state.inflightButtons.add(btn);
  btn.disabled = true;
  try {
    await api.deleteHost(hostId);
    showToast('主机已删除。', 'info');
    await loadHosts();
  } catch (e) {
    showToast('删除失败: ' + describeError(e), 'error');
    btn.disabled = false;
  } finally {
    state.inflightButtons.delete(btn);
  }
}

// ── Host modal (add / edit) ─────────────────────────────────────
function openHostModal(existingHost) {
  const modal = el.hostModal();
  el.hostFormError().classList.add('hidden');
  el.jumpHostsList().innerHTML = '';
  el.envVarsList().innerHTML = '';
  if (existingHost) {
    el.hostModalTitle().textContent = '编辑主机';
    el.hostFormSubmit().textContent = '保存更改';
    el.hostIdField().value = existingHost.host_id;
    el.hfAlias().value = existingHost.alias || '';
    el.hfHost().value  = existingHost.host  || '';
    el.hfPort().value  = existingHost.port  || 22;
    el.hfUser().value  = existingHost.user  || '';
    el.hfNotes().value = existingHost.notes || '';
    const kind = existingHost.auth_kind || 'password';
    const radio = modal.querySelector(`input[name="auth-type"][value="${kind}"]`);
    if (radio) { radio.checked = true; syncAuthFields(kind); }
    fillAuthFields(existingHost.auth);
    fillJumpRows(existingHost.jump_hosts || []);
    fillEnvRows(existingHost.env || {});
    fillBecomeRootFields(existingHost.become_root);
  } else {
    el.hostModalTitle().textContent = '添加主机';
    el.hostFormSubmit().textContent = '保存主机';
    el.hostIdField().value = '';
    el.hfAlias().value = '';
    el.hfHost().value  = '';
    el.hfPort().value  = 22;
    el.hfUser().value  = '';
    el.hfNotes().value = '';
    el.hfPassword().value = '';
    el.hfKeyPem().value = '';
    el.hfKeyPassphrase().value = '';
    el.hfKiAnswers().value = '';
    resetBecomeRootFields();
    modal.querySelector('input[name="auth-type"][value="password"]').checked = true;
    syncAuthFields('password');
  }
  modal.classList.remove('hidden');
  el.hfAlias().focus();
}

function closeHostModal() { el.hostModal().classList.add('hidden'); }

function syncAuthFields(type) {
  el.authPasswordFields().classList.toggle('hidden', type !== 'password');
  el.authKeyFields().classList.toggle('hidden', type !== 'private_key');
  el.authKiFields().classList.toggle('hidden', type !== 'keyboard_interactive');
}

function resetBecomeRootFields() {
  el.hfBecomeRootEnabled().checked = false;
  el.hfBecomeRootFields().classList.add('hidden');
  el.hfBecomeRootCommand().value = 'su -';
  el.hfBecomeRootPassword().value = '';
  el.hfBecomeRootTimeout().value = 5000;
}

function fillBecomeRootFields(becomeRoot) {
  resetBecomeRootFields();
  if (!becomeRoot) return;
  el.hfBecomeRootEnabled().checked = !!becomeRoot.enabled;
  el.hfBecomeRootCommand().value = becomeRoot.command || 'su -';
  el.hfBecomeRootPassword().value = becomeRoot.password || '***';
  el.hfBecomeRootTimeout().value = becomeRoot.prompt_timeout_ms || 5000;
  syncBecomeRootFields();
}

function fillAuthFields(auth) {
  el.hfPassword().value = '';
  el.hfKeyPem().value = '';
  el.hfKeyPassphrase().value = '';
  el.hfKiAnswers().value = '';
  if (!auth) return;
  if (auth.type === 'password') {
    el.hfPassword().value = auth.password || '***';
  } else if (auth.type === 'private_key') {
    el.hfKeyPem().value = auth.key_pem || '***';
    el.hfKeyPassphrase().value = auth.passphrase || '';
  } else if (auth.type === 'keyboard_interactive') {
    el.hfKiAnswers().value = Array.isArray(auth.answers) ? auth.answers.join('\n') : '';
  }
}

function fillJumpRows(jumpHosts) {
  el.jumpHostsList().innerHTML = '';
  jumpHosts.forEach(addJumpRow);
}

function fillEnvRows(env) {
  el.envVarsList().innerHTML = '';
  Object.entries(env || {}).forEach(([key, value]) => addEnvRow(key, value));
}

function syncBecomeRootFields() {
  el.hfBecomeRootFields().classList.toggle('hidden', !el.hfBecomeRootEnabled().checked);
}

function handleEditHost(hostId) {
  const host = state.hosts.find((h) => h.host_id === hostId);
  if (host) openHostModal(host);
}

function addJumpRow(data) {
  const container = el.jumpHostsList();
  const row = document.createElement('div');
  row.className = 'jump-row';
  row.dataset.auth = data?.auth ? JSON.stringify(data.auth) : '';
  row.innerHTML = `
    <div class="field-group" style="margin:0"><label>主机</label>
      <input type="text" class="jump-host" placeholder="jump.example.com" value="${escHtml(data?.host || '')}" /></div>
    <div class="field-group" style="margin:0"><label>用户</label>
      <input type="text" class="jump-user" placeholder="用户名" value="${escHtml(data?.user || '')}" /></div>
    <div class="field-group" style="margin:0"><label>端口</label>
      <input type="number" class="jump-port" min="1" max="65535" value="${data?.port || 22}" /></div>
    <button type="button" class="remove-btn" aria-label="移除跳板">&times;</button>`;
  row.querySelector('.remove-btn').addEventListener('click', () => row.remove());
  container.appendChild(row);
}

function addEnvRow(key, value) {
  const container = el.envVarsList();
  const row = document.createElement('div');
  row.className = 'env-row';
  row.innerHTML = `
    <div class="field-group" style="margin:0"><label>键</label>
      <input type="text" class="env-key" placeholder="VAR_NAME" value="${escHtml(key || '')}" /></div>
    <div class="field-group" style="margin:0"><label>值</label>
      <input type="text" class="env-value" placeholder="变量值" value="${escHtml(value || '')}" /></div>
    <button type="button" class="remove-btn" aria-label="移除变量">&times;</button>`;
  row.querySelector('.remove-btn').addEventListener('click', () => row.remove());
  container.appendChild(row);
}

async function handleHostFormSubmit(e) {
  e.preventDefault();
  el.hostFormError().classList.add('hidden');
  const alias = el.hfAlias().value.trim();
  const host  = el.hfHost().value.trim();
  const port  = parseInt(el.hfPort().value, 10) || 22;
  const user  = el.hfUser().value.trim();
  const notes = el.hfNotes().value.trim();
  if (!alias || !host || !user) {
    showFormError(el.hostFormError(), '别名、主机名和用户名不能为空。');
    return;
  }
  const auth = buildAuthFromForm();
  const jumpHosts = [];
  el.jumpHostsList().querySelectorAll('.jump-row').forEach((row) => {
    const jhost = row.querySelector('.jump-host').value.trim();
    const juser = row.querySelector('.jump-user').value.trim();
    const jport = parseInt(row.querySelector('.jump-port').value, 10) || 22;
    if (jhost) {
      let jumpAuth = structuredClone(auth);
      if (row.dataset.auth) {
        try { jumpAuth = JSON.parse(row.dataset.auth); } catch {}
      }
      jumpHosts.push({ host: jhost, user: juser, port: jport, auth: jumpAuth });
    }
  });
  const env = {};
  el.envVarsList().querySelectorAll('.env-row').forEach((row) => {
    const k = row.querySelector('.env-key').value.trim();
    const v = row.querySelector('.env-value').value;
    if (k) env[k] = v;
  });
  const body = { alias, host, port, user, notes, auth, jump_hosts: jumpHosts, env };
  if (el.hfBecomeRootEnabled().checked) {
    const password = el.hfBecomeRootPassword().value;
    if (!password) {
      showFormError(el.hostFormError(), '启用登入后转 root 时，root 密码不能为空。');
      return;
    }
    body.become_root = {
      enabled: true,
      command: el.hfBecomeRootCommand().value.trim() || 'su -',
      password,
      prompt_timeout_ms: parseInt(el.hfBecomeRootTimeout().value, 10) || 5000,
    };
  }
  const hostId = el.hostIdField().value;
  el.hostFormSubmit().disabled = true;
  el.hostFormSubmit().textContent = '保存中…';
  try {
    if (hostId) {
      await api.updateHost(hostId, body);
      showToast('主机已更新。', 'success');
    } else {
      await api.addHost(body);
      showToast('主机已添加。', 'success');
    }
    closeHostModal();
    await loadHosts();
  } catch (err) {
    showFormError(el.hostFormError(), describeError(err));
  } finally {
    el.hostFormSubmit().disabled = false;
    el.hostFormSubmit().textContent = hostId ? '保存更改' : '保存主机';
  }
}

function buildAuthFromForm() {
  const authType = el.hostModal().querySelector('input[name="auth-type"]:checked').value;
  if (authType === 'password') {
    return { type: 'password', password: el.hfPassword().value };
  }
  if (authType === 'private_key') {
    const auth = { type: 'private_key', key_pem: el.hfKeyPem().value };
    const pp = el.hfKeyPassphrase().value;
    if (pp) auth.passphrase = pp;
    return auth;
  }
  const answers = el.hfKiAnswers().value.split('\n').map((s) => s.trim()).filter(Boolean);
  return { type: 'keyboard_interactive', answers };
}

// ── Reveal credentials modal ────────────────────────────────────
let revealTargetHostId = null;

function handleReveal(hostId) {
  revealTargetHostId = hostId;
  el.revealError().classList.add('hidden');
  el.revealResult().classList.add('hidden');
  el.revealContent().textContent = '';
  el.revealModal().classList.remove('hidden');
  handleRevealSubmit();
}

async function handleRevealSubmit() {
  if (!revealTargetHostId) return;
  el.revealSubmit().disabled = true;
  el.revealSubmit().textContent = '读取中…';
  el.revealError().classList.add('hidden');
  try {
    const data = await apiFetch('POST', `/hosts/${revealTargetHostId}/reveal`);
    el.revealContent().textContent = JSON.stringify(data, null, 2);
    el.revealResult().classList.remove('hidden');
  } catch (err) {
    showFormError(el.revealError(), describeError(err));
  } finally {
    el.revealSubmit().disabled = false;
    el.revealSubmit().textContent = '重新读取';
  }
}

function closeRevealModal() {
  el.revealModal().classList.add('hidden');
  el.revealContent().textContent = '';
  el.revealResult().classList.add('hidden');
  revealTargetHostId = null;
}

// ── Sessions view ───────────────────────────────────────────────
async function loadSessions() {
  el.sessionsLoading().classList.remove('hidden');
  el.sessionsEmpty().classList.add('hidden');
  el.sessionsTableWrap().classList.add('hidden');
  el.sessionsStatus().classList.add('hidden');
  try {
    const data = await api.getSessions();
    state.sessions = Array.isArray(data) ? data : (data.sessions || []);
    renderSessions();
    startSessionsPoller();
  } catch (e) {
    showStatus(el.sessionsStatus(), describeError(e), 'error');
  } finally {
    el.sessionsLoading().classList.add('hidden');
  }
}

function renderSessions() {
  const sessions = state.sessions;
  if (!sessions.length) {
    el.sessionsEmpty().classList.remove('hidden');
    el.sessionsTableWrap().classList.add('hidden');
    return;
  }
  el.sessionsEmpty().classList.add('hidden');
  el.sessionsTableWrap().classList.remove('hidden');
  const tbody = el.sessionsBody();
  tbody.innerHTML = '';
  sessions.forEach((s) => {
    const host = state.hosts.find((h) => h.host_id === s.host_id);
    const hostLabel = host ? escHtml(host.alias) : escHtml(s.host_id);
    const ttl = s.idle_ttl_left_secs != null ? formatTtl(s.idle_ttl_left_secs) : '—';
    const size = (s.cols && s.rows) ? `${s.cols}x${s.rows}` : '—';
    const started = s.created_at ? new Date(s.created_at).toLocaleString() : '—';
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="mono">${escHtml(s.session_id.slice(0, 12))}…</td>
      <td>${hostLabel}</td>
      <td>${escHtml(sessionKindLabel(s.kind))}</td>
      <td>${started}</td>
      <td class="ttl-cell" data-ttl="${s.idle_ttl_left_secs ?? ''}">${ttl}</td>
      <td class="mono">${size}</td>
      <td class="col-actions">
        <div class="action-group">
          <button class="btn btn-sm btn-session-takeover" data-id="${s.session_id}">接管</button>
          <button class="btn btn-sm btn-danger btn-session-close" data-id="${s.session_id}">关闭</button>
        </div>
      </td>`;
    tbody.appendChild(tr);
  });
}

function formatTtl(secs) {
  if (secs == null || secs < 0) return '—';
  const m = Math.floor(secs / 60);
  const s = secs % 60;
  return m > 0 ? `${m} 分 ${s} 秒` : `${s} 秒`;
}

function startSessionsPoller() {
  if (state.sessionsPollerHandle) return;
  state.sessionsPollerHandle = setInterval(async () => {
    if (state.currentView !== 'sessions') { stopSessionsPoller(); return; }
    try {
      const data = await api.getSessions();
      state.sessions = Array.isArray(data) ? data : (data.sessions || []);
      renderSessions();
    } catch { /* ignore poll errors silently */ }
  }, 3000);
}

function stopSessionsPoller() {
  if (state.sessionsPollerHandle) {
    clearInterval(state.sessionsPollerHandle);
    state.sessionsPollerHandle = null;
  }
}

async function handleSessionsTableClick(e) {
  const btn = e.target.closest('button[data-id]');
  if (!btn) return;
  const id = btn.dataset.id;
  if (btn.classList.contains('btn-session-takeover')) handleTakeover(id);
  else if (btn.classList.contains('btn-session-close')) await handleCloseSession(id, btn);
}

async function handleCloseSession(sessionId, btn) {
  if (!confirm('确定关闭这个会话吗？')) return;
  btn.disabled = true;
  try {
    await api.closeSession(sessionId);
    showToast('会话已关闭。', 'info');
    if (state.activeTermSessionId === sessionId) closeTerminal();
    const data = await api.getSessions();
    state.sessions = Array.isArray(data) ? data : (data.sessions || []);
    renderSessions();
  } catch (e) {
    showToast('关闭会话失败: ' + describeError(e), 'error');
    btn.disabled = false;
  }
}

// ── xterm.js terminal ───────────────────────────────────────────
function handleTakeover(sessionId) {
  // Close any existing terminal first
  if (state.activeTermSessionId) closeTerminal();

  const session = state.sessions.find((s) => s.session_id === sessionId);
  const host = session ? state.hosts.find((h) => h.host_id === session.host_id) : null;
  el.termLabel().textContent = host
    ? `${host.alias} - 会话 ${sessionId.slice(0, 8)}`
    : `会话 ${sessionId.slice(0, 8)}`;

  el.termPanel().classList.remove('hidden');
  el.termPanel().scrollIntoView({ behavior: 'smooth' });

  // Initialize xterm
  const term = new Terminal({
    theme: {
      background: '#0d1117',
      foreground: '#e6edf3',
      cursor:     '#58a6ff',
      selectionBackground: 'rgba(88,166,255,0.3)',
      black: '#484f58', red: '#ff7b72', green: '#3fb950', yellow: '#d29922',
      blue: '#58a6ff', magenta: '#bc8cff', cyan: '#39c5cf', white: '#b1bac4',
      brightBlack: '#6e7681', brightRed: '#ffa198', brightGreen: '#56d364',
      brightYellow: '#e3b341', brightBlue: '#79c0ff', brightMagenta: '#d2a8ff',
      brightCyan: '#56d4dd', brightWhite: '#f0f6fc',
    },
    fontFamily: 'monospace',
    fontSize: 13,
    lineHeight: 1.4,
    cursorBlink: true,
    convertEol: true,
    scrollback: 2000,
    rows: session?.rows || 24,
    cols: session?.cols || 80,
  });

  const fitAddon = new FitAddon.FitAddon();
  term.loadAddon(fitAddon);

  const container = el.xtermContainer();
  container.innerHTML = '';
  term.open(container);
  fitAddon.fit();

  state.termInstance = term;
  state.termFitAddon = fitAddon;
  state.activeTermSessionId = sessionId;

  // Open WebSocket
  const wsUrl = `ws://${location.host}/api/sessions/${sessionId}/attach`;
  const ws = new WebSocket(wsUrl);
  state.termSocket = ws;

  ws.onopen = () => {
    term.writeln('\x1b[32m[已连接到会话]\x1b[0m');
  };
  ws.onmessage = (evt) => {
    term.write(evt.data);
  };
  ws.onerror = () => {
    term.writeln('\x1b[31m[WebSocket 错误]\x1b[0m');
  };
  ws.onclose = (evt) => {
    term.writeln(`\x1b[33m[会话已关闭 - 代码 ${evt.code}]\x1b[0m`);
    state.termSocket = null;
  };

  // Send typed input
  term.onData((data) => {
    if (ws.readyState === WebSocket.OPEN) ws.send(data);
  });

  // Resize observer to fit terminal on panel resize
  const ro = new ResizeObserver(() => { try { fitAddon.fit(); } catch {} });
  ro.observe(container);
  state._termResizeObserver = ro;
}

function closeTerminal() {
  if (state.termSocket) {
    state.termSocket.close();
    state.termSocket = null;
  }
  if (state.termInstance) {
    state.termInstance.dispose();
    state.termInstance = null;
  }
  if (state._termResizeObserver) {
    state._termResizeObserver.disconnect();
    state._termResizeObserver = null;
  }
  state.activeTermSessionId = null;
  el.termPanel().classList.add('hidden');
  el.xtermContainer().innerHTML = '';
}

// ── Audit view ──────────────────────────────────────────────────
async function loadAudit() {
  el.auditLoading().classList.remove('hidden');
  el.auditEmpty().classList.add('hidden');
  el.auditList().classList.add('hidden');
  el.auditStatus().classList.add('hidden');
  try {
    const data = await api.getAudit();
    const entries = Array.isArray(data) ? data : (data.entries || []);
    renderAudit(entries);
  } catch (e) {
    showStatus(el.auditStatus(), describeError(e), 'error');
  } finally {
    el.auditLoading().classList.add('hidden');
  }
}

function renderAudit(entries) {
  if (!entries.length) {
    el.auditEmpty().classList.remove('hidden');
    return;
  }
  el.auditList().classList.remove('hidden');
  const list = el.auditList();
  list.innerHTML = '';
  entries.forEach((entry) => {
    const div = document.createElement('div');
    div.className = 'audit-entry';
    const ts = formatAuditTime(entry.ts || entry.timestamp || '');
    const rawAction = entry.action || entry.event || JSON.stringify(entry).slice(0, 80);
    const action = auditActionLabel(rawAction);
    const host = entry.host || entry.alias || entry.host_id || '';
    const detail = auditDetailText(entry);
    const exitCode = entry.exit_code != null ? `退出码:${entry.exit_code}` : '';
    div.innerHTML = `
      <span class="audit-ts">${escHtml(ts)}</span>
      <span class="audit-action">${escHtml(action)}</span>
      <span class="audit-host">${escHtml(host)}</span>
      <span class="audit-detail">${escHtml(detail)} ${escHtml(exitCode)}</span>`;
    list.appendChild(div);
  });
}

function formatAuditTime(value) {
  if (!value) return '';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString('zh-CN', {
    timeZone: 'Asia/Shanghai',
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
  });
}

function auditDetailText(entry) {
  if (entry.detail != null) {
    if (typeof entry.detail === 'string') return entry.detail;
    return JSON.stringify(entry.detail, null, 2);
  }
  return entry.message || entry.error || '';
}

// ── Helpers ─────────────────────────────────────────────────────
function escHtml(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function showStatus(el, message, type) {
  el.textContent = message;
  el.className = `status-bar ${type}`;
  el.classList.remove('hidden');
}

function showFormError(el, message) {
  el.textContent = message;
  el.classList.remove('hidden');
}

function auditActionLabel(action) {
  return {
    vault_init: '初始化凭据库',
    vault_unlock: '解锁凭据库',
    host_add: '添加主机',
    host_update: '更新主机',
    host_remove: '删除主机',
    host_connect: '连接主机',
    host_connect_failed: '连接失败',
    host_disconnect: '断开主机',
    credential_reveal: '查看凭据',
    exec: '执行命令',
    exec_failed: '命令失败',
    pty_open: '打开终端',
    pty_open_failed: '打开终端失败',
    pty_open_root: '打开 root 终端',
    pty_open_root_failed: '打开 root 终端失败',
    pty_send_text: '终端输入',
    pty_send_key: '终端按键',
    pty_close: '关闭终端',
    sftp_list: '列出目录',
    sftp_get: '下载文件',
    sftp_put: '上传文件',
    sftp_download_file: '下载大文件',
    sftp_upload_file: '上传大文件',
  }[action] || action || '';
}

function describeError(err) {
  const byCode = {
    vault_locked: '请在顶部打开30分钟临时管理开关。',
    vault_bad_password: '主密码不正确。',
    vault_already_init: '凭据库已经初始化。',
    host_not_found: '找不到指定主机。',
    auth_failed: 'SSH 认证失败。',
    jump_failed_at_hop: '跳板链连接失败。',
    host_key_mismatch: '主机密钥指纹与首次记录不一致，已拒绝连接。',
    disconnected: '主机没有可用连接。',
    session_not_found: '找不到指定会话。',
    timeout: '操作超时。',
    credential_write_only: '凭据字段只允许写入，不允许读取。',
    bad_request: '请求参数不正确。',
    sftp_error: 'SFTP 操作失败。',
    internal: '内部错误。',
  };
  return byCode[err?.code] || err?.message || '操作失败。';
}

// ── App bootstrap ───────────────────────────────────────────────
async function boot() {
  await checkVaultStatus();
  if (!state.vaultUnlocked) {
    el.lockScreen().classList.add('hidden');
    el.app().classList.remove('hidden');
    showToast('服务未就绪或统一登录已失效，请返回统一入口。', 'error');
  } else {
    showApp();
  }
}

function attachEventListeners() {
  // Lock form
  el.lockForm().addEventListener('submit', handleLockSubmit);

  // Lock vault button
  el.lockBtn().addEventListener('click', () => {
    apiFetch('PUT', '/management/grant', {enabled:false}).then(refreshGrant).catch(e=>showToast(describeError(e),'error'));
  });

  // Nav
  el.navItems().forEach((btn) => {
    btn.addEventListener('click', () => switchView(btn.dataset.view));
  });

  // Auth type radio
  document.querySelectorAll('input[name="auth-type"]').forEach((radio) => {
    radio.addEventListener('change', () => syncAuthFields(radio.value));
  });
  el.hfBecomeRootEnabled().addEventListener('change', syncBecomeRootFields);

  // Add host
  el.addHostBtn().addEventListener('click', () => openHostModal(null));

  // Host modal close
  el.hostModalClose().addEventListener('click', closeHostModal);
  el.hostModalCancel().addEventListener('click', closeHostModal);
  el.hostModal().addEventListener('click', (e) => {
    if (e.target === el.hostModal()) closeHostModal();
  });

  // Host form submit
  el.hostForm().addEventListener('submit', handleHostFormSubmit);

  // Jump / env dynamic rows
  el.addJumpBtn().addEventListener('click', () => addJumpRow(null));
  el.addEnvBtn().addEventListener('click', () => addEnvRow('', ''));

  // Hosts table actions (delegated)
  el.hostsBody().addEventListener('click', handleHostsTableClick);

  // Sessions
  el.sessionsRefresh().addEventListener('click', loadSessions);
  el.sessionsBody().addEventListener('click', handleSessionsTableClick);
  el.termClose().addEventListener('click', closeTerminal);

  // Audit
  el.auditRefresh().addEventListener('click', loadAudit);

  // Reveal modal
  el.revealModalClose().addEventListener('click', closeRevealModal);
  el.revealCancel().addEventListener('click', closeRevealModal);
  el.revealModal().addEventListener('click', (e) => {
    if (e.target === el.revealModal()) closeRevealModal();
  });
  el.revealSubmit().addEventListener('click', handleRevealSubmit);

  // Close modals on Escape
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      if (!el.hostModal().classList.contains('hidden'))   closeHostModal();
      if (!el.revealModal().classList.contains('hidden')) closeRevealModal();
    }
  });
}

// Entry point
document.addEventListener('DOMContentLoaded', () => {
  attachEventListeners();
  boot();
});

async function loadSettings() {
  try {
    const v = await apiFetch('GET', '/settings');
    $('mcp-idle-minutes').value = v.saved_minutes;
    $('settings-runtime').textContent = `当前运行：${v.active_minutes} 分钟\n已保存：${v.saved_minutes} 分钟\n` + (v.restart_required ? '重启连接器后生效。' : '当前已生效。') + (v.environment_override ? '环境变量正在覆盖网页设置。' : '');
    $('settings-save').disabled = !!v.environment_override;
  } catch (e) { $('settings-status').textContent = describeError(e); }
}
$('settings-form').addEventListener('submit', async e => {
  e.preventDefault();
  const minutes = Number($('mcp-idle-minutes').value);
  if (!Number.isInteger(minutes) || minutes < 5 || minutes > 1440) { $('settings-status').textContent = '请输入5至1440之间的整数。'; return; }
  $('settings-save').disabled = true;
  try {
    await apiFetch('PUT', '/settings', {mcp_idle_timeout_minutes: minutes});
    $('settings-status').textContent = '设置已保存。修改将在重启连接器后生效。';
    await loadSettings();
  } catch(e) { $('settings-status').textContent = describeError(e); }
  finally { $('settings-save').disabled = false; }
});

async function refreshGrant(){
  try {const v=await apiFetch('GET','/status');$('management-grant-switch').checked=v.management_unlocked;const left=v.management_remaining_seconds||0;$('management-countdown').textContent=left>0?`剩余 ${Math.floor(left/60)}分${left%60}秒`:'已关闭';} catch(e){$('management-countdown').textContent='登录已失效或服务未连接';}
}
$('management-grant-switch').addEventListener('change',async e=>{try{await apiFetch('PUT','/management/grant',{enabled:e.target.checked});await refreshGrant();}catch(err){e.target.checked=false;showToast(describeError(err),'error')}});
setInterval(refreshGrant,10000);

const methodCatalog={remote_mcp:[['exa','Exa 搜索'],['wechat','微信公众号文章']],http_api:[['doubao','豆包搜索（国内版）']],local_program:[['github','GitHub 命令行（gh / git）']]};
let editorSnapshot='',editorTrigger=null;
function editorState(){return JSON.stringify(Object.fromEntries(new FormData($('registry-form'))));}
function updateMethods(selected){const f=$('registry-form'),kind=f.elements.interface_type.value;f.elements.invocation_method.replaceChildren(...methodCatalog[kind].map(([v,t])=>new Option(t,v)));if(selected&&methodCatalog[kind].some(([v])=>v===selected))f.elements.invocation_method.value=selected;$('invocation-hint').textContent=kind==='local_program'?'当前支持命令行适配；标准输入输出 MCP 尚未开放。':'仅显示已实现并支持的调用方法。';}
function openEditor(item,trigger){
  const f=$('registry-form');f.reset();editorTrigger=trigger;
  for(const k of ['id','name','url','notes'])f.elements[k].value=item?.[k]||'';
  f.elements.id.readOnly=!!item;
  f.elements.interface_type.value=item?.interface_type||'remote_mcp';
  updateMethods(item?.invocation_method||item?.adapter);
  f.elements.tools.value=JSON.stringify(item?.tools||[],null,2);
  f.elements.credential.value='';
  $('registry-editor-title').textContent=item?'编辑 MCP':'新增 MCP';
  if(item?.has_credential){
    f.elements.credential.placeholder='读取中…';
    apiFetch('GET',`/registry/${encodeURIComponent(item.id)}/credential`).then(v=>{
      f.elements.credential.value=v.credential||'';f.elements.credential.placeholder='修改后保存即生效';editorSnapshot=editorState();
    }).catch(e=>{f.elements.credential.placeholder='读取失败';showToast(describeError(e),'error');});
  } else { f.elements.credential.placeholder=item?'此服务无凭据':'填写凭据'; }
  $('registry-editor').showModal();document.body.classList.add('editor-open');editorSnapshot=editorState();
  f.elements.id.focus({preventScroll:true});
}
function closeEditor(force){
  if(!force&&editorSnapshot&&editorState()!==editorSnapshot&&!confirm('有未保存的修改，确定放弃吗？'))return;
  $('registry-editor').close();document.body.classList.remove('editor-open');editorSnapshot='';editorTrigger?.focus({preventScroll:true});
}
async function loadRegistry(){
  const box=$('registry-list');box.replaceChildren();
  try{
    const result=await apiFetch('GET','/registry');
    for(const item of result.services){
      const node=document.createElement('article'),title=document.createElement('h3'),notes=document.createElement('p'),button=document.createElement('button');
      title.textContent=item.name;notes.textContent=item.notes||'（未填写调用注意事项）';
      button.textContent='编辑';button.type='button';button.className='btn btn-ghost';button.onclick=()=>openEditor(item,button);
      node.append(title,notes,button);box.append(node);
    }
    if(!result.services.length){const empty=document.createElement('p');empty.textContent='还没有注册 MCP。';box.append(empty);}
    $('registry-message').classList.add('hidden');
  }catch(e){showStatus($('registry-message'),describeError(e),'error')}
  await refreshGrant();
}
$('registry-form').elements.interface_type.addEventListener('change',()=>updateMethods());
$('registry-close').addEventListener('click',()=>closeEditor(false));
$('registry-cancel').addEventListener('click',()=>closeEditor(false));
$('registry-editor').addEventListener('cancel',e=>{e.preventDefault();closeEditor(false);});
$('registry-new').addEventListener('click',e=>openEditor(null,e.currentTarget));
$('credential-copy').addEventListener('click',async()=>{
  const input=$('rf-credential');if(!input.value){showToast('没有可复制的凭据','info');return;}
  try{await navigator.clipboard.writeText(input.value);showToast('凭据已复制到剪贴板','success');}
  catch{input.focus();input.select();showToast('凭据已选中，可手动复制','info');}
});
$('registry-form').addEventListener('submit',async e=>{
  e.preventDefault();const f=e.target,b=f.querySelector('.modal-footer .btn-primary');b.disabled=true;
  try{
    const value=Object.fromEntries(new FormData(f));value.adapter=value.invocation_method;value.tools=JSON.parse(value.tools);
    await apiFetch('PUT','/registry',value);f.elements.credential.value='';closeEditor(true);
    showToast('注册已保存，凭据不回传给智能体','success');await loadRegistry();
  }catch(err){showStatus($('registry-message'),describeError(err),'error')}
  finally{b.disabled=false}
});
