const API = '';

function escapeHtml(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function toast(msg, type = '') {
  const t = document.getElementById('toast');
  if (!t) return;
  t.textContent = msg;
  t.className = 'toast show ' + type;
  setTimeout(() => t.className = 'toast', 3000);
}

async function fetchJSON(url, opts = {}) {
  let token = null;
  try {
    const t = await fetch(API + '/api/csrf-token', { credentials: 'same-origin' });
    const d = await t.json();
    token = d.token;
  } catch(e) {}
  const headers = { 'Content-Type': 'application/json', ...opts.headers };
  if (token) headers['X-CSRF-Token'] = token;
  const res = await fetch(API + url, { ...opts, headers, credentials: 'same-origin' });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Request failed');
  return data;
}

function showLoading(selector) {
  const el = document.querySelector(selector);
  if (el) el.innerHTML = '<div class="loading-placeholder"><div class="spinner"></div><p>Loading...</p></div>';
}

async function logout() {
  await fetchJSON('/api/auth/logout', { method: 'POST' });
  window.location.href = '/';
}

function setAuthLinks(u, opts) {
  opts = opts || {};
  const el = document.getElementById('auth-links');
  if (!el) return;
  if (!u) {
    el.innerHTML = '<a href="/login" class="btn btn-secondary btn-sm">Login</a>';
    return;
  }
  var prefix = opts.prefix || '';
  var label = u.role === 'admin' ? 'Admin' : 'Voter';
  var adminLink = (u.role === 'admin' && !opts.hideAdmin) ? ' <a href="/admin">Admin</a>' : '';
  el.innerHTML = '<span style="opacity:0.8;">' + escapeHtml(prefix + label) + '</span> <a href="#" onclick="logout()" class="btn btn-sm btn-outline" style="color:white;border-color:rgba(255,255,255,0.4);">Logout</a>' + adminLink;
}

function toggleDark() {
  const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
  document.documentElement.setAttribute('data-theme', isDark ? '' : 'dark');
  localStorage.setItem('theme', isDark ? 'light' : 'dark');
}

function loadTheme() {
  const saved = localStorage.getItem('theme');
  if (saved === 'dark') document.documentElement.setAttribute('data-theme', 'dark');
}

function connectWebSocket(onMessage) {
  const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const ws = new WebSocket(protocol + '//' + location.host);
  ws.onmessage = function(event) {
    try {
      const data = JSON.parse(event.data);
      if (onMessage) onMessage(data);
    } catch (e) { /* silent */ }
  };
  ws.onclose = function() {
    setTimeout(() => connectWebSocket(onMessage), 3000);
  };
  return ws;
}

function showModal(html) {
  let overlay = document.getElementById('modal-overlay');
  if (!overlay) {
    overlay = document.createElement('div');
    overlay.id = 'modal-overlay';
    overlay.className = 'modal-overlay';
    overlay.onclick = function(e) { if (e.target === overlay) closeModal(); };
    document.body.appendChild(overlay);
  }
  overlay.innerHTML = '<div class="modal-content"><button class="modal-close" onclick="closeModal()">&times;</button>' + html + '</div>';
  overlay.style.display = 'flex';
}

function closeModal() {
  const overlay = document.getElementById('modal-overlay');
  if (overlay) overlay.style.display = 'none';
}

async function showCandidateDetail(candidateId) {
  try {
    const c = await fetchJSON('/api/votes/candidate/' + candidateId);
    showModal(`
      <h2>${escapeHtml(c.name)}</h2>
      <p style="color:var(--text-secondary);margin-bottom:15px;">${escapeHtml(c.position_name)}</p>
      <div class="candidate-photo-large"><img src="${escapeHtml(c.photo)}" alt="${escapeHtml(c.name)}"></div>
      ${c.manifesto ? '<div class="manifesto-full">' + escapeHtml(c.manifesto) + '</div>' : '<p style="color:var(--gray);font-style:italic;">No manifesto provided.</p>'}
    `);
  } catch (err) { toast('Failed to load candidate details', 'error'); }
}

function closeModalOnEsc() {
  document.addEventListener('keydown', function(e) { if (e.key === 'Escape') closeModal(); });
}

function togglePassword(id) {
  var input = document.getElementById(id);
  if (!input) return;
  var btn = input.nextElementSibling;
  if (!btn) return;
  if (input.type === 'password') {
    input.type = 'text';
    btn.textContent = '\u{1F441}';
  } else {
    input.type = 'password';
    btn.textContent = '\u{1F441}\u200D\u{1F5E8}';
  }
}

document.addEventListener('DOMContentLoaded', function() {
  loadTheme();
  closeModalOnEsc();
  var nav = document.querySelector('.nav-inner');
  if (nav) {
    var hb = nav.querySelector('.hamburger');
    var nl = nav.querySelector('.nav-links');
    if (hb && nl) {
      hb.addEventListener('click', function() { nl.classList.toggle('open'); });
    }
  }
});
