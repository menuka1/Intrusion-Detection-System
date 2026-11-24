/* Shared helpers: API client (CSRF aware), formatting, toasts, modals, layout wiring. */
const App = (() => {
  const csrf = () => document.querySelector('meta[name="csrf-token"]')?.content || '';
  let token = csrf();

  const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

  async function api(url, { method = 'GET', body, form } = {}) {
    const opts = { method, headers: { Accept: 'application/json' }, credentials: 'same-origin' };
    if (method !== 'GET') opts.headers['X-CSRF-Token'] = token;
    if (form) opts.body = form;
    else if (body !== undefined) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
    let res;
    try { res = await fetch(url, opts); } catch (e) { throw new Error('Network error: the server is unreachable.'); }
    let payload = null;
    try { payload = await res.json(); } catch (e) { /* non-JSON */ }
    if (res.status === 401 && !url.includes('/auth/login')) { location.href = '/login'; throw new Error('Session expired.'); }
    if (!res.ok || !payload || payload.ok === false) {
      const err = new Error(payload?.error || `Request failed (${res.status})`);
      err.status = res.status;
      throw err;
    }
    return payload.data;
  }

  function toast(msg, type = '') {
    const box = $('#toasts'); if (!box) return;
    const el = document.createElement('div');
    el.className = 'toast ' + type; el.textContent = msg; box.appendChild(el);
    setTimeout(() => el.remove(), type === 'error' ? 7000 : 3500);
  }

  const fmtInt = (n) => (n === null || n === undefined) ? '–' : Number(n).toLocaleString();
  const fmtPct = (x, d = 2) => (x === null || x === undefined) ? '–' : (x * 100).toFixed(d) + '%';
  const fmtNum = (x, d = 4) => (x === null || x === undefined) ? '–' : Number(x).toFixed(d);
  const fmtBytes = (n) => { n = Number(n || 0); const u = ['B', 'KB', 'MB', 'GB']; let i = 0; while (n >= 1024 && i < 3) { n /= 1024; i++; } return n.toFixed(i ? 1 : 0) + ' ' + u[i]; };
  const fmtTime = (iso) => { if (!iso) return '–'; const d = new Date(iso); return isNaN(d) ? esc(iso) : d.toLocaleString([], { year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' }); };
  const fmtClock = (iso) => { if (!iso) return '–'; const d = new Date(iso); return isNaN(d) ? esc(iso) : d.toLocaleTimeString(); };
  const badge = (text, cls) => `<span class="badge ${esc(cls ?? text)}">${esc(text)}</span>`;
  const algoName = (a) => ({ decision_tree: 'Decision Tree', random_forest: 'Random Forest', ann: 'Artificial Neural Network' }[a] || a);
  const isAdmin = () => document.body.dataset.role === 'admin';

  function modal(title, html) {
    const wrap = document.createElement('div');
    wrap.className = 'modal';
    wrap.innerHTML = `<div class="modal-box" role="dialog" aria-modal="true"><div class="modal-head"><h2>${esc(title)}</h2><button class="icon-btn" aria-label="Close">✕</button></div><div class="modal-body">${html}</div></div>`;
    const close = () => wrap.remove();
    wrap.addEventListener('click', (e) => { if (e.target === wrap) close(); });
    $('.icon-btn', wrap).addEventListener('click', close);
    document.addEventListener('keydown', function onKey(e) { if (e.key === 'Escape') { close(); document.removeEventListener('keydown', onKey); } });
    document.body.appendChild(wrap);
    return { el: wrap, body: $('.modal-body', wrap), close };
  }

  function confirmBox(message) { return window.confirm(message); }

  function debounce(fn, ms = 300) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; }

  function pager(el, { page, per_page, total }, onPage) {
    const pages = Math.max(1, Math.ceil(total / per_page));
    el.innerHTML = `<span>${fmtInt(total)} records</span><button class="btn btn-sm" data-p="${page - 1}" ${page <= 1 ? 'disabled' : ''}>Previous</button><span>Page ${page} of ${pages}</span><button class="btn btn-sm" data-p="${page + 1}" ${page >= pages ? 'disabled' : ''}>Next</button>`;
    $$('button', el).forEach((b) => b.addEventListener('click', () => onPage(Number(b.dataset.p))));
  }

  function setPill(id, cls, text) { const el = $(id); if (!el) return; el.className = 'pill ' + cls; el.innerHTML = `<i class="dot"></i>${esc(text)}`; }

  async function refreshStatusPills() {
    try {
      const s = await api('/api/system/status');
      setPill('#pillDb', s.database.ok ? 'ok' : 'bad', s.database.ok ? 'DB connected' : 'DB offline');
      const m = s.ml_engine;
      setPill('#pillModel', m.state === 'ready' ? 'ok' : (m.state === 'error' ? 'bad' : 'warn'),
        m.state === 'ready' ? `${algoName(m.model)} v${m.version}` : m.label);
      const r = $('#pillReplay'); if (r) r.hidden = !s.replay.running;
      return s;
    } catch (e) { setPill('#pillDb', 'bad', 'Unreachable'); }
  }

  async function refreshAlertBadge() {
    try {
      const d = await api('/api/alerts?status=Open&per_page=1');
      const b = $('#navAlertBadge'); if (!b) return;
      b.hidden = !d.total; b.textContent = d.total > 99 ? '99+' : d.total;
    } catch (e) { /* ignore */ }
  }

  function wireLayout() {
    $('#menuBtn')?.addEventListener('click', () => document.body.classList.toggle('nav-open'));
    $('#scrim')?.addEventListener('click', () => document.body.classList.remove('nav-open'));
    $('#logoutBtn')?.addEventListener('click', async () => {
      try { await api('/api/auth/logout', { method: 'POST', body: {} }); } catch (e) { /* ignore */ }
      location.href = '/login';
    });
    if (document.body.classList.contains('app')) {
      refreshStatusPills(); refreshAlertBadge();
      setInterval(refreshStatusPills, 10000); setInterval(refreshAlertBadge, 10000);
    }
  }

  document.addEventListener('DOMContentLoaded', wireLayout);
  return { api, esc, $, $$, toast, fmtInt, fmtPct, fmtNum, fmtBytes, fmtTime, fmtClock, badge, algoName, isAdmin, modal,
    confirmBox, debounce, pager, setToken: (t) => { token = t; } };
})();
