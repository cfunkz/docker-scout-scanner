// Shared helpers for the dashboard and the admin panel.
// No framework, no build step; every DOM node is created with textContent so
// advisory text from vulnerability feeds can never inject markup.
'use strict';

export const state = { me: null, csrf: '' };

// ---------- DOM ----------
export function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v === null || v === undefined || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k === 'text') el.textContent = v;
      else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else if (k === 'style' && typeof v === 'object') Object.assign(el.style, v);
      else if (k === 'dataset') Object.assign(el.dataset, v);
      else if (k === 'href') el.setAttribute('href', safeHref(v));
      else el.setAttribute(k, v === true ? '' : v);
    }
  }
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

// Only allow http(s), relative and hash links (advisory URLs come from feeds).
export function safeHref(u) {
  const s = String(u || '');
  if (s.startsWith('#') || s.startsWith('api/') || s.startsWith('./')) return s;
  try {
    const p = new URL(s, location.href);
    if (p.protocol === 'https:' || p.protocol === 'http:') return p.href;
  } catch (_) { /* fallthrough */ }
  return '#';
}

export const $ = (sel, root = document) => root.querySelector(sel);
export function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); return el; }
export function mount(el, ...nodes) { clear(el); el.append(...nodes.flat(Infinity).filter((n) => n !== null && n !== undefined && n !== false)); return el; }

// ---------- API ----------
export class ApiError extends Error {
  constructor(status, msg) { super(msg); this.status = status; }
}

export async function api(path, { method = 'GET', body, raw = false } = {}) {
  const opts = { method, credentials: 'same-origin', headers: { 'Accept': 'application/json' } };
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  if (method !== 'GET' && state.csrf) opts.headers['X-CSRF-Token'] = state.csrf;
  const res = await fetch('api/' + path.replace(/^\//, ''), opts);
  if (raw) return res;
  let data = null;
  const text = await res.text();
  if (text) { try { data = JSON.parse(text); } catch (_) { data = { error: text.slice(0, 200) }; } }
  if (!res.ok) {
    const err = new ApiError(res.status, (data && data.error) || res.statusText);
    if (res.status === 401 && onUnauthorized) onUnauthorized();
    throw err;
  }
  return data;
}

let onUnauthorized = null;
export function setUnauthorizedHandler(fn) { onUnauthorized = fn; }

// ---------- formatting ----------
export const SEVS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
export const sevClass = (s) => 'sev sev-' + String(s || 'unknown').toLowerCase();
const SEV_LABEL = { CRITICAL: 'CRIT', HIGH: 'HIGH', MEDIUM: 'MED', LOW: 'LOW', UNKNOWN: 'UNK' };
export const sevBadge = (s) => h('span', { class: sevClass(s), title: s }, SEV_LABEL[s] || 'UNK');

export function fmtTime(ts) {
  if (!ts) return '—';
  const d = new Date(ts * 1000);
  return d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

export function ago(ts) {
  if (!ts) return 'never';
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 60) return 'just now';
  if (s < 3600) return Math.floor(s / 60) + ' min ago';
  if (s < 86400) return Math.floor(s / 3600) + ' h ago';
  return Math.floor(s / 86400) + ' d ago';
}

export function bytes(n) {
  if (!n) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(u.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
  return (n / Math.pow(1024, i)).toFixed(i ? 1 : 0) + ' ' + u[i];
}

export const pct = (x) => (x * 100).toFixed(x >= 0.1 ? 0 : x >= 0.01 ? 1 : 2) + '%';
export const shortId = (id) => String(id || '').replace('sha256:', '').slice(0, 12);

export function riskBadge(r) {
  const cls = r >= 70 ? 'risk risk-hi' : r >= 45 ? 'risk risk-md' : 'risk risk-lo';
  return h('span', { class: cls, title: 'Risk score (0–100): severity + EPSS + KEV + fix + in use' }, Number(r || 0).toFixed(0));
}

export function counts(sc) {
  if (!sc) return h('span', { class: 'muted' }, 'not scanned');
  if (sc.status === 'failed') return h('span', { class: 'chip chip-err', title: sc.error }, 'scan failed');
  return h('span', { class: 'counts' },
    ...[['critical', 'C'], ['high', 'H'], ['medium', 'M'], ['low', 'L']].map(([k, l]) =>
      h('span', { class: 'cnt cnt-' + k + (sc[k] ? '' : ' zero'), title: sc[k] + ' ' + k }, l + ' ' + sc[k])));
}

// ---------- prefs (stored in the browser only) ----------
const PREF_KEY = 'dss.prefs';
export const defaultPrefs = { theme: 'auto', hideUnfixed: false, showIgnored: false, pageSize: 100, minSeverity: 'UNKNOWN', compact: false, refreshSec: 30 };
export function prefs() {
  try { return { ...defaultPrefs, ...JSON.parse(localStorage.getItem(PREF_KEY) || '{}') }; } catch (_) { return { ...defaultPrefs }; }
}
export function savePrefs(p) { localStorage.setItem(PREF_KEY, JSON.stringify(p)); applyPrefs(); }
export function applyPrefs() {
  const p = prefs();
  const dark = p.theme === 'dark' || (p.theme === 'auto' && matchMedia('(prefers-color-scheme: dark)').matches);
  document.documentElement.dataset.theme = dark ? 'dark' : 'light';
  document.documentElement.classList.toggle('compact', !!p.compact);
}

// ---------- toasts & modals ----------
export function toast(msg, kind = 'ok') {
  let box = $('#toasts');
  if (!box) { box = h('div', { id: 'toasts', role: 'status', 'aria-live': 'polite' }); document.body.append(box); }
  const t = h('div', { class: 'toast toast-' + kind }, msg);
  box.append(t);
  setTimeout(() => t.remove(), kind === 'err' ? 7000 : 3500);
}

export function modal(title, body, actions = []) {
  const close = () => wrap.remove();
  const wrap = h('div', { class: 'modal-wrap', onclick: (e) => { if (e.target === wrap) close(); } },
    h('div', { class: 'modal', role: 'dialog', 'aria-modal': 'true', 'aria-label': title },
      h('div', { class: 'modal-head' }, h('h3', null, title), h('button', { class: 'btn ghost', onclick: close, 'aria-label': 'Close' }, '✕')),
      h('div', { class: 'modal-body' }, body),
      actions.length ? h('div', { class: 'modal-foot' }, actions.map((a) => h('button', { class: 'btn ' + (a.kind || ''), onclick: () => a.run(close) }, a.label))) : null));
  document.addEventListener('keydown', function esc(e) { if (e.key === 'Escape') { close(); document.removeEventListener('keydown', esc); } });
  document.body.append(wrap);
  const f = wrap.querySelector('input,select,textarea,button.primary');
  if (f) f.focus();
  return close;
}

// ---------- tiny SVG charts ----------
const SVGNS = 'http://www.w3.org/2000/svg';
function s(tag, attrs) { const e = document.createElementNS(SVGNS, tag); for (const [k, v] of Object.entries(attrs || {})) e.setAttribute(k, v); return e; }

// Stacked area-ish trend: one line per series.
export function lineChart(rows, series, { height = 240 } = {}) {
  const wrap = h('div', { class: 'chart' });
  if (!rows.length) { wrap.append(h('div', { class: 'muted pad' }, 'No history yet: the trend fills in day by day.')); return wrap; }
  const W = 1100, H = height, P = 34;
  const maxY = Math.max(1, ...rows.flatMap((r) => series.map((sr) => r[sr.key] || 0)));
  const x = (i) => P + (rows.length === 1 ? (W - 2 * P) / 2 : (i * (W - 2 * P)) / (rows.length - 1));
  const y = (v) => H - P + 6 - (v / maxY) * (H - P - 10);
  const svg = s('svg', { viewBox: `0 0 ${W} ${H}`, class: 'svgchart', role: 'img', 'aria-label': 'Trend chart' });
  for (let g = 0; g <= 4; g++) {
    const v = Math.round((maxY * g) / 4);
    svg.append(s('line', { x1: P, x2: W - P, y1: y(v), y2: y(v), class: 'grid' }));
    const t = s('text', { x: 2, y: y(v) + 4, class: 'axis' }); t.textContent = v; svg.append(t);
  }
  for (const sr of series) {
    const d = rows.map((r, i) => (i ? 'L' : 'M') + x(i).toFixed(1) + ' ' + y(r[sr.key] || 0).toFixed(1)).join(' ');
    svg.append(s('path', { d, class: 'line ' + sr.cls, fill: 'none' }));
    rows.forEach((r, i) => {
      const c = s('circle', { cx: x(i), cy: y(r[sr.key] || 0), r: 2.5, class: 'dot ' + sr.cls });
      const tt = s('title', {}); tt.textContent = `${r.day}: ${r[sr.key] || 0} ${sr.label}`; c.append(tt);
      svg.append(c);
    });
  }
  const first = s('text', { x: P, y: H - 4, class: 'axis' }); first.textContent = rows[0].day; svg.append(first);
  const last = s('text', { x: W - P, y: H - 4, class: 'axis', 'text-anchor': 'end' }); last.textContent = rows[rows.length - 1].day; svg.append(last);
  wrap.append(svg, h('div', { class: 'legend' }, series.map((sr) => h('span', { class: 'lg ' + sr.cls }, sr.label))));
  return wrap;
}

export function sevBar(sc) {
  const total = SEVS.reduce((a, k) => a + (sc[k.toLowerCase()] || 0), 0);
  const bar = h('div', { class: 'sevbar', role: 'img', 'aria-label': 'Severity distribution' });
  if (!total) { bar.append(h('span', { class: 'seg seg-none', style: { width: '100%' } })); return bar; }
  for (const k of SEVS) {
    const n = sc[k.toLowerCase()] || 0;
    if (n) bar.append(h('span', { class: 'seg seg-' + k.toLowerCase(), style: { width: (100 * n) / total + '%' }, title: `${n} ${k.toLowerCase()}` }));
  }
  return bar;
}

// ---------- auth screens ----------
export async function loadMe() {
  const me = await api('me');
  state.me = me;
  state.csrf = me.csrf || '';
  return me;
}

export function loginView(root, { title, subtitle, onDone }) {
  const err = h('div', { class: 'form-err', role: 'alert' });
  const user = h('input', { name: 'username', autocomplete: 'username', required: true, autofocus: true, maxlength: 64 });
  const pass = h('input', { name: 'password', type: 'password', autocomplete: 'current-password', required: true, maxlength: 128 });
  const btn = h('button', { class: 'btn primary', type: 'submit' }, 'Sign in');
  const form = h('form', {
    class: 'card login', onsubmit: async (e) => {
      e.preventDefault(); err.textContent = ''; btn.disabled = true;
      try {
        const r = await api('auth/login', { method: 'POST', body: { username: user.value, password: pass.value } });
        state.csrf = r.csrf;
        await onDone();
      } catch (ex) { err.textContent = ex.message; pass.value = ''; pass.focus(); } finally { btn.disabled = false; }
    },
  },
    h('div', { class: 'brand big' }, h('span', { class: 'logo' }, '◆'), title),
    h('p', { class: 'muted' }, subtitle),
    h('label', null, 'Username', user),
    h('label', null, 'Password', pass),
    err, btn);
  mount(root, h('div', { class: 'center' }, form));
}

export function changePasswordForm({ forced, onDone }) {
  const err = h('div', { class: 'form-err', role: 'alert' });
  const cur = h('input', { type: 'password', autocomplete: 'current-password', required: true });
  const nw = h('input', { type: 'password', autocomplete: 'new-password', required: true, minlength: 12, maxlength: 72 });
  const nw2 = h('input', { type: 'password', autocomplete: 'new-password', required: true, minlength: 12, maxlength: 72 });
  return h('form', {
    class: 'card form', onsubmit: async (e) => {
      e.preventDefault(); err.textContent = '';
      if (nw.value !== nw2.value) { err.textContent = 'The new passwords do not match.'; return; }
      try {
        await api('me/password', { method: 'POST', body: { current: cur.value, new: nw.value } });
        toast('Password changed. Other sessions were signed out.');
        cur.value = nw.value = nw2.value = '';
        onDone && onDone();
      } catch (ex) { err.textContent = ex.message; }
    },
  },
    h('h3', null, forced ? 'Choose a new password' : 'Change password'),
    forced ? h('p', { class: 'muted' }, 'This account uses a temporary password. Set your own (12+ characters) to continue.') : null,
    h('label', null, 'Current password', cur),
    h('label', null, 'New password (12+ characters)', nw),
    h('label', null, 'Repeat new password', nw2),
    err, h('button', { class: 'btn primary', type: 'submit' }, 'Save password'));
}

export async function logout() {
  try { await api('auth/logout', { method: 'POST' }); } catch (_) { /* ignore */ }
  location.hash = '';
  location.reload();
}

// Sortable, filterable table with paging. cols: [{key,label,render,sort,cls}]
export function dataTable(rows, cols, { pageSize = 100, empty = 'Nothing here.', rowClass, onRow, initialSort } = {}) {
  let sortKey = initialSort ? initialSort.key : null, sortDir = initialSort ? initialSort.dir : -1, page = 0;
  const wrap = h('div', { class: 'tablewrap' });
  function render() {
    let data = rows.slice();
    if (sortKey) {
      const c = cols.find((c) => c.key === sortKey);
      const val = c.sort || ((r) => r[sortKey]);
      data.sort((a, b) => { const x = val(a), y = val(b); return (x > y ? 1 : x < y ? -1 : 0) * sortDir; });
    }
    const pages = Math.max(1, Math.ceil(data.length / pageSize));
    page = Math.min(page, pages - 1);
    const slice = data.slice(page * pageSize, (page + 1) * pageSize);
    const thead = h('thead', null, h('tr', null, cols.map((c) => h('th', {
      class: (c.cls || '') + (c.nosort ? '' : ' sortable') + (sortKey === c.key ? (sortDir > 0 ? ' asc' : ' desc') : ''),
      scope: 'col',
      onclick: c.nosort ? null : () => { if (sortKey === c.key) sortDir = -sortDir; else { sortKey = c.key; sortDir = -1; } render(); },
    }, c.label))));
    const tbody = h('tbody');
    if (!slice.length) tbody.append(h('tr', null, h('td', { colspan: cols.length, class: 'muted pad center-text' }, empty)));
    for (const r of slice) {
      const tr = h('tr', { class: (rowClass ? rowClass(r) : '') + (onRow ? ' clickable' : '') }, cols.map((c) => h('td', { class: c.cls || '' }, c.render ? c.render(r) : (r[c.key] ?? ''))));
      if (onRow) {
        tr.tabIndex = 0;
        tr.addEventListener('click', (e) => { if (!e.target.closest('a,button,input')) onRow(r, tr, e); });
        tr.addEventListener('keydown', (e) => { if (e.key === 'Enter') onRow(r, tr, e); });
      }
      tbody.append(tr);
    }
    const pager = pages > 1 ? h('div', { class: 'pager' },
      h('button', { class: 'btn ghost', disabled: page === 0, onclick: () => { page--; render(); } }, '‹ Prev'),
      h('span', { class: 'muted' }, `Page ${page + 1} of ${pages} · ${data.length} rows`),
      h('button', { class: 'btn ghost', disabled: page >= pages - 1, onclick: () => { page++; render(); } }, 'Next ›')) : h('div', { class: 'pager muted' }, `${data.length} rows`);
    mount(wrap, h('table', { class: 'tbl' }, thead, tbody), pager);
  }
  render();
  wrap.update = (newRows) => { rows = newRows; page = 0; render(); };
  return wrap;
}

export function debounce(fn, ms = 200) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; }
