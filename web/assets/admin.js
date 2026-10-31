// Admin panel. Served only by the localhost-bound nginx server.
'use strict';
import {
  h, $, mount, api, state, toast, modal, fmtTime, ago, bytes, shortId, counts, applyPrefs, loadMe, loginView,
  changePasswordForm, logout, dataTable, setUnauthorizedHandler,
} from './common.js';

const root = $('#app');
let timer = null;
applyPrefs();
setUnauthorizedHandler(() => boot());

async function boot() {
  try {
    const me = await loadMe();
    if (!me.user) { loginView(root, { title: 'Scanner admin', subtitle: 'Admin accounts only. This panel is reachable from this machine only.', onDone: boot }); return; }
    if (me.must_change) { mount(root, h('div', { class: 'center' }, changePasswordForm({ forced: true, onDone: boot }))); return; }
    shell();
    window.addEventListener('hashchange', route);
    route();
  } catch (e) {
    mount(root, h('div', { class: 'center' }, h('div', { class: 'card err' }, e.message)));
  }
}

function shell() {
  const nav = [['#/', 'Status'], ['#/scans', 'Scans'], ['#/settings', 'Settings'], ['#/rules', 'Accepted risks'], ['#/users', 'Users'], ['#/audit', 'Audit log']];
  mount(root,
    h('header', { class: 'top admin' },
      h('a', { class: 'brand', href: '#/' }, h('span', { class: 'logo' }, '◆'), 'Scanner admin'),
      h('nav', { class: 'tabs', 'aria-label': 'Admin' }, nav.map(([href, l]) => h('a', { href, dataset: { nav: href } }, l))),
      h('div', { class: 'spacer' }),
      h('span', { class: 'chip chip-warn', title: 'This panel only listens on localhost' }, 'localhost'),
      h('div', { class: 'user' }, h('span', { class: 'muted' }, state.me.user), h('button', { class: 'btn ghost', onclick: logout }, 'Sign out'))),
    h('main', { id: 'view' }));
}

function route() {
  clearInterval(timer);
  const path = (location.hash || '#/').slice(1).split('?')[0];
  document.querySelectorAll('[data-nav]').forEach((a) => a.classList.toggle('active', a.dataset.nav.slice(1) === path));
  const view = $('#view');
  const fn = { '/': status, '/scans': scans, '/settings': settings, '/rules': rules, '/users': users, '/audit': audit }[path] || status;
  fn(view).catch((e) => mount(view, h('div', { class: 'card err' }, e.message)));
}

const post = (path, body = {}) => api(path, { method: 'POST', body });
async function act(label, fn) {
  try { const r = await fn(); toast(label + (r && r.result ? ': ' + r.result : '')); return r; } catch (e) { toast(e.message, 'err'); return null; }
}

// ---------- Status ----------
async function status(view) {
  const render = async () => {
    const s = await api('admin/status');
    const db = (d) => h('div', { class: 'card' },
      h('h3', null, d.engine === 'trivy' ? 'Trivy' : 'Grype', ' ', h('span', { class: 'muted small' }, d.version || '')),
      d.error && !d.ready ? h('p', { class: 'muted' }, d.error) : null,
      h('dl', { class: 'kv' },
        h('dt', null, 'Database'), h('dd', null, d.ready ? h('span', { class: 'ok' }, 'ready') : h('span', { class: 'warn' }, 'not downloaded')),
        h('dt', null, 'DB built'), h('dd', null, d.db_built && !d.db_built.startsWith('0001') ? ago(Date.parse(d.db_built) / 1000) : '—'),
        h('dt', null, 'Downloaded'), h('dd', null, d.db_updated && !d.db_updated.startsWith('0001') ? ago(Date.parse(d.db_updated) / 1000) : '—')));
    mount(view,
      s.initial_password_pending ? h('div', { class: 'banner warn' }, 'The generated first-run password file still exists in the data volume. It is removed when you change the admin password.') : null,
      !s.docker_ok ? h('div', { class: 'banner err' }, 'Docker API unreachable: ' + (s.docker_error || 'unknown error')) : null,
      h('div', { class: 'toolbar' }, h('h2', null, 'Status'), h('div', { class: 'spacer' }),
        h('button', { class: 'btn primary', onclick: () => act('Queued', () => post('admin/scan', { all: true })).then(render) }, 'Scan all now'),
        h('button', { class: 'btn', title: 'Re-read every image from Docker instead of using cached SBOMs', onclick: () => act('Queued full rescan', () => post('admin/scan', { all: true, force: true })).then(render) }, 'Full rescan'),
        h('button', { class: 'btn', onclick: () => act('DB update started', () => post('admin/db/update')) }, 'Update vuln DBs'),
        h('button', { class: 'btn', onclick: () => act('Feed refresh started', () => post('admin/intel/update')) }, 'Refresh EPSS/KEV')),
      h('div', { class: 'grid3' }, db(s.trivy), db(s.grype),
        h('div', { class: 'card' }, h('h3', null, 'Threat intel'), h('dl', { class: 'kv' },
          h('dt', null, 'CISA KEV'), h('dd', null, s.kev_entries + ' CVEs'),
          h('dt', null, 'EPSS'), h('dd', null, s.epss_entries.toLocaleString() + ' scores')))),
      h('div', { class: 'grid2' },
        h('div', { class: 'card' }, h('h3', null, 'Background tasks'), h('table', { class: 'tbl' }, h('tbody', null, s.tasks.map((t) => h('tr', null,
          h('td', { class: 'nowrap' }, t.name), h('td', { class: 'nowrap' }, t.running ? h('span', { class: 'chip chip-run' }, 'running') : t.last_error ? h('span', { class: 'chip chip-err', title: t.last_error }, 'failed') : t.last_ok ? h('span', { class: 'ok' }, 'ok') : h('span', { class: 'muted' }, 'never')),
          h('td', { class: 'muted small nowrap' }, t.last_run ? ago(t.last_run) : ''), h('td', { class: 'small' }, t.last_error || t.detail || '')))))),
        h('div', { class: 'card' }, h('h3', null, 'Process'), h('dl', { class: 'kv' },
          h('dt', null, 'Queue'), h('dd', null, `${s.running} running, ${s.queue} queued`),
          h('dt', null, 'Uptime'), h('dd', null, Math.floor(s.uptime_s / 3600) + ' h ' + Math.floor((s.uptime_s % 3600) / 60) + ' min'),
          h('dt', null, 'Database'), h('dd', null, bytes(s.db_bytes)),
          h('dt', null, 'Heap'), h('dd', null, bytes(s.heap_bytes)),
          h('dt', null, 'Runtime'), h('dd', null, s.go)),
          h('h4', null, 'Maintenance'),
          h('div', { class: 'btnrow' },
            purge('absent', 'Forget removed images'), purge('history', 'Prune scan history'), purge('sboms', 'Drop cached SBOMs'), purge('vacuum', 'Compact DB')),
          h('p', { class: 'muted small' }, 'Prometheus metrics: ', h('code', null, '/metrics'), ' on this port (admin session, or a bearer token if METRICS_TOKEN is set).'))));
  };
  const purge = (what, label) => h('button', { class: 'btn small', onclick: () => modal(label + '?', h('p', null, 'This cannot be undone.'), [{ label: 'Cancel', kind: 'ghost', run: (c) => c() }, { label, kind: 'danger', run: async (c) => { c(); await act(label, () => post('admin/purge', { what })); render(); } }]) }, label);
  await render();
  timer = setInterval(() => { if (!document.hidden && !$('.modal-wrap')) render().catch(() => {}); }, 10000);
}

// ---------- Scans ----------
async function scans(view) {
  const render = async () => {
    const [jobs, images] = await Promise.all([api('admin/jobs'), api('images')]);
    const scanBtn = (im, force) => h('button', { class: 'btn small' + (force ? ' ghost' : ''), onclick: () => act('Queued ' + (im.repo_tags[0] || shortId(im.id)), () => post('admin/scan', { image_id: im.id, force })).then(render) }, force ? 'Re-read' : 'Scan');
    mount(view,
      h('div', { class: 'toolbar' }, h('h2', null, 'Scans'), h('div', { class: 'spacer' }), h('button', { class: 'btn', onclick: () => act('Synced', () => post('admin/sync')).then(render) }, 'Sync with Docker')),
      h('h3', null, 'Jobs'),
      h('div', { class: 'card flush' }, dataTable(jobs, [
        { key: 'id', label: '#', cls: 'num' }, { key: 'name', label: 'Image' }, { key: 'trigger', label: 'Trigger' },
        { key: 'state', label: 'State', render: (j) => h('span', { class: 'chip ' + ({ running: 'chip-run', failed: 'chip-err', done: 'chip-ok' }[j.state] || ''), title: j.error || '' }, j.state + (j.phase ? ': ' + j.phase : '')) },
        { key: 'queued', label: 'Queued', render: (j) => ago(j.queued) },
        { key: 'took', label: 'Took', cls: 'num', sort: (j) => (j.finished ? j.finished - j.started : 0), render: (j) => (j.finished && j.started ? (j.finished - j.started) + ' s' : '') },
        { key: 'error', label: 'Error', render: (j) => h('span', { class: 'small err-text' }, j.error || '') },
      ], { pageSize: 25, empty: 'No jobs since start.' })),
      h('h3', null, 'Images'),
      h('div', { class: 'card flush' }, dataTable(images, [
        { key: 'name', label: 'Image', sort: (r) => r.repo_tags[0] || '', render: (r) => h('span', null, r.repo_tags[0] || '<untagged> ' + shortId(r.id), r.excluded ? h('span', { class: 'chip' }, 'excluded') : null) },
        { key: 'counts', label: 'Findings', nosort: true, render: (r) => counts(r.scan) },
        { key: 'scanned', label: 'Scanned', sort: (r) => (r.scan ? r.scan.finished_at : 0), render: (r) => (r.scan ? ago(r.scan.finished_at) : 'never') },
        { key: 'act', label: '', nosort: true, render: (r) => h('span', { class: 'btnrow' }, scanBtn(r, false), scanBtn(r, true)) },
      ], { pageSize: 50 })));
  };
  await render();
  timer = setInterval(() => { if (!document.hidden) render().catch(() => {}); }, 5000);
}

// ---------- Settings ----------
async function settings(view) {
  const s = await api('admin/settings');
  const status = await api('admin/status');
  const grypeOK = !status.grype.error || status.grype.error !== 'grype not installed';
  const num = (name, label, min, max, help) => h('label', null, label, h('input', { type: 'number', name, value: s[name], min, max, required: true }), help ? h('small', { class: 'muted' }, help) : null);
  const chk = (name, label, help) => h('label', { class: 'check' }, h('input', { type: 'checkbox', name, checked: !!s[name] }), h('span', null, label, help ? h('small', { class: 'muted block' }, help) : null));
  const txt = (name, label, help, attrs = {}) => h('label', null, label, h('input', { name, value: s[name] || '', ...attrs }), help ? h('small', { class: 'muted' }, help) : null);
  const sev = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  const form = h('form', {
    class: 'settings', onsubmit: async (e) => {
      e.preventDefault();
      const f = e.target;
      const body = {
        ...s,
        engine: f.engine.value, concurrency: +f.concurrency.value, scan_interval_h: +f.scan_interval_h.value,
        watch_events: f.watch_events.checked, scan_on_start: f.scan_on_start.checked, only_in_use: f.only_in_use.checked,
        exclude: f.exclude.value.split('\n').map((x) => x.trim()).filter(Boolean),
        secret_scanning: f.secret_scanning.checked, scan_timeout_min: +f.scan_timeout_min.value, db_update_h: +f.db_update_h.value,
        offline: f.offline.checked, history_keep: +f.history_keep.value,
        epss_enabled: f.epss_enabled.checked, kev_enabled: f.kev_enabled.checked, epss_url: f.epss_url.value.trim(), kev_url: f.kev_url.value.trim(),
        webhook_url: f.webhook_url.value.trim(), webhook_format: f.webhook_format.value,
        notify_severities: sev.filter((x) => f['sev_' + x].checked), notify_kev: f.notify_kev.checked, notify_min_epss: +f.notify_min_epss.value / 100,
        session_hours: +f.session_hours.value, require_login: f.require_login.checked, lockout_attempts: +f.lockout_attempts.value, lockout_minutes: +f.lockout_minutes.value,
      };
      if (!body.require_login && !confirm('Anyone who can reach the dashboard port will see all reports without signing in. Continue?')) return;
      const r = await act('Settings saved', () => api('admin/settings', { method: 'PUT', body }));
      if (r) Object.assign(s, r);
    },
  },
    h('div', { class: 'grid2' },
      h('fieldset', { class: 'card' }, h('legend', null, 'Scanning'),
        h('label', null, 'Engine', h('select', { name: 'engine' },
          h('option', { value: 'trivy', selected: s.engine === 'trivy' }, 'Trivy'),
          h('option', { value: 'grype', selected: s.engine === 'grype', disabled: !grypeOK }, 'Grype'),
          h('option', { value: 'both', selected: s.engine === 'both', disabled: !grypeOK }, 'Both (merge and cross-check)')),
        h('small', { class: 'muted' }, 'Both runs the two matchers on the same SBOM in parallel; findings seen by both get a 2× mark.')),
        num('concurrency', 'Parallel scans', 1, 16),
        num('scan_interval_h', 'Full rescan every (hours, 0 = off)', 0, 720, 'Images are also re-matched automatically after every DB update.'),
        num('scan_timeout_min', 'Per-image timeout (minutes)', 1, 240),
        chk('watch_events', 'Scan new images as they appear', 'Listens to Docker events (pull, build, tag).'),
        chk('scan_on_start', 'Scan unscanned images at start-up'),
        chk('only_in_use', 'Only scan images used by containers'),
        chk('secret_scanning', 'Look for secrets baked into layers', 'Slower: reads every file. Runs only when an image changes.'),
        h('label', null, 'Exclude images (one glob per line)', h('textarea', { name: 'exclude', rows: 4, placeholder: 'e.g.\nk8s.gcr.io/*\n<untagged>' }, (s.exclude || []).join('\n')))),
      h('div', null,
        h('fieldset', { class: 'card' }, h('legend', null, 'Databases and threat intel'),
          num('db_update_h', 'Update vulnerability DBs every (hours)', 1, 168),
          num('history_keep', 'Scans per image to keep in full', 1, 1000, 'Older scans keep their counts for trend charts.'),
          chk('offline', 'Offline / air-gapped mode', 'Never download anything. Mount DBs into the cache volume yourself.'),
          chk('epss_enabled', 'Use EPSS exploit probability'), chk('kev_enabled', 'Use CISA Known Exploited Vulnerabilities'),
          txt('epss_url', 'EPSS feed URL', null, { type: 'url' }), txt('kev_url', 'KEV feed URL', null, { type: 'url' })),
        h('fieldset', { class: 'card' }, h('legend', null, 'Notifications'),
          txt('webhook_url', 'Webhook URL', 'Slack, Discord, ntfy or any JSON endpoint. Leave empty to disable.', { type: 'text', autocomplete: 'off', spellcheck: 'false' }),
          h('label', null, 'Format', h('select', { name: 'webhook_format' }, ['generic', 'slack', 'discord', 'ntfy'].map((f) => h('option', { value: f, selected: s.webhook_format === f }, f)))),
          h('div', { class: 'label' }, 'Alert on new findings with severity', h('div', { class: 'row' }, sev.map((x) => h('label', { class: 'check' }, h('input', { type: 'checkbox', name: 'sev_' + x, checked: (s.notify_severities || []).includes(x) }), x)))),
          chk('notify_kev', 'Always alert on new known-exploited findings'),
          h('label', null, 'Also alert when EPSS ≥ (%, 0 = off)', h('input', { type: 'number', name: 'notify_min_epss', min: 0, max: 100, step: 0.1, value: +(s.notify_min_epss * 100).toFixed(1) })),
          h('button', { class: 'btn small', type: 'button', onclick: () => act('Test sent', () => post('admin/notify/test')) }, 'Send test (saved URL)')),
        h('fieldset', { class: 'card' }, h('legend', null, 'Access'),
          chk('require_login', 'Require sign-in for the dashboard', 'Keep this on if the dashboard is reachable from your LAN or through a reverse proxy.'),
          num('session_hours', 'Session lifetime (hours)', 1, 720, 'Admin sessions are capped at 8 hours.'),
          num('lockout_attempts', 'Lock account after failed sign-ins', 1, 100),
          num('lockout_minutes', 'Lockout duration (minutes)', 1, 1440)))),
    h('div', { class: 'btnrow sticky' }, h('button', { class: 'btn primary', type: 'submit' }, 'Save settings')));
  mount(view, h('h2', null, 'Settings'), form);
}

// ---------- Accepted risks ----------
async function rules(view) {
  const list = await api('ignores');
  const form = h('form', {
    class: 'card form', onsubmit: async (e) => {
      e.preventDefault();
      const f = e.target;
      const exp = f.expires.value ? Math.floor(new Date(f.expires.value + 'T23:59:59').getTime() / 1000) : 0;
      const r = await act('Rule added; images are being re-matched', () => post('admin/ignores', {
        vuln_id: f.vuln_id.value.trim(), pkg: f.pkg.value.trim() || '*', image: f.image.value.trim() || '*',
        status: f.status.value, justification: f.justification.value, reason: f.reason.value.trim(), expires_at: exp,
      }));
      if (r) rules(view);
    },
  },
    h('h3', null, 'Accept a risk'),
    h('p', { class: 'muted small' }, 'Matching findings are hidden from counts, alerts and risk scores, but stay visible under "Show accepted". Rules export as OpenVEX for use with trivy --vex or grype --vex in CI.'),
    h('div', { class: 'grid3' },
      h('label', null, 'Vulnerability id', h('input', { name: 'vuln_id', required: true, placeholder: 'CVE-2024-1234 or *' })),
      h('label', null, 'Package (glob)', h('input', { name: 'pkg', placeholder: '* (any)' })),
      h('label', null, 'Image (glob)', h('input', { name: 'image', placeholder: '* (any), e.g. myapp:*' }))),
    h('div', { class: 'grid3' },
      h('label', null, 'VEX status', h('select', { name: 'status' }, ['not_affected', 'affected', 'fixed', 'under_investigation'].map((x) => h('option', { value: x }, x)))),
      h('label', null, 'Justification', h('select', { name: 'justification' }, ['', 'component_not_present', 'vulnerable_code_not_present', 'vulnerable_code_not_in_execute_path', 'vulnerable_code_cannot_be_controlled_by_adversary', 'inline_mitigations_already_exist'].map((x) => h('option', { value: x }, x || '(none)')))),
      h('label', null, 'Expires (optional)', h('input', { name: 'expires', type: 'date' }))),
    h('label', null, 'Reason (required)', h('textarea', { name: 'reason', rows: 2, required: true, maxlength: 1000, placeholder: 'Why is this acceptable? Who decided?' })),
    h('button', { class: 'btn primary', type: 'submit' }, 'Add rule'));
  mount(view, h('div', { class: 'toolbar' }, h('h2', null, 'Accepted risks'), h('div', { class: 'spacer' }), h('a', { class: 'btn', href: 'api/vex' }, 'Export OpenVEX')), form,
    h('div', { class: 'card flush' }, dataTable(list, [
      { key: 'vuln_id', label: 'Vulnerability' }, { key: 'pkg', label: 'Package' }, { key: 'image', label: 'Image' }, { key: 'status', label: 'Status' },
      { key: 'reason', label: 'Reason' },
      { key: 'expires_at', label: 'Expires', render: (r) => (r.expires_at ? (r.expires_at < Date.now() / 1000 ? h('span', { class: 'warn' }, 'expired') : fmtTime(r.expires_at)) : 'never') },
      { key: 'created_by', label: 'By', render: (r) => r.created_by + ', ' + ago(r.created_at) },
      { key: 'x', label: '', nosort: true, render: (r) => h('button', { class: 'btn small danger', onclick: async () => { if (confirm('Delete this rule?')) { await act('Rule deleted', () => api('admin/ignores/' + r.id, { method: 'DELETE' })); rules(view); } } }, 'Delete') },
    ], { empty: 'No rules yet.' })));
}

// ---------- Users & sessions ----------
async function users(view) {
  const [list, sessions] = await Promise.all([api('admin/users'), api('admin/sessions')]);
  const showPw = (user, pw) => modal('Temporary password', h('div', null, h('p', null, `Give this to ${user}. They must change it at first sign-in. It is not shown again.`), h('code', { class: 'secret' }, pw)), [{ label: 'Done', kind: 'primary', run: (c) => c() }]);
  const form = h('form', {
    class: 'card form inline', onsubmit: async (e) => {
      e.preventDefault();
      const f = e.target;
      const r = await act('User created', () => post('admin/users', { username: f.username.value.trim(), password: f.password.value, role: f.role.value }));
      if (r) { if (r.password) showPw(f.username.value, r.password); users(view); }
    },
  },
    h('h3', null, 'Add user'),
    h('div', { class: 'grid3' },
      h('label', null, 'Username', h('input', { name: 'username', required: true, pattern: '[A-Za-z0-9._@-]{3,64}', autocomplete: 'off' })),
      h('label', null, 'Password (blank = generate)', h('input', { name: 'password', type: 'password', minlength: 12, autocomplete: 'new-password' })),
      h('label', null, 'Role', h('select', { name: 'role' }, h('option', { value: 'viewer' }, 'viewer (dashboard)'), h('option', { value: 'admin' }, 'admin (dashboard + this panel)')))),
    h('button', { class: 'btn primary', type: 'submit' }, 'Create'));
  const patch = (u, body, label) => act(label, () => api('admin/users/' + u.id, { method: 'PATCH', body })).then((r) => { if (r && r.password) showPw(u.username, r.password); users(view); });
  mount(view, h('h2', null, 'Users'), form,
    h('div', { class: 'card flush' }, dataTable(list, [
      { key: 'username', label: 'User', render: (u) => h('span', null, u.username, u.must_change ? h('span', { class: 'chip chip-warn' }, 'temp password') : null, u.locked_until > Date.now() / 1000 ? h('span', { class: 'chip chip-err' }, 'locked') : null) },
      { key: 'role', label: 'Role' },
      { key: 'last_login', label: 'Last sign-in', render: (u) => ago(u.last_login) },
      { key: 'x', label: '', nosort: true, render: (u) => h('span', { class: 'btnrow' },
        h('button', { class: 'btn small', onclick: () => patch(u, { role: u.role === 'admin' ? 'viewer' : 'admin' }, 'Role changed') }, u.role === 'admin' ? 'Make viewer' : 'Make admin'),
        h('button', { class: 'btn small', onclick: () => { if (confirm('Reset password for ' + u.username + '?')) patch(u, { reset_password: true }, 'Password reset'); } }, 'Reset password'),
        u.locked_until > Date.now() / 1000 ? h('button', { class: 'btn small', onclick: () => patch(u, { unlock: true }, 'Unlocked') }, 'Unlock') : null,
        u.username !== state.me.user ? h('button', { class: 'btn small danger', onclick: async () => { if (confirm('Delete ' + u.username + '?')) { await act('Deleted', () => api('admin/users/' + u.id, { method: 'DELETE' })); users(view); } } }, 'Delete') : null) },
    ])),
    h('h3', null, 'Active sessions'),
    h('div', { class: 'card flush' }, dataTable(sessions, [
      { key: 'username', label: 'User' }, { key: 'scope', label: 'Where' }, { key: 'ip', label: 'IP' },
      { key: 'user_agent', label: 'Browser', render: (s) => h('span', { class: 'small ellipsis' }, s.user_agent) },
      { key: 'last_seen', label: 'Last seen', render: (s) => ago(s.last_seen) },
      { key: 'expires_at', label: 'Expires', render: (s) => fmtTime(s.expires_at) },
      { key: 'x', label: '', nosort: true, render: (s) => (s.current ? h('span', { class: 'muted' }, 'this session') : h('button', { class: 'btn small danger', onclick: async () => { await act('Session revoked', () => api('admin/sessions/' + s.id, { method: 'DELETE' })); users(view); } }, 'Revoke')) },
    ], { empty: 'No sessions.' })),
    changePasswordForm({ forced: false }));
}

// ---------- Audit ----------
async function audit(view) {
  const list = await api('admin/audit?limit=1000');
  mount(view, h('h2', null, 'Audit log'), h('div', { class: 'card flush' }, dataTable(list, [
    { key: 'ts', label: 'When', render: (a) => fmtTime(a.ts) }, { key: 'actor', label: 'Who' }, { key: 'ip', label: 'IP' },
    { key: 'action', label: 'Action', render: (a) => h('code', { class: a.action.includes('fail') || a.action.includes('denied') ? 'warn' : '' }, a.action) },
    { key: 'detail', label: 'Detail', render: (a) => h('span', { class: 'small' }, a.detail) },
  ], { pageSize: 100, initialSort: { key: 'ts', dir: -1 } })));
}

boot();
