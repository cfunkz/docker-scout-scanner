// Dashboard (LAN-facing, read-only).
'use strict';
import {
  h, $, mount, clear, api, state, toast, modal, fmtTime, ago, bytes, pct, shortId, sevBadge, riskBadge, counts,
  prefs, savePrefs, applyPrefs, defaultPrefs, lineChart, sevBar, loadMe, loginView, changePasswordForm, logout, twoFactorCard, tokensCard,
  dataTable, debounce, setUnauthorizedHandler, SEVS,
} from './common.js';

const root = $('#app');
let refreshTimer = null;

applyPrefs();
matchMedia('(prefers-color-scheme: dark)').addEventListener('change', applyPrefs);
setUnauthorizedHandler(() => boot());

async function boot() {
  try {
    const me = await loadMe();
    if (!me.user && me.require_login) {
      loginView(root, { title: 'Docker Scanner', subtitle: 'Sign in to see vulnerability reports.', onDone: boot });
      return;
    }
    if (me.must_change) {
      mount(root, h('div', { class: 'center' }, changePasswordForm({ forced: true, onDone: boot })));
      return;
    }
    shell();
    window.addEventListener('hashchange', route);
    route();
  } catch (e) {
    mount(root, h('div', { class: 'center' }, h('div', { class: 'card' }, h('h3', null, 'Cannot reach the scanner'), h('p', { class: 'muted' }, e.message),
      h('button', { class: 'btn', onclick: boot }, 'Retry'))));
  }
}

function shell() {
  const nav = [['#/', 'Overview'], ['#/images', 'Images'], ['#/vulns', 'Vulnerabilities'], ['#/settings', 'Settings']];
  mount(root,
    h('header', { class: 'top' },
      h('a', { class: 'brand', href: '#/' }, h('span', { class: 'logo' }, '◆'), 'Docker Scanner'),
      h('nav', { class: 'tabs', 'aria-label': 'Main' }, nav.map(([href, label]) => h('a', { href, dataset: { nav: href } }, label))),
      h('div', { class: 'spacer' }),
      h('form', {
        class: 'search', role: 'search', onsubmit: (e) => {
          e.preventDefault();
          const q = e.target.q.value.trim();
          if (q) location.hash = /^(CVE|GHSA)-/i.test(q) ? '#/vuln/' + encodeURIComponent(q.toUpperCase()) : '#/vulns?q=' + encodeURIComponent(q);
        },
      }, h('input', { name: 'q', placeholder: 'Search CVE, package…', 'aria-label': 'Search vulnerabilities' })),
      state.me.user ? h('div', { class: 'user' }, h('span', { class: 'muted' }, state.me.user),
        h('button', { class: 'btn ghost', onclick: logout }, 'Sign out')) : null),
    h('main', { id: 'view' }));
}

function route() {
  clearInterval(refreshTimer);
  const hash = location.hash || '#/';
  const [path, qs] = hash.slice(1).split('?');
  const params = new URLSearchParams(qs || '');
  document.querySelectorAll('[data-nav]').forEach((a) => {
    const n = a.dataset.nav.slice(1);
    a.classList.toggle('active', n === '/' ? path === '/' : path.startsWith(n) || (n === '/images' && path.startsWith('/image/')) || (n === '/vulns' && path.startsWith('/vuln/')));
  });
  const view = $('#view');
  const parts = path.split('/').filter(Boolean);
  const loading = h('div', { class: 'muted pad' }, 'Loading…');
  mount(view, loading);
  const go = {
    '': () => overview(view),
    images: () => images(view, params),
    image: () => imageDetail(view, decodeURIComponent(parts[1] || ''), params),
    vulns: () => vulns(view, params),
    vuln: () => vulnDetail(view, decodeURIComponent(parts[1] || '')),
    settings: () => settings(view),
  }[parts[0] || ''];
  (go || (() => mount(view, h('div', { class: 'card' }, 'Page not found.'))))()
    .catch((e) => mount(view, h('div', { class: 'card err' }, 'Error: ' + e.message)));
}

function autoRefresh(fn) {
  const sec = prefs().refreshSec;
  if (sec > 0) refreshTimer = setInterval(() => { if (!document.hidden && !$('.modal-wrap')) fn().catch(() => {}); }, sec * 1000);
}

// ---------------- Overview ----------------
async function overview(view) {
  const render = async () => {
    const [o, trend] = await Promise.all([api('overview'), api('trend?days=90')]);
    const kpi = (label, val, cls, hint, href) => h(href ? 'a' : 'div', { class: 'kpi ' + (cls || ''), href, title: hint }, h('div', { class: 'kpi-val' }, val), h('div', { class: 'kpi-label' }, label));
    const totalOpen = o.critical + o.high + o.medium + o.low + o.unknown;
    mount(view,
      !o.docker_ok ? h('div', { class: 'banner err' }, 'The scanner cannot reach the Docker API. Check the socket proxy container.') : null,
      o.queue + o.running > 0 ? h('div', { class: 'banner info' }, `Scanning: ${o.running} running, ${o.queue} queued.`) : null,
      h('section', { class: 'kpis' },
        kpi('Images', o.images, '', `${o.scanned} scanned, ${o.in_use} used by containers`, '#/images'),
        kpi('Critical', o.critical, 'k-crit', 'Open critical findings across all images', '#/vulns'),
        kpi('High', o.high, 'k-high', 'Open high findings', '#/vulns'),
        kpi('Known exploited', o.kev, o.kev ? 'k-kev' : '', 'Findings on the CISA KEV list: attackers use these today', '#/vulns?kev=1'),
        kpi('Fixable', totalOpen ? Math.round((100 * o.fixable) / totalOpen) + '%' : '—', '', `${o.fixable} of ${totalOpen} findings have a fixed version`),
        kpi('New since last scan', o.new_findings, o.new_findings ? 'k-new' : '', 'Findings that appeared in the latest scan of each image'),
        kpi('End-of-life OS', o.eosl, o.eosl ? 'k-high' : '', 'Images whose base OS no longer gets security fixes'),
        o.secrets ? kpi('Secrets', o.secrets, 'k-crit', 'Secrets found baked into image layers') : null),
      h('div', { class: 'grid2' },
        h('section', { class: 'card' }, h('h3', null, 'Riskiest images'),
          o.top_images.length ? h('table', { class: 'tbl' }, h('tbody', null, o.top_images.map((t) => h('tr', { class: 'clickable', onclick: () => location.hash = '#/image/' + shortId(t.id) },
            h('td', null, riskBadge(t.risk)),
            h('td', null, h('a', { href: '#/image/' + shortId(t.id) }, t.name), t.in_use ? h('span', { class: 'chip chip-run' }, 'running') : null, t.eosl ? h('span', { class: 'chip chip-warn' }, 'EOL') : null),
            h('td', { class: 'num' }, t.kev ? h('span', { class: 'chip chip-kev' }, 'KEV ' + t.kev) : null),
            h('td', { class: 'num' }, h('span', { class: 'cnt cnt-critical' + (t.critical ? '' : ' zero') }, 'C ' + t.critical), ' ', h('span', { class: 'cnt cnt-high' + (t.high ? '' : ' zero') }, 'H ' + t.high)),
            h('td', { class: 'num muted' }, t.new ? '+' + t.new + ' new' : ''))))) : h('p', { class: 'muted' }, 'No scans yet. The first scan starts automatically.')),
        h('section', { class: 'card' }, h('h3', null, 'Fix these first'), h('p', { class: 'muted small' }, 'Vulnerabilities across all images, ranked by risk.'),
          o.top_vulns.length ? h('table', { class: 'tbl' }, h('tbody', null, o.top_vulns.map((v) => h('tr', { class: 'clickable', onclick: () => location.hash = '#/vuln/' + encodeURIComponent(v.id) },
            h('td', null, riskBadge(v.risk)), h('td', null, sevBadge(v.severity)),
            h('td', null, h('a', { href: '#/vuln/' + encodeURIComponent(v.id) }, v.id), v.kev ? h('span', { class: 'chip chip-kev' }, 'KEV') : null, h('div', { class: 'muted small ellipsis' }, v.packages.join(', '))),
            h('td', { class: 'num' }, v.images + ' img'))))) : h('p', { class: 'muted' }, 'Nothing to fix. Nice.'))),
      h('section', { class: 'card' }, h('h3', null, 'Trend (90 days)'),
        lineChart(trend, [{ key: 'critical', label: 'Critical', cls: 's-crit' }, { key: 'high', label: 'High', cls: 's-high' }, { key: 'kev', label: 'Known exploited', cls: 's-kev' }, { key: 'fixable', label: 'Fixable', cls: 's-fix' }])),
      h('p', { class: 'muted small' }, 'Last scan finished ' + ago(o.last_scan) + '.'));
  };
  await render();
  autoRefresh(render);
}

// ---------------- Images ----------------
async function images(view, params) {
  const p = prefs();
  let all = await api('images' + (params.get('all') ? '?all=1' : ''));
  const q = h('input', { type: 'search', placeholder: 'Filter images…', value: params.get('q') || '', 'aria-label': 'Filter images' });
  const onlyUse = h('input', { type: 'checkbox', checked: params.get('inuse') === '1' });
  const onlyBad = h('input', { type: 'checkbox' });
  const filter = () => {
    const t = q.value.trim().toLowerCase();
    return all.filter((im) => (!t || im.repo_tags.join(' ').toLowerCase().includes(t) || im.id.includes(t))
      && (!onlyUse.checked || im.containers.length)
      && (!onlyBad.checked || (im.scan && (im.scan.critical + im.scan.kev) > 0)));
  };
  const name = (im) => im.repo_tags[0] || '<untagged> ' + shortId(im.id);
  const table = dataTable(filter(), [
    { key: 'risk', label: 'Risk', sort: (r) => (r.scan ? r.scan.risk_max : -1), render: (r) => (r.scan ? riskBadge(r.scan.risk_max) : h('span', { class: 'muted' }, '—')) },
    {
      key: 'name', label: 'Image', sort: name, render: (r) => h('div', null,
        h('a', { href: '#/image/' + shortId(r.id) }, name(r)),
        r.repo_tags.length > 1 ? h('span', { class: 'muted small' }, ' +' + (r.repo_tags.length - 1) + ' tags') : null,
        r.containers.length ? h('span', { class: 'chip chip-run', title: r.containers.map((c) => c.name + ' (' + c.state + ')').join(', ') }, r.containers.length + ' container' + (r.containers.length > 1 ? 's' : '')) : null,
        r.eosl ? h('span', { class: 'chip chip-warn', title: 'Base OS is end-of-life' }, 'EOL OS') : null,
        r.excluded ? h('span', { class: 'chip' }, 'excluded') : null,
        !r.present ? h('span', { class: 'chip' }, 'removed') : null),
    },
    { key: 'counts', label: 'Findings', sort: (r) => (r.scan ? r.scan.critical * 1e6 + r.scan.high * 1e3 + r.scan.medium : -1), render: (r) => counts(r.scan) },
    { key: 'kev', label: 'KEV', cls: 'num', sort: (r) => (r.scan ? r.scan.kev : -1), render: (r) => (r.scan && r.scan.kev ? h('span', { class: 'chip chip-kev' }, r.scan.kev) : '') },
    { key: 'fix', label: 'Fixable', cls: 'num', sort: (r) => (r.scan ? r.scan.fixable : -1), render: (r) => (r.scan ? r.scan.fixable : '') },
    { key: 'new', label: 'Change', cls: 'num', sort: (r) => (r.scan ? r.scan.new_count - r.scan.resolved_count : 0), render: (r) => delta(r.scan) },
    { key: 'size', label: 'Size', cls: 'num', sort: (r) => r.size, render: (r) => bytes(r.size) },
    { key: 'scanned', label: 'Scanned', sort: (r) => (r.scan ? r.scan.finished_at : 0), render: (r) => (r.scan ? h('span', { title: fmtTime(r.scan.finished_at) }, ago(r.scan.finished_at)) : h('span', { class: 'muted' }, 'pending')) },
  ], { pageSize: p.pageSize, empty: 'No images match.', onRow: (r) => location.hash = '#/image/' + shortId(r.id), initialSort: { key: 'risk', dir: -1 } });
  const upd = debounce(() => table.update(filter()));
  q.addEventListener('input', upd); onlyUse.addEventListener('change', upd); onlyBad.addEventListener('change', upd);
  mount(view,
    h('div', { class: 'toolbar' }, h('h2', null, 'Images'), q,
      h('label', { class: 'check' }, onlyUse, 'Used by containers'),
      h('label', { class: 'check' }, onlyBad, 'Critical or KEV only'),
      h('a', { class: 'btn ghost', href: params.get('all') ? '#/images' : '#/images?all=1' }, params.get('all') ? 'Hide removed' : 'Show removed')),
    h('div', { class: 'card flush' }, table));
  autoRefresh(async () => { all = await api('images' + (params.get('all') ? '?all=1' : '')); table.update(filter()); });
}

function delta(sc) {
  if (!sc || !sc.prev_scan) return '';
  const parts = [];
  if (sc.new_count) parts.push(h('span', { class: 'delta up', title: 'new findings since the previous scan' }, '+' + sc.new_count));
  if (sc.resolved_count) parts.push(h('span', { class: 'delta down', title: 'findings resolved since the previous scan' }, '−' + sc.resolved_count));
  return parts.length ? h('span', null, ...parts) : h('span', { class: 'muted' }, '±0');
}

// ---------------- Image detail ----------------
async function imageDetail(view, id, params) {
  const d = await api('images/' + encodeURIComponent(id));
  const im = d.image, sc = im.scan;
  const tab = params.get('tab') || 'findings';
  const tabs = [['findings', 'Findings'], ['fix', 'Fix plan'], ['changes', 'Changes'], ['layers', 'Layers'], ['history', 'History']];
  const body = h('div');
  const name = im.repo_tags[0] || shortId(im.id);
  mount(view,
    h('div', { class: 'crumbs' }, h('a', { href: '#/images' }, 'Images'), ' / ', name),
    h('section', { class: 'card head' },
      h('div', { class: 'head-main' },
        h('h2', null, name, im.containers.length ? h('span', { class: 'chip chip-run' }, 'in use') : null, im.eosl ? h('span', { class: 'chip chip-warn' }, 'EOL OS') : null),
        h('div', { class: 'meta muted small' },
          h('span', { title: im.id }, 'ID ' + shortId(im.id)), ' · ', (im.os_family ? im.os_family + ' ' + im.os_name : im.os || 'unknown OS'), ' · ', bytes(im.size),
          ' · ', im.pkg_count + ' packages', ' · built ', fmtTime(im.created)),
        im.repo_tags.length > 1 ? h('div', { class: 'small' }, 'Also tagged: ', im.repo_tags.slice(1).join(', ')) : null,
        im.containers.length ? h('div', { class: 'small' }, 'Containers: ', im.containers.map((c) => c.name + ' (' + c.state + ')').join(', ')) : null,
        im.eosl ? h('div', { class: 'banner warn small' }, 'This base OS is end-of-life: new vulnerabilities in it will never be fixed. Move to a supported release.') : null),
      h('div', { class: 'head-side' },
        sc ? riskBadge(sc.risk_max) : null,
        sc ? h('div', null, counts(sc)) : null,
        sc ? sevBar(sc) : null,
        sc ? h('div', { class: 'muted small' }, 'Scanned ', ago(sc.finished_at), ' with ', sc.engines, sc.sbom_reused ? ' (cached SBOM)' : '', ' in ', (sc.duration_ms / 1000).toFixed(1), 's') : h('div', { class: 'muted' }, 'Not scanned yet'),
        sc && sc.status === 'failed' ? h('div', { class: 'banner err small' }, 'Last scan failed: ' + sc.error) : null,
        h('div', { class: 'btnrow' },
          h('a', { class: 'btn small', href: `api/images/${shortId(im.id)}/export?format=csv` }, 'CSV'),
          h('a', { class: 'btn small', href: `api/images/${shortId(im.id)}/export?format=json` }, 'JSON'),
          h('a', { class: 'btn small', href: `api/images/${shortId(im.id)}/export?format=sarif` }, 'SARIF'),
          d.has_sbom ? h('a', { class: 'btn small', href: `api/images/${shortId(im.id)}/export?format=sbom` }, 'SBOM') : null))),
    h('nav', { class: 'subtabs' }, tabs.map(([k, l]) => h('a', { href: `#/image/${shortId(im.id)}?tab=${k}`, class: tab === k ? 'active' : '' }, l,
      k === 'changes' && sc && (sc.new_count || sc.resolved_count) ? h('span', { class: 'badge' }, sc.new_count + sc.resolved_count) : null))),
    body);
  const layerName = layerNamer(im.layers || []);
  if (tab === 'findings') await findingsTab(body, im, layerName);
  else if (tab === 'fix') await fixTab(body, im, layerName);
  else if (tab === 'changes') await changesTab(body, im);
  else if (tab === 'layers') await layersTab(body, im);
  else if (tab === 'history') historyTab(body, d.history);
}

function layerNamer(layers) {
  const m = new Map(layers.map((l) => [l.diff_id, l]));
  return (diff) => {
    const l = m.get(diff);
    if (!l) return diff ? 'layer ' + shortId(diff) : '';
    return `#${l.index + 1}${l.index === 0 ? ' (base)' : ''} ${l.created_by || ''}`.trim();
  };
}

async function findingsTab(body, im, layerName) {
  if (!im.latest_scan) { mount(body, h('div', { class: 'card muted' }, 'No findings yet.')); return; }
  const p = prefs();
  const all = await api(`images/${shortId(im.id)}/findings`);
  const q = h('input', { type: 'search', placeholder: 'Filter by id, package, title…', 'aria-label': 'Filter findings' });
  const sev = h('select', { 'aria-label': 'Minimum severity' }, SEVS.map((s) => h('option', { value: s, selected: s === p.minSeverity }, s === 'UNKNOWN' ? 'All severities' : s + ' and up')));
  const fixOnly = h('input', { type: 'checkbox', checked: p.hideUnfixed });
  const kevOnly = h('input', { type: 'checkbox' });
  const showIgn = h('input', { type: 'checkbox', checked: p.showIgnored });
  const rank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 };
  const filter = () => {
    const t = q.value.trim().toLowerCase(), min = rank[sev.value];
    return all.filter((f) => (!t || (f.id + ' ' + f.pkg + ' ' + f.title + ' ' + (f.aliases || '')).toLowerCase().includes(t))
      && rank[f.severity] >= min && (!fixOnly.checked || f.fixed) && (!kevOnly.checked || f.kev) && (showIgn.checked || !f.ignored_by));
  };
  const table = dataTable(filter(), [
    { key: 'risk', label: 'Risk', render: (f) => riskBadge(f.risk) },
    { key: 'severity', label: 'Sev', sort: (f) => rank[f.severity] * 100 + f.cvss, render: (f) => sevBadge(f.severity) },
    {
      key: 'id', label: 'Vulnerability', render: (f) => h('div', null,
        h('a', { href: '#/vuln/' + encodeURIComponent(f.id) }, f.id),
        f.kev ? h('span', { class: 'chip chip-kev', title: 'CISA Known Exploited Vulnerability' + (f.kev_ransomware ? ' (used in ransomware)' : '') }, f.kev_ransomware ? 'KEV ⚠' : 'KEV') : null,
        f.kind === 'secret' ? h('span', { class: 'chip chip-err' }, 'secret') : null,
        f.ignored_by ? h('span', { class: 'chip' }, 'accepted') : null,
        f.engines.includes(',') ? h('span', { class: 'chip chip-ok', title: 'Confirmed by both engines' }, '2×') : null,
        h('div', { class: 'muted small ellipsis' }, f.title)),
    },
    { key: 'pkg', label: 'Package', render: (f) => h('div', null, h('code', null, f.pkg), h('div', { class: 'muted small' }, f.version + (f.pkg_type ? ' · ' + f.pkg_type : ''))) },
    { key: 'fixed', label: 'Fixed in', render: (f) => (f.fixed ? h('code', { class: 'ok' }, f.fixed) : h('span', { class: 'muted' }, 'no fix')) },
    { key: 'epss', label: 'EPSS', cls: 'num', render: (f) => (f.epss ? h('span', { title: `Exploit probability in the next 30 days. Percentile ${pct(f.epss_pct)}` }, pct(f.epss)) : '') },
    { key: 'cvss', label: 'CVSS', cls: 'num', render: (f) => (f.cvss ? f.cvss.toFixed(1) : '') },
    { key: 'layer', label: 'Introduced by', render: (f) => h('span', { class: 'small ellipsis layer', title: layerName(f.layer) }, layerName(f.layer)) },
  ], { pageSize: p.pageSize, empty: 'No findings match these filters.', rowClass: (f) => (f.ignored_by ? 'dim' : ''), onRow: (f) => findingModal(f, layerName), initialSort: { key: 'risk', dir: -1 } });
  const upd = debounce(() => table.update(filter()));
  [q].forEach((e) => e.addEventListener('input', upd));
  [sev, fixOnly, kevOnly, showIgn].forEach((e) => e.addEventListener('change', upd));
  mount(body, h('div', { class: 'toolbar' }, q, sev, h('label', { class: 'check' }, fixOnly, 'Fixable only'), h('label', { class: 'check' }, kevOnly, 'KEV only'), h('label', { class: 'check' }, showIgn, 'Show accepted')),
    h('div', { class: 'card flush' }, table));
}

function findingModal(f, layerName) {
  modal(f.id, h('div', { class: 'detail' },
    h('div', { class: 'row' }, sevBadge(f.severity), riskBadge(f.risk), f.kev ? h('span', { class: 'chip chip-kev' }, 'Known exploited (CISA KEV)') : null, f.kev_ransomware ? h('span', { class: 'chip chip-err' }, 'Used in ransomware') : null),
    f.title ? h('h4', null, f.title) : null,
    f.description ? h('p', { class: 'desc' }, f.description) : null,
    h('dl', { class: 'kv' },
      h('dt', null, 'Package'), h('dd', null, h('code', null, f.pkg + ' ' + f.version), f.pkg_type ? ' (' + f.pkg_type + ')' : ''),
      f.path ? [h('dt', null, 'Path'), h('dd', null, h('code', null, f.path))] : null,
      h('dt', null, 'Fixed in'), h('dd', null, f.fixed || 'No fix available yet'),
      h('dt', null, 'CVSS'), h('dd', null, f.cvss ? f.cvss.toFixed(1) : 'n/a'),
      h('dt', null, 'EPSS'), h('dd', null, f.epss ? `${pct(f.epss)} chance of exploitation in 30 days (percentile ${pct(f.epss_pct)})` : 'n/a'),
      h('dt', null, 'Layer'), h('dd', { class: 'small' }, layerName(f.layer) || 'unknown'),
      h('dt', null, 'Found by'), h('dd', null, f.engines),
      f.aliases ? [h('dt', null, 'Aliases'), h('dd', null, f.aliases.split(',').join(', '))] : null,
      f.published ? [h('dt', null, 'Published'), h('dd', null, new Date(f.published).toLocaleDateString())] : null,
      f.purl ? [h('dt', null, 'purl'), h('dd', { class: 'small' }, h('code', null, f.purl))] : null),
    h('div', { class: 'btnrow' },
      f.url ? h('a', { class: 'btn', href: f.url, target: '_blank', rel: 'noopener noreferrer' }, 'Advisory ↗') : null,
      f.id.startsWith('CVE-') ? h('a', { class: 'btn', href: 'https://nvd.nist.gov/vuln/detail/' + encodeURIComponent(f.id), target: '_blank', rel: 'noopener noreferrer' }, 'NVD ↗') : null,
      h('a', { class: 'btn', href: '#/vuln/' + encodeURIComponent(f.id) }, 'Other images with this')),
    h('p', { class: 'muted small' }, 'To accept this risk, add a rule in the admin panel (localhost only).')));
}

async function fixTab(body, im, layerName) {
  const [plan, findings] = await Promise.all([api(`images/${shortId(im.id)}/fixplan`), im.latest_scan ? api(`images/${shortId(im.id)}/findings`) : []]);
  const b = plan.base_image;
  // Findings of one upgrade step: same package and installed version, not accepted.
  const stepFindings = (st) => findings.filter((f) => f.pkg === st.pkg && f.version === st.installed && f.fixed && !f.ignored_by && st.vuln_ids.includes(f.id));
  const vulnLink = (id) => h('a', { href: '#/vuln/' + encodeURIComponent(id) }, id);
  const cveList = (st) => {
    const ids = st.vuln_ids;
    const shown = ids.slice(0, 3);
    return h('div', { class: 'small cvelist' }, shown.map((id, i) => [i ? ', ' : '', vulnLink(id)]),
      ids.length > shown.length ? h('span', { class: 'muted' }, ` +${ids.length - shown.length} more`) : null);
  };
  const stepModal = (st) => {
    const rank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 };
    const rows = stepFindings(st).sort((x, y) => y.risk - x.risk || rank[y.severity] - rank[x.severity]);
    modal(`${st.pkg} ${st.installed} → ${st.target}`, h('div', null,
      h('p', { class: 'muted' }, `Upgrading fixes these ${rows.length} vulnerabilities. Click an id for details and other affected images.`),
      dataTable(rows, [
        { key: 'risk', label: 'Risk', render: (f) => riskBadge(f.risk) },
        { key: 'severity', label: 'Sev', sort: (f) => rank[f.severity] * 100 + f.cvss, render: (f) => sevBadge(f.severity) },
        { key: 'id', label: 'Vulnerability', render: (f) => h('div', null, vulnLink(f.id), f.kev ? h('span', { class: 'chip chip-kev' }, 'KEV') : null, h('div', { class: 'muted small ellipsis' }, f.title)) },
        { key: 'fixed', label: 'Fixed in', cls: 'nowrap', render: (f) => h('code', { class: 'ok' }, f.fixed) },
        { key: 'epss', label: 'EPSS', cls: 'num', render: (f) => (f.epss ? pct(f.epss) : '') },
        { key: 'url', label: '', cls: 'nowrap', nosort: true, render: (f) => (f.url ? h('a', { href: f.url, target: '_blank', rel: 'noopener noreferrer' }, 'Advisory ↗') : '') },
      ], { pageSize: 50, initialSort: { key: 'risk', dir: -1 } })));
  };
  mount(body,
    h('div', { class: 'grid3' },
      h('div', { class: 'kpi' }, h('div', { class: 'kpi-val' }, plan.fixable_total), h('div', { class: 'kpi-label' }, 'fixable findings')),
      h('div', { class: 'kpi' }, h('div', { class: 'kpi-val' }, plan.steps.length), h('div', { class: 'kpi-label' }, 'package upgrades')),
      h('div', { class: 'kpi' }, h('div', { class: 'kpi-val' }, plan.unfixable), h('div', { class: 'kpi-label' }, 'no fix yet'))),
    b ? h('div', { class: 'card ' + (b.share_pct >= 50 || b.eosl ? 'callout' : '') },
      h('h3', null, 'Base image'),
      h('p', null, `${b.share_pct}% of findings (${b.findings}, ${b.fixable} fixable) live in the base layer${b.os ? ' (' + b.os + ')' : ''}. `,
        b.eosl ? h('strong', null, 'The base OS is end-of-life, so rebuild on a supported release. ') : '',
        b.share_pct >= 50 ? 'Rebuilding on a newer base image tag (or a slimmer one, such as distroless or alpine) is likely the quickest win.' : 'Most findings come from layers you add, so the package upgrades below matter more.')) : null,
    h('div', { class: 'card flush' }, dataTable(plan.steps, [
      { key: 'pkg', label: 'Upgrade', render: (s) => h('div', null, h('code', null, s.pkg), h('span', { class: 'muted small' }, ' ' + s.pkg_type), cveList(s)) },
      { key: 'installed', label: 'From → to', nosort: true, render: (s) => h('span', null, h('code', null, s.installed), ' → ', h('code', { class: 'ok' }, s.target)) },
      { key: 'fixes', label: 'CVEs fixed', cls: 'num', render: (s) => h('button', { class: 'btn small', title: 'Show the CVEs this upgrade fixes', onclick: () => stepModal(s) }, s.fixes + ' ›') },
      { key: 'critical', label: 'Crit/High', cls: 'num', sort: (s) => s.critical * 1000 + s.high, render: (s) => h('span', null, h('span', { class: 'cnt cnt-critical' + (s.critical ? '' : ' zero') }, 'C ' + s.critical), ' ', h('span', { class: 'cnt cnt-high' + (s.high ? '' : ' zero') }, 'H ' + s.high)) },
      { key: 'kev', label: 'KEV', cls: 'num', render: (s) => (s.kev ? h('span', { class: 'chip chip-kev' }, s.kev) : '') },
      { key: 'risk_sum', label: 'Risk removed', cls: 'num', render: (s) => s.risk_sum.toFixed(0) },
      { key: 'remaining', label: 'Left after', cls: 'num', render: (s) => (s.remaining ? h('span', { class: 'muted', title: 'findings in this package with no fix yet' }, s.remaining) : '0') },
      { key: 'layer', label: 'Layer', render: (s) => h('span', { class: 'small ellipsis layer', title: layerName(s.layer) }, layerName(s.layer)) },
    ], { empty: 'No fixable findings. Remaining issues have no upstream fix yet.', initialSort: { key: 'risk_sum', dir: -1 }, onRow: (s) => stepModal(s) })),
    h('p', { class: 'muted small' }, 'Click a row to list the CVEs it fixes. The full per-CVE list is on the Findings tab. Target versions are the lowest that clear every listed vulnerability in the package. Check your package manager for the exact version string.'));
}

async function changesTab(body, im) {
  const d = await api(`images/${shortId(im.id)}/diff`);
  if (!d.baseline) { mount(body, h('div', { class: 'card muted' }, 'No earlier scan of this image or tag to compare with yet.')); return; }
  const list = (rows, kind) => dataTable(rows, [
    { key: 'severity', label: 'Sev', render: (f) => sevBadge(f.severity) },
    { key: 'id', label: 'Vulnerability', render: (f) => h('span', null, h('a', { href: '#/vuln/' + encodeURIComponent(f.id) }, f.id), f.kev ? h('span', { class: 'chip chip-kev' }, 'KEV') : null) },
    { key: 'pkg', label: 'Package', render: (f) => h('code', null, f.pkg + ' ' + f.version) },
    { key: 'fixed', label: 'Fixed in', render: (f) => f.fixed || '—' },
  ], { empty: kind === 'new' ? 'Nothing new.' : 'Nothing resolved.' });
  const sameImage = d.baseline.image_id === im.id;
  mount(body,
    h('p', { class: 'muted' }, 'Compared with the scan of ', fmtTime(d.baseline.finished_at),
      sameImage ? ' (same image; changes come from new advisories or rule changes).' : ` (an earlier build of ${d.baseline.ref}; changes come from the rebuild and from new advisories).`),
    h('div', { class: 'grid2' },
      h('section', { class: 'card flush' }, h('h3', { class: 'pad' }, h('span', { class: 'delta up' }, '+' + d.new.length), ' New'), list(d.new, 'new')),
      h('section', { class: 'card flush' }, h('h3', { class: 'pad' }, h('span', { class: 'delta down' }, '−' + d.resolved.length), ' Resolved'), list(d.resolved, 'res'))));
}

async function layersTab(body, im) {
  const fs = im.latest_scan ? await api(`images/${shortId(im.id)}/findings`) : [];
  const per = new Map();
  for (const f of fs) {
    if (f.ignored_by) continue;
    const e = per.get(f.layer) || { n: 0, c: 0, hgh: 0 };
    e.n++; if (f.severity === 'CRITICAL') e.c++; if (f.severity === 'HIGH') e.hgh++;
    per.set(f.layer, e);
  }
  const layers = im.layers || [];
  mount(body, h('div', { class: 'card flush' }, h('table', { class: 'tbl' },
    h('thead', null, h('tr', null, ['#', 'Instruction', 'Size', 'Findings'].map((t) => h('th', null, t)))),
    h('tbody', null, layers.map((l) => {
      const e = per.get(l.diff_id) || { n: 0, c: 0, hgh: 0 };
      return h('tr', null, h('td', null, l.index + 1, l.index === 0 ? h('span', { class: 'chip' }, 'base') : null),
        h('td', null, h('code', { class: 'wrap small' }, l.created_by || shortId(l.diff_id))),
        h('td', { class: 'num' }, l.size ? bytes(l.size) : ''),
        h('td', { class: 'num' }, e.n ? h('span', null, e.n, ' ', e.c ? h('span', { class: 'cnt cnt-critical' }, 'C ' + e.c) : null, ' ', e.hgh ? h('span', { class: 'cnt cnt-high' }, 'H ' + e.hgh) : null) : h('span', { class: 'muted' }, '0')));
    })))),
  h('p', { class: 'muted small' }, 'Each finding is traced to the Dockerfile instruction that added the vulnerable package, so you know whether to bump the base image or fix your own RUN step.'));
}

function historyTab(body, hist) {
  const rows = hist.slice().reverse().map((s) => ({ day: new Date(s.finished_at * 1000).toLocaleDateString(), critical: s.critical, high: s.high, medium: s.medium, kev: s.kev }));
  mount(body,
    h('section', { class: 'card' }, lineChart(rows, [{ key: 'critical', label: 'Critical', cls: 's-crit' }, { key: 'high', label: 'High', cls: 's-high' }, { key: 'medium', label: 'Medium', cls: 's-med' }, { key: 'kev', label: 'KEV', cls: 's-kev' }])),
    h('div', { class: 'card flush' }, dataTable(hist, [
      { key: 'finished_at', label: 'When', render: (s) => fmtTime(s.finished_at || s.started_at) },
      { key: 'trigger', label: 'Trigger' },
      { key: 'status', label: 'Status', render: (s) => (s.status === 'failed' ? h('span', { class: 'chip chip-err', title: s.error }, 'failed') : s.status) },
      { key: 'image_id', label: 'Image', render: (s) => h('code', null, shortId(s.image_id)) },
      { key: 'counts', label: 'Findings', nosort: true, render: (s) => counts(s) },
      { key: 'delta', label: 'Change', nosort: true, render: (s) => delta(s) },
      { key: 'duration_ms', label: 'Took', cls: 'num', render: (s) => (s.duration_ms / 1000).toFixed(1) + 's' + (s.sbom_reused ? ' ⚡' : '') },
    ], { empty: 'No history.' })),
    h('p', { class: 'muted small' }, '⚡ = matched against the cached SBOM without re-reading the image.'));
}

// ---------------- Fleet vulnerabilities ----------------
async function vulns(view, params) {
  const q = h('input', { type: 'search', placeholder: 'CVE id, package or keyword…', value: params.get('q') || '', 'aria-label': 'Search vulnerabilities' });
  const kevOnly = h('input', { type: 'checkbox', checked: params.get('kev') === '1' });
  const inUse = h('input', { type: 'checkbox' });
  const fixOnly = h('input', { type: 'checkbox' });
  let rows = [];
  const table = dataTable([], [
    { key: 'risk', label: 'Risk', render: (v) => riskBadge(v.risk) },
    { key: 'severity', label: 'Sev', sort: (v) => SEVS.length - SEVS.indexOf(v.severity), render: (v) => sevBadge(v.severity) },
    { key: 'id', label: 'Vulnerability', render: (v) => h('div', null, h('a', { href: '#/vuln/' + encodeURIComponent(v.id) }, v.id), v.kev ? h('span', { class: 'chip chip-kev' }, 'KEV') : null, h('div', { class: 'muted small ellipsis' }, v.title)) },
    { key: 'packages', label: 'Packages', sort: (v) => v.packages.join(), render: (v) => h('span', { class: 'small' }, v.packages.slice(0, 4).join(', ') + (v.packages.length > 4 ? '…' : '')) },
    { key: 'images', label: 'Images', cls: 'num' },
    { key: 'in_use', label: 'Running', cls: 'num', render: (v) => (v.in_use ? h('span', { class: 'chip chip-run' }, v.in_use) : '0') },
    { key: 'epss', label: 'EPSS', cls: 'num', render: (v) => (v.epss ? pct(v.epss) : '') },
    { key: 'fixable', label: 'Fix', cls: 'num', sort: (v) => (v.fixable ? 1 : 0), render: (v) => (v.fixable ? h('span', { class: 'ok' }, 'yes') : h('span', { class: 'muted' }, 'no')) },
  ], { pageSize: prefs().pageSize, empty: 'No open vulnerabilities match.', onRow: (v) => location.hash = '#/vuln/' + encodeURIComponent(v.id), initialSort: { key: 'risk', dir: -1 } });
  const filter = () => rows.filter((v) => (!kevOnly.checked || v.kev) && (!inUse.checked || v.in_use) && (!fixOnly.checked || v.fixable));
  const load = async () => { rows = await api('vulns?limit=5000&q=' + encodeURIComponent(q.value.trim())); table.update(filter()); };
  q.addEventListener('input', debounce(load, 300));
  [kevOnly, inUse, fixOnly].forEach((e) => e.addEventListener('change', () => table.update(filter())));
  mount(view, h('div', { class: 'toolbar' }, h('h2', null, 'Vulnerabilities'), q,
    h('label', { class: 'check' }, kevOnly, 'Known exploited'), h('label', { class: 'check' }, inUse, 'In running images'), h('label', { class: 'check' }, fixOnly, 'Fixable')),
  h('p', { class: 'muted small' }, 'One row per vulnerability across every image on this host. Use it to answer "are we affected by X, and where?"'),
  h('div', { class: 'card flush' }, table));
  await load();
}

async function vulnDetail(view, id) {
  let d;
  try { d = await api('vulns/' + encodeURIComponent(id)); } catch (e) {
    if (e.status === 404) { mount(view, h('div', { class: 'card' }, h('h2', null, id), h('p', { class: 'ok' }, 'Not present in any image currently on this host.'))); return; }
    throw e;
  }
  const v = d.vuln;
  mount(view,
    h('div', { class: 'crumbs' }, h('a', { href: '#/vulns' }, 'Vulnerabilities'), ' / ', id),
    h('section', { class: 'card' },
      h('h2', null, id, ' ', sevBadge(v.severity), v.kev ? h('span', { class: 'chip chip-kev' }, 'Known exploited') : null),
      v.title ? h('h4', null, v.title) : null,
      v.description ? h('p', { class: 'desc' }, v.description) : null,
      h('div', { class: 'row muted small' }, v.cvss ? 'CVSS ' + v.cvss.toFixed(1) + ' · ' : '', v.epss ? 'EPSS ' + pct(v.epss) + ' · ' : '', v.aliases ? 'Aliases: ' + v.aliases : ''),
      h('div', { class: 'btnrow' }, v.url ? h('a', { class: 'btn', href: v.url, target: '_blank', rel: 'noopener noreferrer' }, 'Advisory ↗') : null,
        id.startsWith('CVE-') ? h('a', { class: 'btn', href: 'https://nvd.nist.gov/vuln/detail/' + encodeURIComponent(id), target: '_blank', rel: 'noopener noreferrer' }, 'NVD ↗') : null)),
    h('h3', null, `Affected images (${d.images.length})`),
    h('div', { class: 'card flush' }, dataTable(d.images, [
      { key: 'name', label: 'Image', render: (a) => h('span', null, h('a', { href: '#/image/' + shortId(a.image_id) }, a.name), a.in_use ? h('span', { class: 'chip chip-run', title: (a.containers || []).join(', ') }, 'running') : null) },
      { key: 'pkg', label: 'Package', render: (a) => h('code', null, a.pkg + ' ' + a.version) },
      { key: 'fixed', label: 'Fixed in', render: (a) => (a.fixed ? h('code', { class: 'ok' }, a.fixed) : h('span', { class: 'muted' }, 'no fix')) },
    ], { empty: 'None.' })));
}

// ---------------- Settings ----------------
async function settings(view) {
  const p = prefs();
  const server = await api('settings/public');
  const ignores = await api('ignores');
  const sel = (name, opts, val) => h('select', { name }, opts.map(([v, l]) => h('option', { value: v, selected: String(v) === String(val) }, l)));
  const form = h('form', {
    class: 'card form', onsubmit: (e) => {
      e.preventDefault();
      const f = e.target;
      savePrefs({ theme: f.theme.value, pageSize: +f.pageSize.value, minSeverity: f.minSeverity.value, hideUnfixed: f.hideUnfixed.checked, showIgnored: f.showIgnored.checked, compact: f.compact.checked, refreshSec: +f.refreshSec.value });
      toast('Display settings saved in this browser.');
    },
  },
    h('h3', null, 'Display'),
    h('label', null, 'Theme', sel('theme', [['auto', 'Follow system'], ['light', 'Light'], ['dark', 'Dark']], p.theme)),
    h('label', null, 'Rows per page', sel('pageSize', [[50, 50], [100, 100], [250, 250], [1000, 1000]], p.pageSize)),
    h('label', null, 'Default minimum severity', sel('minSeverity', SEVS.map((s) => [s, s === 'UNKNOWN' ? 'All' : s]), p.minSeverity)),
    h('label', null, 'Auto-refresh', sel('refreshSec', [[0, 'Off'], [15, 'Every 15 s'], [30, 'Every 30 s'], [120, 'Every 2 min']], p.refreshSec)),
    h('label', { class: 'check' }, h('input', { type: 'checkbox', name: 'hideUnfixed', checked: p.hideUnfixed }), 'Hide findings without a fix by default'),
    h('label', { class: 'check' }, h('input', { type: 'checkbox', name: 'showIgnored', checked: p.showIgnored }), 'Show accepted-risk findings by default'),
    h('label', { class: 'check' }, h('input', { type: 'checkbox', name: 'compact', checked: p.compact }), 'Compact tables'),
    h('div', { class: 'btnrow' }, h('button', { class: 'btn primary', type: 'submit' }, 'Save'),
      h('button', { class: 'btn ghost', type: 'button', onclick: () => { savePrefs(defaultPrefs); route(); } }, 'Reset')));
  const yes = (b) => (b ? 'on' : 'off');
  mount(view,
    h('h2', null, 'Settings'),
    h('div', { class: 'grid2' },
      form,
      h('div', null,
        state.me.user ? changePasswordForm({ forced: false }) : null,
        state.me.user ? twoFactorCard() : null,
        h('section', { class: 'card' }, h('h3', null, 'Scanner configuration'),
          h('p', { class: 'muted small' }, 'Read-only here. Change these in the admin panel, which only listens on the server\'s localhost.'),
          h('dl', { class: 'kv' },
            h('dt', null, 'Engine'), h('dd', null, server.engine),
            h('dt', null, 'Full rescan'), h('dd', null, server.scan_interval_h ? `every ${server.scan_interval_h} h` : 'off'),
            h('dt', null, 'Scan new images'), h('dd', null, yes(server.watch_events)),
            h('dt', null, 'Only images in use'), h('dd', null, yes(server.only_in_use)),
            h('dt', null, 'Secret scanning'), h('dd', null, yes(server.secret_scanning)),
            h('dt', null, 'EPSS / KEV'), h('dd', null, yes(server.epss_enabled) + ' / ' + yes(server.kev_enabled)),
            h('dt', null, 'Offline mode'), h('dd', null, yes(server.offline)),
            h('dt', null, 'Notifications'), h('dd', null, yes(server.notifications_on)),
            h('dt', null, 'History kept'), h('dd', null, server.history_keep + ' scans per image'))))),
    state.me.user ? tokensCard({ allowAdmin: false }) : null,
    h('section', { class: 'card flush' }, h('div', { class: 'pad row' }, h('h3', null, 'Accepted risks'), h('div', { class: 'spacer' }), h('a', { class: 'btn small', href: 'api/vex' }, 'Export OpenVEX')),
      dataTable(ignores, [
        { key: 'vuln_id', label: 'Vulnerability' }, { key: 'pkg', label: 'Package' }, { key: 'image', label: 'Image' },
        { key: 'status', label: 'Status' }, { key: 'reason', label: 'Reason' },
        { key: 'expires_at', label: 'Expires', render: (r) => (r.expires_at ? fmtTime(r.expires_at) : 'never') },
        { key: 'created_by', label: 'By' },
      ], { empty: 'No accepted risks.' })));
}

boot();
