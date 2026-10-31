'use strict';
// ConfigBridge console. Plain DOM, no innerHTML: every vendor value is rendered
// as text. The tenant API key lives only in this variable (lost on reload).
const S = { key: null, tenant: '', meta: null, paths: {} };

// ---------- tiny helpers ----------
function h(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') e.className = v;
    else if (k === 'style') e.style.cssText = v; // CSSOM: allowed under style-src 'self' (attributes are not)
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else if (k === 'value') e.value = v;
    else if (k === 'checked') e.checked = !!v;
    else e.setAttribute(k, v === true ? '' : v);
  }
  for (const c of kids.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    e.append(c instanceof Node ? c : String(c));
  }
  return e;
}
const app = () => document.getElementById('app');
function get(o, path) {
  for (const p of path.split('.')) { if (o == null) return undefined; o = o[p]; }
  return o;
}
function toast(msg, bad) {
  const t = h('div', { class: 'toast' + (bad ? ' bad' : '') }, msg);
  document.getElementById('toasts').append(t);
  setTimeout(() => t.remove(), bad ? 6000 : 3500);
}
function ago(v) {
  if (!v) return '—';
  const d = typeof v === 'number' ? new Date(v) : new Date(v);
  if (isNaN(d)) return String(v);
  const s = Math.round((Date.now() - d.getTime()) / 1000);
  if (s < 60) return s + 's ago';
  if (s < 3600) return Math.round(s / 60) + 'm ago';
  if (s < 86400) return Math.round(s / 3600) + 'h ago';
  return d.toISOString().slice(0, 10);
}
function when(v) {
  if (v === null || v === undefined || v === '') return '—';
  const d = new Date(v);
  return isNaN(d) ? String(v) : d.toISOString().replace('T', ' ').slice(0, 19) + 'Z';
}
const short = (s, n = 10) => (s ? String(s).slice(0, n) : '');
const OK = ['healthy', 'success', 'live'];
const WARN = ['degraded', 'completed_with_errors', 'incomplete', 'draft', 'approved', 'partial'];
function pill(v) {
  const s = String(v || 'idle');
  const cls = OK.includes(s) ? 'ok' : WARN.includes(s) ? 'warn' : ['idle', 'running', 'test'].includes(s) ? '' : 'bad';
  return h('span', { class: 'pill ' + cls }, s.replace(/_/g, ' '));
}
async function busy(btn, fn) {
  btn.disabled = true; btn.classList.add('busy');
  try { return await fn(); } finally { btn.disabled = false; btn.classList.remove('busy'); }
}

// ---------- API ----------
async function api(method, path, body) {
  const opt = { method, cache: 'no-store', credentials: 'omit', redirect: 'error',
    headers: { Authorization: 'Bearer ' + S.key, Accept: 'application/json' } };
  if (body !== undefined) { opt.headers['Content-Type'] = 'application/json'; opt.body = typeof body === 'string' ? body : JSON.stringify(body); }
  let r;
  try { r = await fetch(path, opt); } catch (e) { toast('API unreachable', true); throw e; }
  const text = await r.text();
  let data = null;
  if (text) { try { data = JSON.parse(text); } catch { data = text; } }
  if (r.status === 401) { lock('Key rejected or expired.'); throw new Error('unauthorized'); }
  return { ok: r.ok, status: r.status, data };
}
async function must(method, path, body) {
  const r = await api(method, path, body);
  if (!r.ok) { const m = (r.data && r.data.error) || 'HTTP ' + r.status; toast(m.replace(/_/g, ' '), true); throw new Error(m); }
  return r.data;
}

// ---------- OCSF metadata (public, from /ui/ocsf.json) ----------
async function loadMeta() {
  if (S.meta) return;
  const r = await fetch('ocsf.json', { cache: 'no-store', credentials: 'omit' });
  S.meta = await r.json();
}
const classes = () => S.meta.schema.classes;
const objects = () => S.meta.schema.objects;
function classLabel(name) { const c = classes()[name]; return c ? `${c.caption} (${c.uid})` : name; }
// attrAt resolves an OCSF path like "vulnerabilities.0.cve.uid" to its attribute.
function attrAt(cls, path) {
  let attrs = (classes()[cls] || {}).attributes, a = null;
  for (const seg of path.split('.')) {
    if (/^\d+$/.test(seg)) continue;
    if (!attrs) return null;
    a = attrs[seg];
    if (!a) return null;
    attrs = a.object_type ? (objects()[a.object_type] || {}).attributes : null;
  }
  return a;
}
const PLATFORM_FILLED = { time: 1, severity_id: 1 };
// pathsFor lists mappable leaf paths for a class (depth-limited, cycle-safe).
function pathsFor(cls) {
  if (S.paths[cls]) return S.paths[cls];
  const out = [], owned = S.meta.platform_owned;
  (function walk(attrs, prefix, depth, seen) {
    for (const [name, a] of Object.entries(attrs || {}).sort()) {
      const p = prefix + name + (a.is_array ? '.0' : '');
      if (owned[prefix + name] || owned[name] && !prefix) continue;
      if (a.object_type) {
        if (depth < 4 && !seen.includes(a.object_type) && out.length < 2500)
          walk((objects()[a.object_type] || {}).attributes, p + '.', depth + 1, seen.concat(a.object_type));
      } else out.push([p, a.type.replace(/_t$/, '') + (a.requirement === 'required' ? ' · required' : '')]);
    }
  })(classes()[cls].attributes, '', 0, []);
  out.push(['unmapped.<your_field>', 'free-form vendor field']);
  return (S.paths[cls] = out);
}
function enumText(a) {
  if (!a || !a.enum) return '';
  return Object.entries(a.enum).map(([k, v]) => `${k}=${v}`).join(', ');
}

// ---------- shell ----------
const NAV = [['overview', 'Overview'], ['connectors', 'Connectors'], ['builder', 'New connector'], ['records', 'OCSF records'], ['quarantine', 'Quarantine'], ['runs', 'Runs'], ['secrets', 'Secrets']];
function lock(msg) {
  S.key = null;
  app().replaceChildren(loginView(msg));
}
function loginView(msg) {
  const input = h('input', { type: 'password', autocomplete: 'off', spellcheck: 'false', placeholder: 'Tenant API key', 'aria-label': 'Tenant API key' });
  const err = h('div', { class: 'small', style: 'color:var(--bad)' }, msg || '');
  const go = h('button', { class: 'primary', type: 'submit' }, 'Unlock console');
  const form = h('form', { class: 'bd', onsubmit: async (e) => {
    e.preventDefault();
    const k = input.value.trim();
    if (k.length < 32) { err.textContent = 'That is not a tenant API key.'; return; }
    S.key = k; input.value = '';
    await busy(go, async () => {
      try {
        const r = await api('GET', '/health?limit=100');
        if (!r.ok) { err.textContent = 'API error ' + r.status; S.key = null; return; }
        S.tenant = (r.data[0] && r.data[0].tenant_id) || '';
        await loadMeta();
        shell();
      } catch { if (S.key) err.textContent = 'API unreachable.'; }
    });
  } },
  h('div', { class: 'brand', style: 'padding:0' }, h('span', { class: 'logo' }, 'CB'), 'ConfigBridge'),
  h('div', {}, h('h1', {}, 'Sign in to your tenant'), h('p', { class: 'muted small', style: 'margin:6px 0 0' },
    'Paste the tenant API key. It is kept in this tab\'s memory only: never stored, sent only to this API, gone on reload.')),
  input, err, go);
  return h('div', { class: 'login' }, h('div', { class: 'card' }, form));
}
function shell() {
  const nav = h('nav', { class: 'nav' }, NAV.map(([id, label]) => h('a', { href: '#/' + id, 'data-v': id }, label)));
  const side = h('aside', { class: 'side' },
    h('div', { class: 'brand' }, h('span', { class: 'logo' }, 'CB'), 'ConfigBridge'), nav,
    h('div', { class: 'foot' },
      h('div', {}, 'Tenant ', h('code', {}, S.tenant || 'unknown')),
      h('div', {}, 'OCSF ', h('code', {}, S.meta.schema.version)),
      h('button', { class: 'sm', onclick: () => lock('Locked.') }, 'Lock')));
  app().replaceChildren(h('div', { class: 'shell' }, side, h('main', { class: 'main', id: 'view' })));
  route();
}
function route() {
  document.querySelectorAll('.drawer, .scrim').forEach((x) => x.remove());
  if (!S.key) return;
  const [, view = 'overview', arg = ''] = (location.hash || '#/overview').split('/');
  const q = new URLSearchParams((location.hash.split('?')[1]) || '');
  document.querySelectorAll('.nav a').forEach((a) => a.classList.toggle('on', a.dataset.v === view.split('?')[0]));
  const v = document.getElementById('view');
  if (!v) return;
  const name = view.split('?')[0];
  const fn = { overview, connectors, builder, records, quarantine, runs, secrets }[name] || overview;
  v.replaceChildren(h('div', { class: 'muted' }, 'Loading…'));
  fn(v, decodeURIComponent(arg.split('?')[0]), q).catch((e) => {
    if (S.key) v.replaceChildren(h('div', { class: 'card' }, h('div', { class: 'empty' }, 'Could not load: ' + e.message)));
  });
}
window.addEventListener('hashchange', route);
function header(title, sub, ...actions) {
  return h('div', { class: 'head' }, h('div', {}, h('h1', {}, title), sub ? h('p', {}, sub) : null), h('div', { class: 'row' }, actions));
}
function table(cols, rows, onRow) {
  if (!rows.length) return h('div', { class: 'empty' }, 'Nothing here yet.');
  return h('div', { class: 'tbl-wrap' }, h('table', {},
    h('thead', {}, h('tr', {}, cols.map((c) => h('th', { class: c.num ? 'num' : '' }, c.t)))),
    h('tbody', {}, rows.map((r) => h('tr', { class: onRow ? 'click' : '', onclick: onRow ? () => onRow(r) : null },
      cols.map((c) => h('td', { class: (c.num ? 'num ' : '') + (c.clip ? 'clip' : '') }, c.v(r))))))));
}

// ---------- shared actions ----------
async function execute(btn, id, test) {
  return busy(btn, async () => {
    const r = await api('POST', `/connectors/${encodeURIComponent(id)}/${test ? 'test' : 'run'}`);
    const d = r.data || {};
    if (!r.ok && !d.id) { toast((d.error || 'HTTP ' + r.status).replace(/_/g, ' '), true); return null; }
    const msg = `${id} ${test ? 'test' : 'run'}: ${d.outcome} · ${d.received} received, ${d.accepted} accepted, ${d.quarantined} quarantined` + (d.skipped ? `, ${d.skipped} skipped` : '') + (d.error ? ` · ${d.error}` : '');
    toast(msg, !r.ok || (d.outcome !== 'success'));
    return d;
  });
}
function runButtons(id, after) {
  const t = h('button', { class: 'sm', onclick: async (e) => { e.stopPropagation(); await execute(t, id, true); after && after(); } }, 'Test');
  const r = h('button', { class: 'sm primary', onclick: async (e) => { e.stopPropagation(); await execute(r, id, false); after && after(); } }, 'Run');
  return h('div', { class: 'row', style: 'flex-wrap:nowrap' }, t, r);
}
function countsBar(r) {
  const tot = Math.max(1, r.received || 0);
  return h('div', { style: 'min-width:120px' },
    h('div', { class: 'bar', title: `${r.accepted} accepted · ${r.quarantined} quarantined · ${r.skipped || 0} skipped` },
      h('span', { class: 'a', style: `width:${(100 * r.accepted) / tot}%` }),
      h('span', { class: 'q', style: `width:${(100 * r.quarantined) / tot}%` }),
      h('span', { class: 's', style: `width:${(100 * (r.skipped || 0)) / tot}%` })),
    h('div', { class: 'small muted', style: 'margin-top:3px' }, `${r.accepted}/${r.received}` + (r.quarantined ? ` · ${r.quarantined} q` : '') + (r.skipped ? ` · ${r.skipped} skipped` : '')));
}

// ---------- views ----------
async function overview(v) {
  const [health, runList, cfgs] = await Promise.all([must('GET', '/health?limit=500'), must('GET', '/runs?limit=200'), must('GET', '/configs?limit=500')]);
  const real = runList.filter((r) => r.mode !== 'test');
  const bad = health.filter((x) => !['healthy', 'idle'].includes(x.status));
  const sum = (k) => real.reduce((a, r) => a + (r[k] || 0), 0);
  const kpi = (val, label) => h('div', { class: 'kpi' }, h('div', { class: 'v' }, val), h('div', { class: 'l' }, label));
  const refresh = () => route();
  v.replaceChildren(
    header('Overview', 'Every connector writes OCSF ' + S.meta.schema.version + ' events into one tenant-isolated store.',
      h('a', { class: 'btn', href: '#/builder' }, 'New connector')),
    h('div', { class: 'kpis' },
      kpi(cfgs.length, 'connectors'), kpi(health.length, 'live'),
      kpi(health.filter((x) => x.status === 'healthy').length, 'healthy'),
      kpi(bad.length, 'need attention'),
      kpi(sum('accepted').toLocaleString(), `accepted (last ${real.length} runs)`),
      kpi(sum('quarantined').toLocaleString(), 'quarantined'),
      kpi(sum('skipped').toLocaleString(), 'skipped by filter')),
    h('div', { class: 'stack' },
      h('div', { class: 'card' }, h('div', { class: 'hd' }, h('h2', {}, 'Connection health'), h('button', { class: 'ghost sm', onclick: refresh }, 'Refresh')),
        table([
          { t: 'Connector', v: (x) => h('div', {}, h('div', {}, x.name), h('code', { class: 'faint' }, x.connector)) },
          { t: 'Status', v: (x) => pill(x.status) },
          { t: 'Last attempt', v: (x) => ago(x.last_run) },
          { t: 'Last clean success', v: (x) => ago(x.last_success) },
          { t: 'Accepted', num: 1, v: (x) => x.accepted.toLocaleString() },
          { t: 'Error', v: (x) => x.error ? h('code', {}, x.error) : h('span', { class: 'faint' }, '—') },
          { t: '', v: (x) => runButtons(x.connector, refresh) },
        ], health)),
      h('div', { class: 'card' }, h('div', { class: 'hd' }, h('h2', {}, 'Recent runs'), h('a', { href: '#/runs', class: 'small muted' }, 'All runs')),
        runTable(runList.slice(0, 8)))));
}
function runTable(list) {
  return table([
    { t: 'Started', v: (r) => h('span', { title: when(r.started_at) }, ago(r.started_at)) },
    { t: 'Connector', v: (r) => h('code', {}, r.connector) },
    { t: 'Mode', v: (r) => h('span', { class: 'tag' }, r.mode) },
    { t: 'Outcome', v: (r) => pill(r.outcome) },
    { t: 'Records', v: countsBar },
    { t: 'Pages', num: 1, v: (r) => r.pages },
    { t: 'Attempts', num: 1, v: (r) => r.attempts },
    { t: 'Config', v: (r) => h('code', { class: 'faint', title: r.config_hash }, 'rev ' + r.config_version + ' · ' + short(r.config_hash, 8)) },
    { t: 'Error', v: (r) => r.error ? h('code', {}, r.error) : '' },
  ], list);
}
async function connectors(v) {
  const cfgs = await must('GET', '/configs?limit=500');
  v.replaceChildren(
    header('Connectors', 'One JSON config per source. Edits create a new draft revision; only the live revision runs.',
      h('a', { class: 'btn', href: '#/builder' }, 'New connector')),
    h('div', { class: 'card' }, table([
      { t: 'Connector', v: (c) => h('div', {}, h('div', {}, c.name), h('code', { class: 'faint' }, c.id)) },
      { t: 'OCSF class', v: (c) => c.class ? h('span', {}, classLabel(c.class)) : '—' },
      { t: 'Newest revision', v: (c) => h('div', { class: 'row' }, h('span', {}, 'rev ' + c.revision), pill(c.status)) },
      { t: 'Live', v: (c) => c.live_revision ? 'rev ' + c.live_revision : h('span', { class: 'faint' }, 'not live') },
      { t: 'Config hash', v: (c) => h('code', { class: 'faint', title: c.hash }, short(c.hash, 12)) },
      { t: 'Created', v: (c) => ago(c.created_at) },
      { t: '', v: (c) => h('div', { class: 'row', style: 'flex-wrap:nowrap' },
        h('a', { class: 'btn sm', href: '#/builder/' + encodeURIComponent(c.id), onclick: (e) => e.stopPropagation() }, 'Edit'),
        h('a', { class: 'btn sm', href: `#/records?class=${c.class}&source=${encodeURIComponent(c.id)}`, onclick: (e) => e.stopPropagation() }, 'Records'),
        c.live_revision ? runButtons(c.id, () => route()) : null) },
    ], cfgs)));
}

const COLS = {
  vulnerability_finding: [['finding_info.uid', 'ID'], ['finding_info.title', 'Title', 1], ['vulnerabilities.0.vendor_name', 'Vendor'], ['unmapped.product', 'Product'], ['unmapped.ransomware_use', 'Ransomware'], ['time', 'Time', 0, 't']],
  detection_finding: [['finding_info.uid', 'ID'], ['finding_info.title', 'Title', 1], ['severity', 'Severity'], ['time', 'Time', 0, 't']],
  user_inventory: [['user.uid', 'User ID'], ['user.name', 'Name'], ['user.email_addr', 'Email'], ['user.type', 'Type', 0, 'e:user.type_id'], ['user.ldap_person.last_login_time', 'Last login', 0, 't']],
  inventory_info: [['device.uid', 'Device ID'], ['device.hostname', 'Hostname'], ['device.type_id', 'Type', 0, 'e:device.type_id'], ['device.last_seen_time', 'Last seen', 0, 't']],
  authentication: [['metadata.uid', 'Event ID'], ['user.name', 'User'], ['status', 'Status'], ['time', 'Time', 0, 't']],
};
async function records(v, _arg, q) {
  const cls = q.get('class') || 'vulnerability_finding';
  const source = q.get('source') || '';
  const offset = +q.get('offset') || 0, limit = 50;
  const [rows, cfgs] = await Promise.all([
    must('GET', `/records/${cls}?limit=${limit}&offset=${offset}` + (source ? '&source=' + encodeURIComponent(source) : '')),
    must('GET', '/configs?limit=500')]);
  const nav = (o) => { const p = new URLSearchParams({ class: o.class ?? cls, source: o.source ?? source, offset: o.offset ?? 0 }); location.hash = '#/records?' + p; };
  const clsSel = h('select', { onchange: (e) => nav({ class: e.target.value, source: '' }) },
    Object.keys(classes()).sort().map((n) => h('option', { value: n, selected: n === cls }, classLabel(n))));
  const srcSel = h('select', { onchange: (e) => nav({ source: e.target.value }) }, h('option', { value: '' }, 'All sources'),
    cfgs.filter((c) => c.class === cls).map((c) => h('option', { value: c.id, selected: c.id === source }, c.id)));
  const search = h('input', { type: 'search', placeholder: 'Filter this page…' });
  const cols = (COLS[cls] || [['metadata.uid', 'ID']]).map(([p, t, clip, kind]) => ({ t, clip, v: (r) => {
    if (kind === 't') return h('span', { class: 'small' }, when(get(r, p)));
    if (kind && kind.startsWith('e:')) { const ep = kind.slice(2), val = get(r, ep); const a = attrAt(cls, ep); return val === undefined ? '—' : (a && a.enum && a.enum[val]) || String(val); }
    const val = get(r, p); return val === undefined || val === null ? h('span', { class: 'faint' }, '—') : String(val);
  } }));
  cols.push({ t: 'Source', v: (r) => h('code', { class: 'faint' }, get(r, 'metadata.source')) });
  const body = h('div', {}, table(cols, rows, showRecord));
  search.addEventListener('input', () => {
    const s = search.value.toLowerCase();
    body.replaceChildren(table(cols, s ? rows.filter((r) => JSON.stringify(r).toLowerCase().includes(s)) : rows, showRecord));
  });
  v.replaceChildren(
    header('OCSF records', 'Stored events, exactly as a SIEM or Security Lake would ingest them. Click a row for the full event.'),
    h('div', { class: 'card' },
      h('div', { class: 'hd' }, h('div', { class: 'row grow' }, h('div', { style: 'width:280px' }, clsSel), h('div', { style: 'width:220px' }, srcSel), h('div', { style: 'width:220px' }, search)),
        h('div', { class: 'row' }, h('span', { class: 'small muted' }, `${offset + 1}–${offset + rows.length}`),
          h('button', { class: 'sm', disabled: offset === 0, onclick: () => nav({ offset: Math.max(0, offset - limit) }) }, 'Prev'),
          h('button', { class: 'sm', disabled: rows.length < limit, onclick: () => nav({ offset: offset + limit }) }, 'Next'))),
      body));
}
function jsonNode(v, ind = '') {
  const pad = ind + '  ';
  if (v === null) return h('span', { class: 'j-z' }, 'null');
  if (Array.isArray(v)) {
    if (!v.length) return '[]';
    return ['[\n', v.map((x, i) => [pad, jsonNode(x, pad), i < v.length - 1 ? ',\n' : '\n']), ind, ']'];
  }
  if (typeof v === 'object') {
    const ks = Object.keys(v);
    if (!ks.length) return '{}';
    return ['{\n', ks.map((k, i) => [pad, h('span', { class: 'j-k' }, JSON.stringify(k)), ': ', jsonNode(v[k], pad), i < ks.length - 1 ? ',\n' : '\n']), ind, '}'];
  }
  const cls = typeof v === 'string' ? 'j-s' : typeof v === 'number' ? 'j-n' : 'j-b';
  return h('span', { class: cls }, JSON.stringify(v));
}
function drawer(title, ...content) {
  const close = () => { d.remove(); s.remove(); document.removeEventListener('keydown', esc); };
  const esc = (e) => e.key === 'Escape' && close();
  const s = h('div', { class: 'scrim', onclick: close });
  const d = h('div', { class: 'drawer', role: 'dialog', 'aria-label': title },
    h('div', { class: 'hd' }, h('h2', {}, title), h('button', { class: 'ghost', onclick: close, 'aria-label': 'Close' }, 'Close')),
    h('div', { class: 'bd' }, content));
  document.addEventListener('keydown', esc);
  document.body.append(s, d);
}
function showRecord(r) {
  const copy = h('button', { class: 'sm', onclick: async () => { await navigator.clipboard.writeText(JSON.stringify(r, null, 2)); toast('Copied'); } }, 'Copy JSON');
  drawer(get(r, 'class_name') + ' · ' + (get(r, 'finding_info.uid') || get(r, 'user.uid') || get(r, 'device.uid') || ''),
    h('div', { class: 'row', style: 'margin-bottom:12px' },
      h('span', { class: 'tag' }, 'class_uid ' + r.class_uid), h('span', { class: 'tag' }, 'type_uid ' + r.type_uid),
      h('span', { class: 'tag' }, 'OCSF ' + get(r, 'metadata.version')), h('span', { class: 'grow' }), copy),
    h('pre', { class: 'code' }, jsonNode(r)));
}
async function quarantine(v, _a, q) {
  const id = q.get('connector') || '';
  const [rows, cfgs] = await Promise.all([must('GET', '/quarantine?limit=500' + (id ? '&connector=' + encodeURIComponent(id) : '')), must('GET', '/configs?limit=500')]);
  const groups = {};
  for (const r of rows) { const k = r.source + '\u0000' + r.field + '\u0000' + r.reason; (groups[k] = groups[k] || { ...r, n: 0 }).n++; }
  const sel = h('select', { style: 'width:240px', onchange: (e) => { location.hash = '#/quarantine?connector=' + encodeURIComponent(e.target.value); } },
    h('option', { value: '' }, 'All connectors'), cfgs.map((c) => h('option', { value: c.id, selected: c.id === id }, c.id)));
  v.replaceChildren(
    header('Quarantine', 'Records that failed a required mapping, an OCSF type or an enum. The rest of the page still landed. Raw payloads are never stored.', sel),
    h('div', { class: 'stack' },
      h('div', { class: 'card' }, h('div', { class: 'hd' }, h('h2', {}, 'Grouped by cause'), h('span', { class: 'small muted' }, 'one config fix usually clears a whole group')),
        table([{ t: 'Rows', num: 1, v: (g) => g.n }, { t: 'Connector', v: (g) => h('code', {}, g.source) }, { t: 'OCSF field', v: (g) => h('code', {}, g.field) }, { t: 'Reason', v: (g) => g.reason },
          { t: '', v: (g) => h('a', { class: 'btn sm', href: '#/builder/' + encodeURIComponent(g.source) }, 'Fix config') }],
        Object.values(groups).sort((a, b) => b.n - a.n))),
      h('div', { class: 'card' }, h('div', { class: 'hd' }, h('h2', {}, 'Rows'), h('span', { class: 'small muted' }, rows.length + ' newest')),
        table([{ t: 'Run', v: (r) => h('code', { class: 'faint' }, short(r.run_id, 12)) }, { t: 'Connector', v: (r) => h('code', {}, r.source) },
          { t: 'Page', num: 1, v: (r) => r.page }, { t: 'Index', num: 1, v: (r) => r.record_index }, { t: 'Field', v: (r) => h('code', {}, r.field) }, { t: 'Reason', v: (r) => r.reason }], rows))));
}
async function runs(v, _a, q) {
  const id = q.get('connector') || '';
  const [list, cfgs] = await Promise.all([must('GET', '/runs?limit=200' + (id ? '&connector=' + encodeURIComponent(id) : '')), must('GET', '/configs?limit=500')]);
  const sel = h('select', { style: 'width:240px', onchange: (e) => { location.hash = '#/runs?connector=' + encodeURIComponent(e.target.value); } },
    h('option', { value: '' }, 'All connectors'), cfgs.map((c) => h('option', { value: c.id, selected: c.id === id }, c.id)));
  v.replaceChildren(header('Runs', 'Every run is pinned to the exact config revision and SHA-256 hash it used.', sel), h('div', { class: 'card' }, runTable(list)));
}
async function secrets(v) {
  const list = await must('GET', '/secrets?limit=500');
  const name = h('input', { placeholder: 'github_token', autocomplete: 'off', spellcheck: 'false' });
  const host = h('input', { placeholder: 'api.github.com', autocomplete: 'off', spellcheck: 'false' });
  const val = h('input', { type: 'password', placeholder: 'value (write-only)', autocomplete: 'new-password' });
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(location.hostname);
  const save = h('button', { class: 'primary', type: 'submit' }, 'Store secret');
  const form = h('form', { class: 'bd stack', onsubmit: async (e) => {
    e.preventDefault();
    if (!name.value || !host.value || !val.value) { toast('Name, host and value are all required', true); return; }
    await busy(save, async () => {
      const r = await api('PUT', '/secrets/' + encodeURIComponent(name.value.trim()), { value: val.value, allowed_host: host.value.trim() });
      val.value = '';
      if (r.status === 204) { toast('Stored ' + name.value + ' (bound to ' + host.value + ')'); route(); }
      else toast(((r.data && r.data.error) || 'HTTP ' + r.status).replace(/_/g, ' '), true);
    });
  } },
  h('div', { class: 'grid3' }, h('label', { class: 'f' }, 'Name', name), h('label', { class: 'f' }, 'Allowed host', host), h('label', { class: 'f' }, 'Value', val)),
  h('div', { class: 'row spread' }, h('span', { class: 'small muted' }, 'Encrypted per tenant (AES-256-GCM locally, Secrets Manager + KMS in prod). Only ever sent to the bound host. Never shown again.'), save),
  !local && location.protocol !== 'https:' ? h('div', { class: 'issues' }, h('li', {}, 'This page is not on HTTPS. Do not store real secrets over plain HTTP.')) : null);
  v.replaceChildren(header('Secrets', 'Configs reference a secret by name. Values are write-only.'),
    h('div', { class: 'stack' }, h('div', { class: 'card' }, h('div', { class: 'hd' }, h('h2', {}, 'Add or rotate')), form),
      h('div', { class: 'card' }, table([{ t: 'Name', v: (s) => h('code', {}, s.name) }, { t: 'Bound host', v: (s) => h('code', {}, s.allowed_host) },
        { t: 'Backend', v: (s) => h('span', { class: 'tag' }, s.backend) }, { t: 'Created', v: (s) => ago(s.created_at) }, { t: 'Updated', v: (s) => ago(s.updated_at) }], list))));
}

// ---------- builder (B-5): form <-> config JSON, same validator as the API ----------
const kv = (o) => Object.entries(o || {}).map(([k, x]) => [k, String(x)]);
const obj = (rows) => Object.fromEntries(rows.filter(([k]) => k.trim()).map(([k, x]) => [k.trim(), x]));
const num = (x) => (x === '' || x === undefined || x === null || isNaN(+x) ? undefined : +x);
function blank() {
  return { id: '', name: '', url: '', timeout: '20', ports: '', params: [], headers: [['Accept', 'application/json']],
    auth: { type: 'none', secret: '', header: '', username: '', token_url: '', client_id: '', scopes: '', extra: [], tpl: [] },
    items_path: '', pag: { type: 'none', page_param: 'page', start_page: '1', offset_param: 'offset', size_param: 'limit', page_size: '100', cursor_param: '', cursor_path: '' },
    filter: [], cls: 'user_inventory', activity: '', rows: [{ o: 'user.uid', src: 'path', val: 'id', tf: 'string', req: true, lookup: '', def: '', fmt: '', tz: '' }],
    sched: { enabled: false, interval: '3600' }, limits: { max_pages: '10', max_records: '1000', max_response_bytes: '1048576', max_run_seconds: '60' },
    retry: { max_attempts: '4', base_delay_ms: '1000', max_retry_after_seconds: '60' } };
}
function parse(c) {
  const f = blank(), a = c.auth || {}, p = c.pagination || {}, r = c.request || {};
  Object.assign(f, { id: c.id || '', name: c.name || '', url: r.url || '', timeout: String(r.timeout_seconds || ''), ports: (r.allowed_ports || []).join(', '),
    params: kv(r.params), headers: kv(r.headers), items_path: c.items_path || '', cls: (c.destination || {}).class || 'user_inventory',
    activity: (c.destination || {}).activity_id ? String(c.destination.activity_id) : '' });
  f.auth = { type: a.type || 'none', secret: a.secret || '', header: a.header || '', username: a.username || '', token_url: a.token_url || '', client_id: a.client_id || '',
    scopes: (a.scopes || []).join(', '), extra: kv(a.extra_params), tpl: (a.headers || []).map((x) => [x.name, x.value]) };
  for (const k of Object.keys(f.pag)) if (k !== 'type') f.pag[k] = p[k] !== undefined && p[k] !== 0 && p[k] !== '' ? String(p[k]) : '';
  f.pag.type = p.type || 'none';
  f.filter = (c.filter || []).map((x) => ({ path: x.path, op: x.op, value: Array.isArray(x.value) ? x.value.join(', ') : String(x.value ?? '') }));
  f.rows = Object.entries((c.destination || {}).mapping || {}).map(([o, m]) => ({ o, src: m.path !== undefined ? 'path' : 'constant',
    val: m.path !== undefined ? m.path : String(m.constant ?? ''), tf: m.transform || '', req: !!m.required,
    lookup: Object.entries(m.lookup || {}).map(([k, x]) => `${k}=${x}`).join('\n'), def: m.default !== undefined ? String(m.default) : '', fmt: m.format || '', tz: m.timezone || '' }));
  const s = c.schedule || {}, l = c.limits || {}, t = c.retry || {};
  f.sched = { enabled: !!s.enabled, interval: String(s.interval_seconds || '') };
  for (const k of Object.keys(f.limits)) f.limits[k] = l[k] ? String(l[k]) : '';
  for (const k of Object.keys(f.retry)) f.retry[k] = t[k] ? String(t[k]) : '';
  return f;
}
function serialize(f) {
  const a = f.auth, t = a.type, auth = { type: t };
  if (t !== 'none') auth.secret = a.secret.trim();
  if (t === 'api_key') auth.header = a.header.trim();
  if (t === 'basic') auth.username = a.username.trim();
  if (t === 'oauth2_client_credentials') {
    auth.token_url = a.token_url.trim();
    if (a.client_id.trim()) auth.client_id = a.client_id.trim();
    const sc = a.scopes.split(',').map((x) => x.trim()).filter(Boolean); if (sc.length) auth.scopes = sc;
    const ex = obj(a.extra); if (Object.keys(ex).length) auth.extra_params = ex;
  }
  if (t === 'static') auth.headers = a.tpl.filter(([n]) => n.trim()).map(([name, value]) => ({ name: name.trim(), value }));
  const pag = { type: f.pag.type }, P = f.pag;
  const put = (k, isNum) => { if (P[k] !== '') pag[k] = isNum ? num(P[k]) : P[k].trim(); };
  if (P.type === 'page') { put('page_param'); put('start_page', 1); put('size_param'); put('page_size', 1); }
  if (P.type === 'offset') { put('offset_param'); put('size_param'); put('page_size', 1); }
  if (P.type === 'cursor') { put('cursor_param'); put('cursor_path'); put('size_param'); put('page_size', 1); }
  const request = { method: 'GET', url: f.url.trim() };
  if (num(f.timeout)) request.timeout_seconds = num(f.timeout);
  const ps = obj(f.params), hs = obj(f.headers);
  if (Object.keys(ps).length) request.params = ps;
  if (Object.keys(hs).length) request.headers = hs;
  const ports = f.ports.split(',').map((x) => num(x.trim())).filter(Boolean); if (ports.length) request.allowed_ports = ports;
  const mapping = {};
  for (const r of f.rows) {
    if (!r.o.trim()) continue;
    const m = {};
    if (r.src === 'path') m.path = r.val.trim(); else m.constant = r.val;
    if (r.req) m.required = true;
    if (r.tf) m.transform = r.tf;
    if (r.def !== '') m.default = r.def;
    if (r.tf === 'datetime' && r.fmt) m.format = r.fmt;
    if (r.tf === 'datetime' && r.tz) m.timezone = r.tz;
    if (r.tf === 'lookup') m.lookup = Object.fromEntries(r.lookup.split(/\n|,/).map((x) => x.split('=').map((y) => y.trim())).filter((x) => x.length === 2 && x[0]));
    mapping[r.o.trim()] = m;
  }
  const filter = f.filter.filter((x) => x.path.trim()).map((x) => ({ path: x.path.trim(), op: x.op,
    value: x.op === 'in' ? x.value.split(',').map((y) => y.trim()).filter(Boolean) : x.op === 'exists' ? x.value !== 'false' : x.op === 'within_days' ? num(x.value) : x.value }));
  const limits = {}, retry = {};
  for (const [k, x] of Object.entries(f.limits)) if (num(x)) limits[k] = num(x);
  for (const [k, x] of Object.entries(f.retry)) if (num(x)) retry[k] = num(x);
  const dest = { class: f.cls, mapping };
  if (num(f.activity)) dest.activity_id = num(f.activity);
  const c = { version: 1, id: f.id.trim(), name: f.name.trim(), request, auth, items_path: f.items_path.trim(), pagination: pag,
    schedule: { enabled: f.sched.enabled, interval_seconds: num(f.sched.interval) || 3600 } };
  if (filter.length) c.filter = filter;
  c.destination = dest;
  if (Object.keys(limits).length) c.limits = limits;
  if (Object.keys(retry).length) c.retry = retry;
  return c;
}

const B = { f: null, saved: null, steps: {}, issues: [], secretNames: [] };
async function builder(v, id) {
  B.saved = null; B.steps = {}; B.issues = [];
  const [sec, existing] = await Promise.all([must('GET', '/secrets?limit=500'), id ? must('GET', '/configs/' + encodeURIComponent(id)) : null]);
  B.secretNames = sec.map((s) => [s.name, s.allowed_host]);
  B.f = existing ? parse(existing.config) : blank();
  B.existing = existing;
  renderBuilder(v);
}
function renderBuilder(v) {
  const f = B.f;
  const json = h('textarea', { class: 'json', spellcheck: 'false', 'aria-label': 'Config JSON' });
  const refreshJSON = () => { json.value = JSON.stringify(serialize(f), null, 2); };
  const rerender = () => renderBuilder(v);
  // inp binds an input to obj[key]; changes update the JSON preview without re-rendering (keeps focus).
  const inp = (o, k, attrs = {}) => h('input', { value: o[k], spellcheck: 'false', autocomplete: 'off', ...attrs, oninput: (e) => { o[k] = e.target.value; refreshJSON(); } });
  const sel = (o, k, opts, re = true) => h('select', { onchange: (e) => { o[k] = e.target.value; re ? rerender() : refreshJSON(); } },
    opts.map(([val, label]) => h('option', { value: val, selected: String(o[k]) === String(val) }, label || val)));
  const field = (label, control, hint) => h('label', { class: 'f' }, h('span', {}, label, hint ? h('span', { class: 'hint' }, ' · ' + hint) : null), control);
  const del = (arr, i) => h('button', { class: 'ghost sm', type: 'button', 'aria-label': 'Remove', onclick: () => { arr.splice(i, 1); rerender(); } }, '×');
  const kvRows = (arr, ph) => h('div', {}, arr.map((row, i) => h('div', { class: 'krow' }, inp(row, 0, { placeholder: ph[0] }), inp(row, 1, { placeholder: ph[1] }), del(arr, i))),
    h('button', { class: 'sm', type: 'button', onclick: () => { arr.push(['', '']); rerender(); } }, '+ Add'));
  const section = (title, sub, ...body) => h('div', { class: 'card' }, h('div', { class: 'hd' }, h('div', {}, h('h2', {}, title), sub ? h('div', { class: 'small muted' }, sub) : null)), h('div', { class: 'bd stack' }, body));

  // auth fields
  const a = f.auth, at = a.type;
  const secretList = h('datalist', { id: 'secret-names' }, B.secretNames.map(([n, host]) => h('option', { value: n }, n + ' → ' + host)));
  const authBody = [field('Type', sel(a, 'type', [['none'], ['api_key'], ['bearer'], ['basic'], ['oauth2_client_credentials'], ['static']]))];
  if (at !== 'none') authBody.push(field('Secret name', inp(a, 'secret', { list: 'secret-names', placeholder: 'stored with Secrets → never the value' }), 'stored on the Secrets page'));
  if (at === 'api_key') authBody.push(field('Header', inp(a, 'header', { placeholder: 'X-API-Key' })));
  if (at === 'basic') authBody.push(field('Username', inp(a, 'username', { placeholder: 'me@company.com' })));
  if (at === 'oauth2_client_credentials') authBody.push(field('Token URL', inp(a, 'token_url', { placeholder: 'https://auth.vendor.com/oauth2/token' })),
    h('div', { class: 'grid2' }, field('Client ID', inp(a, 'client_id', { placeholder: 'empty = secret field client_id' })), field('Scopes', inp(a, 'scopes', { placeholder: 'read, users.read' }))),
    field('Extra token params', kvRows(a.extra, ['audience', 'value'])));
  if (at === 'static') authBody.push(field('Headers', kvRows(a.tpl, ['Authorization', 'SSWS {{secret.value}}']), 'only {{secret.<field>}} placeholders'));

  // pagination
  const P = f.pag, pt = P.type;
  const pagBody = [field('Type', sel(P, 'type', [['none'], ['page'], ['offset'], ['link', 'link (HTTP Link header)'], ['cursor']]))];
  if (pt === 'page') pagBody.push(h('div', { class: 'grid4' }, field('Page param', inp(P, 'page_param')), field('Start page', inp(P, 'start_page')), field('Size param', inp(P, 'size_param')), field('Page size', inp(P, 'page_size'))));
  if (pt === 'offset') pagBody.push(h('div', { class: 'grid3' }, field('Offset param', inp(P, 'offset_param')), field('Size param', inp(P, 'size_param')), field('Page size', inp(P, 'page_size'))));
  if (pt === 'cursor') pagBody.push(h('div', { class: 'grid4' }, field('Cursor param', inp(P, 'cursor_param')), field('Cursor path', inp(P, 'cursor_path', { placeholder: 'meta.next' })), field('Size param', inp(P, 'size_param')), field('Page size', inp(P, 'page_size'))));

  // OCSF destination
  const cls = classes()[f.cls], identity = S.meta.identity[f.cls];
  const acts = (cls.attributes.activity_id || {}).enum || {};
  const reqTop = Object.entries(cls.attributes).filter(([n, x]) => x.requirement === 'required' && !S.meta.platform_owned[n] && !PLATFORM_FILLED[n] && n !== 'metadata').map(([n]) => n);
  const pl = h('datalist', { id: 'ocsf-paths' }, pathsFor(f.cls).map(([p, t]) => h('option', { value: p }, t)));
  const mapped = new Set(f.rows.map((r) => r.o.trim()));
  const mapRow = (r, i) => {
    const at2 = attrAt(f.cls, r.o.trim());
    const note = h('div', { class: 'note' });
    const setNote = () => {
      const x = attrAt(f.cls, r.o.trim());
      note.textContent = !r.o.trim() ? '' : r.o.startsWith('unmapped.') ? 'free-form: scalar values only' : !x ? 'not an OCSF attribute of this class' :
        x.type + (x.enum ? ' · enum ' + enumText(x) : '') + (x.type === 'timestamp_t' ? ' · use transform datetime (stored as epoch ms)' : '');
      note.style.color = r.o.trim() && !x && !r.o.startsWith('unmapped.') ? 'var(--bad)' : '';
    };
    setNote();
    const ocsfIn = h('input', { value: r.o, list: 'ocsf-paths', placeholder: 'OCSF path, e.g. user.email_addr', spellcheck: 'false', autocomplete: 'off', class: 'mono',
      oninput: (e) => { r.o = e.target.value; setNote(); refreshJSON(); } });
    const extra = [];
    if (r.tf === 'lookup') extra.push(field('Lookup (vendor=ocsf, one per line)', h('textarea', { rows: 2, value: r.lookup, oninput: (e) => { r.lookup = e.target.value; refreshJSON(); } }), at2 && at2.enum ? enumText(at2) : ''));
    if (r.tf === 'datetime') extra.push(field('Format', inp(r, 'fmt', { placeholder: 'Go layout, empty = RFC3339 / date' })), field('Timezone', inp(r, 'tz', { placeholder: 'Asia/Kolkata (naive times)' })));
    if (r.src === 'path') extra.push(field('Default', inp(r, 'def', { placeholder: 'used when missing' })));
    return h('div', { class: 'maprow' + (r.o.trim() === identity ? ' identity' : '') },
      h('div', { class: 'top' }, ocsfIn, sel(r, 'src', [['path', 'from path'], ['constant', 'constant']]),
        inp(r, 'val', { placeholder: r.src === 'path' ? 'vendor path, e.g. profile.email' : 'fixed value', class: 'mono' }),
        sel(r, 'tf', [['', 'no transform'], ['string'], ['trim'], ['integer'], ['datetime'], ['lookup']]),
        h('label', { class: 'inline-check' }, h('input', { type: 'checkbox', checked: r.req, onchange: (e) => { r.req = e.target.checked; refreshJSON(); } }), 'required'),
        del(f.rows, i)),
      extra.length ? h('div', { class: 'extra' }, extra) : null, note);
  };

  const steps = [['save', 'Save draft', 'POST /configs: full validation, new revision + hash'], ['validate', 'Validate', 're-check the stored revision'],
    ['activate', 'Activate', 'make this revision live'], ['test', 'Test connection', 'one bounded page, nothing written'], ['run', 'Run', 'collect, map to OCSF, store']];
  const stepNode = ([k, t, s], i) => {
    const st = B.steps[k];
    return h('div', { class: 'step' + (st ? (st.ok ? ' done' : ' fail') : '') }, h('div', { class: 'n' }, st ? (st.ok ? '✓' : '!') : i + 1),
      h('div', {}, h('div', { class: 't' }, t), h('div', { class: 's' }, st ? st.msg : s)),
      h('button', { class: 'sm', type: 'button', onclick: (e) => doStep(k, e.currentTarget).then(rerender) }, t.split(' ')[0]));
  };
  const all = h('button', { class: 'primary', type: 'button', onclick: (e) => busy(e.currentTarget, async () => {
    for (const k of ['save', 'validate', 'activate', 'test']) { if (!(await doStep(k))) break; }
    rerender();
  }) }, 'Save → validate → activate → test');

  v.replaceChildren(
    header(B.existing ? 'Edit ' + f.id : 'New connector', B.existing ? `Editing creates a new draft revision (newest is rev ${B.existing.revision}, ${B.existing.status}).` : 'Fill the form or paste JSON. The API runs the same validator either way.',
      h('a', { class: 'btn', href: '#/connectors' }, 'Back')),
    h('div', { class: 'builder' },
      h('div', { class: 'stack' },
        section('Source', null, h('div', { class: 'grid2' }, field('ID', inp(f, 'id', { placeholder: 'okta_users', class: 'mono' }), 'a-z 0-9 _ -'), field('Name', inp(f, 'name', { placeholder: 'Okta users' }))),
          field('URL', inp(f, 'url', { placeholder: 'https://api.vendor.com/v1/users', class: 'mono' }), 'https only, no query string, no credentials'),
          h('div', { class: 'grid2' }, field('Query params', kvRows(f.params, ['limit', '100']), 'non-secret; also server-side filters'), field('Headers', kvRows(f.headers, ['Accept', 'application/json']), 'non-secret')),
          h('div', { class: 'grid2' }, field('Timeout (s)', inp(f, 'timeout')), field('Extra allowed ports', inp(f, 'ports', { placeholder: '443 is default' })))),
        section('Authentication', null, secretList, authBody),
        section('Response and paging', null, field('Items path', inp(f, 'items_path', { placeholder: 'data.items (empty = response is the array)', class: 'mono' })), pagBody),
        section('Filter', 'Keep only matching vendor records (all conditions must match). Dropped records are counted as skipped.',
          f.filter.map((x, i) => h('div', { class: 'frow' }, inp(x, 'path', { placeholder: 'vendor path, e.g. knownRansomwareCampaignUse', class: 'mono' }),
            sel(x, 'op', [['equals'], ['not_equals'], ['in'], ['exists'], ['within_days']], false),
            inp(x, 'value', { placeholder: 'value · in: a, b · exists: true/false · days' }), del(f.filter, i))),
          h('div', {}, h('button', { class: 'sm', type: 'button', onclick: () => { f.filter.push({ path: '', op: 'equals', value: '' }); rerender(); } }, '+ Add condition'))),
        section('OCSF destination', 'Every record becomes one OCSF event of this class. Paths are checked against the pinned schema.',
          h('div', { class: 'grid2' }, field('Class', sel(f, 'cls', Object.keys(classes()).sort().map((n) => [n, classLabel(n)]))),
            field('Activity', sel(f, 'activity', [['', 'default (' + (acts[S.meta.default_activity[f.cls]] || '') + ')']].concat(Object.entries(acts).filter(([k]) => k !== '0').map(([k, x]) => [k, x])), false))),
          h('div', { class: 'classinfo' },
            h('div', {}, h('strong', {}, cls.caption), ' · category ', cls.category_name, ' · class_uid ', h('code', {}, cls.uid)),
            h('div', {}, 'Identity (upsert key): ', h('code', {}, identity), mapped.has(identity) ? '' : h('span', { style: 'color:var(--bad)' }, ' · not mapped yet, must be required')),
            reqTop.length ? h('div', {}, 'Also required by OCSF: ', reqTop.map((n) => h('code', { style: 'margin-right:6px' }, n + (mapped.has(n) || [...mapped].some((m) => m.startsWith(n + '.')) ? ' ✓' : '')))) : null,
            h('div', { class: 'faint' }, 'Set by the platform: class/category/activity/type, severity caption, metadata.version, tenant, source, processed time. Defaults: time = fetch time, severity_id = 0.')),
          pl, f.rows.map(mapRow),
          h('div', { class: 'row' }, h('button', { class: 'sm', type: 'button', onclick: () => { f.rows.push({ o: '', src: 'path', val: '', tf: '', req: false, lookup: '', def: '', fmt: '', tz: '' }); rerender(); } }, '+ Add mapping'),
            !mapped.has(identity) ? h('button', { class: 'sm', type: 'button', onclick: () => { f.rows.unshift({ o: identity, src: 'path', val: 'id', tf: 'string', req: true, lookup: '', def: '', fmt: '', tz: '' }); rerender(); } }, '+ Add identity ' + identity) : null)),
        h('details', { class: 'card', style: 'padding:12px 16px' }, h('summary', {}, 'Schedule, limits and retries'),
          h('div', { class: 'stack', style: 'margin-top:12px' },
            h('div', { class: 'grid2' }, h('label', { class: 'inline-check' }, h('input', { type: 'checkbox', checked: f.sched.enabled, onchange: (e) => { f.sched.enabled = e.target.checked; refreshJSON(); } }), 'Run on a schedule'),
              field('Interval (s)', inp(f.sched, 'interval'))),
            h('div', { class: 'grid4' }, Object.keys(f.limits).map((k) => field(k.replace(/_/g, ' '), inp(f.limits, k)))),
            h('div', { class: 'grid3' }, Object.keys(f.retry).map((k) => field(k.replace(/_/g, ' '), inp(f.retry, k))))))),
      h('div', { class: 'aside' },
        h('div', { class: 'card' }, h('div', { class: 'hd' }, h('h2', {}, 'Pipeline'), B.saved ? h('code', { class: 'faint' }, 'rev ' + B.saved.revision + ' · ' + short(B.saved.hash, 8)) : null),
          h('div', { class: 'bd stack' }, h('div', { class: 'steps' }, steps.map(stepNode)), all,
            B.issues.length ? h('ul', { class: 'issues' }, B.issues.map((x) => h('li', {}, h('code', {}, x.field), ': ', x.message))) : null,
            B.steps.run && B.steps.run.ok ? h('a', { class: 'btn', href: `#/records?class=${f.cls}&source=${encodeURIComponent(f.id)}` }, 'View stored OCSF records') : null)),
        h('div', { class: 'card' }, h('div', { class: 'hd' }, h('h2', {}, 'Config JSON'),
          h('div', { class: 'row' },
            h('button', { class: 'sm', type: 'button', onclick: async () => { await navigator.clipboard.writeText(json.value); toast('Copied'); } }, 'Copy'),
            h('button', { class: 'sm', type: 'button', onclick: () => {
              try { B.f = parse(JSON.parse(json.value)); B.issues = []; rerender(); toast('Form updated from JSON'); } catch (e) { toast('Invalid JSON: ' + e.message, true); }
            } }, 'Apply to form'))),
          h('div', { class: 'bd' }, json, h('div', { class: 'small faint', style: 'margin-top:6px' }, 'Holds secret names only. Paste a config here and press Apply to load it into the form.'))))));
  refreshJSON();
}
async function doStep(k, btn) {
  const run = async () => {
    const f = B.f, id = encodeURIComponent(f.id.trim());
    const set = (ok, msg, issues) => { B.steps[k] = { ok, msg }; if (issues !== undefined) B.issues = issues; return ok; };
    if (k !== 'save' && !B.saved) {
      if (!B.existing || B.existing.config.id !== f.id.trim()) return set(false, 'save a draft first');
    }
    if (k === 'save') {
      const r = await api('POST', '/configs', serialize(f));
      if (r.status === 201) { B.saved = r.data; return set(true, `rev ${r.data.revision} saved as ${r.data.status}`, []); }
      if (r.status === 422) return set(false, r.data.errors.length + ' problem(s)', r.data.errors);
      return set(false, (r.data && r.data.error) || 'HTTP ' + r.status, []);
    }
    if (k === 'validate') {
      const r = await api('POST', `/configs/${id}/validate`);
      if (!r.ok) return set(false, (r.data && r.data.error) || 'HTTP ' + r.status);
      const errs = r.data.errors || [];
      return set(!errs.length, errs.length ? errs.length + ' problem(s)' : 'no problems', errs);
    }
    if (k === 'activate') {
      const rev = (B.saved || B.existing).revision;
      const r = await api('POST', `/configs/${id}/activate`, { revision: rev });
      return set(r.ok, r.ok ? `rev ${rev} is live` : (r.data && r.data.error) || 'HTTP ' + r.status);
    }
    const r = await api('POST', `/connectors/${id}/${k === 'test' ? 'test' : 'run'}`);
    const d = r.data || {};
    if (!d.id) return set(false, (d.error || 'HTTP ' + r.status).replace(/_/g, ' '));
    const msg = `${d.outcome} · ${d.received} received, ${d.accepted} accepted, ${d.quarantined} quarantined` + (d.skipped ? `, ${d.skipped} skipped` : '') + (d.error ? ' · ' + d.error : '');
    return set(r.ok && d.outcome === 'success', msg);
  };
  try { return btn ? await busy(btn, run) : await run(); } catch { return false; }
}

lock();
