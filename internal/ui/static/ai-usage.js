'use strict';
// Metadata only. Operator credentials stay in a page closure, never storage/URLs.
let disposePlatformAI = null;
function clearPlatformAI() {
  if (disposePlatformAI) disposePlatformAI();
  disposePlatformAI = null;
}
function platformAIPage() {
  clearPlatformAI();
  let token = '';
  const controller = new AbortController();
  disposePlatformAI = () => { token = ''; controller.abort(); };
  const panel = h('div', { class: 'stack' });
  const field = h('input', { type: 'password', autocomplete: 'off', required: true, minlength: 32, maxlength: 512 });
  const err = h('div', { class: 'small', role: 'alert' });
  const go = h('button', { type: 'submit', class: 'primary' }, 'Open platform usage');
  const form = h('form', { class: 'bd stack', onsubmit: async (e) => {
    e.preventDefault(); token = field.value.trim(); field.value = '';
    if (token.length < 32) { token = ''; err.textContent = 'Enter the platform operator credential from your private server environment.'; return; }
    await busy(go, async () => {
      const fetcher = async (query) => {
        const r = await fetch('/operator/ai/consumption?' + query, { cache: 'no-store', credentials: 'omit', redirect: 'error', signal: controller.signal,
          headers: { Accept: 'application/json', Authorization: 'Bearer ' + token } });
        if (!r.ok) {
          if (r.status === 401) throw new Error('Platform access denied. Use CB_OPERATOR_TOKEN, not a customer key.');
          if (r.status === 503) throw new Error('Platform reporting is unavailable. Check CB_OPERATOR_TOKEN and database migrations.');
          if (r.status === 429) throw new Error('Too many requests. Wait briefly before refreshing.');
          throw new Error('Invalid filters or report unavailable (HTTP ' + r.status + ').');
        }
        return r.json();
      };
      try {
        const initial = await fetcher(new URLSearchParams());
        if (!controller.signal.aborted) await usageDashboard(panel, fetcher, true, initial);
      } catch (e) { token = ''; if (!controller.signal.aborted) err.textContent = e.message; }
    });
  } }, h('p', { class: 'muted' }, 'Platform operators can compare all customer accounts. Customer admins cannot access this view with their normal account key.'),
    h('label', { class: 'f' }, h('span', {}, 'Platform operator credential'), field), err, go);
  panel.append(h('div', { class: 'card' }, form));
  app().replaceChildren(h('main', { class: 'operator-main' },
    header('Platform console', 'Usage metadata only. No prompts, answers or customer records.',
      h('a', { class: 'btn', href: '#/overview' }, 'Customer console'), h('button', { onclick: platformAIPage }, 'Lock platform view')), panel));
}
async function aiUsagePage(v) { await usageDashboard(v, (q) => must('GET', '/ai/consumption?' + q), false); }
async function usageDashboard(v, fetcher, operator, initial) {
  const today = new Date().toISOString().slice(0, 10);
  const week = new Date(Date.parse(today + 'T00:00:00Z') - 6 * 86400000).toISOString().slice(0, 10);
  const from = h('input', { type: 'date', value: week, max: today, required: true });
  const to = h('input', { type: 'date', value: today, max: today, required: true });
  const customer = h('input', { placeholder: 'All customers', maxlength: 64, autocomplete: 'off', spellcheck: 'false' });
  const results = h('div', { class: 'stack', 'aria-live': 'polite' });
  const error = h('p', { class: 'small usage-error', role: 'alert', style: 'color:var(--bad)' });
  const refresh = h('button', { type: 'submit', class: 'primary' }, 'Apply filters');
  let offset = 0, revision = 0, active = { from: week, to: today, customer: '' };
  const number = (n) => Number(n || 0).toLocaleString();
  const tokenValue = (n) => n === null ? 'Not reported' : number(n);
  const label = (name, input) => h('label', { class: 'f' }, h('span', {}, name), input);
  const card = (title, body, ...actions) => h('section', { class: 'card' }, h('div', { class: 'hd' }, h('h2', {}, title), ...actions), body);
  const kpi = (n, text) => h('div', { class: 'kpi' }, h('div', { class: 'v' }, number(n)), h('div', { class: 'l' }, text));
  async function load(preset) {
    const current = ++revision; error.textContent = '';
    const q = new URLSearchParams({ from: active.from, to: active.to, limit: '50', offset: String(offset) });
    if (operator && active.customer) q.set('customer', active.customer);
    try {
      const report = preset || await fetcher(q);
      if (current !== revision || !v.isConnected) return;
      draw(report);
    } catch (e) { if (current === revision && v.isConnected) { results.replaceChildren(); error.textContent = e.message; } }
  }
  function draw(r) {
    const s = r.summary;
    const max = Math.max(1, ...r.daily.map((d) => d.reported_tokens + d.unreported_reserved_tokens));
    const daily = table([
      { t: 'UTC day', v: (d) => d.day },
      { t: 'Reported / held', v: (d) => h('div', { class: 'usage-track', role: 'img', 'aria-label': d.day + ': ' + d.reported_tokens + ' reported tokens, ' + d.unreported_reserved_tokens + ' held tokens' },
        h('span', { class: 'usage-reported', style: 'width:' + (100 * d.reported_tokens / max) + '%' }), h('span', { class: 'usage-held', style: 'width:' + (100 * d.unreported_reserved_tokens / max) + '%' })) },
      { t: 'Requests', num: true, v: (d) => number(d.requests) }, { t: 'Reported tokens', num: true, v: (d) => number(d.reported_tokens) },
      { t: 'Held tokens', num: true, v: (d) => number(d.unreported_reserved_tokens) }
    ], r.daily);
    const previous = h('button', { class: 'sm', disabled: offset === 0, onclick: () => { offset = Math.max(0, offset - 50); load(); } }, 'Previous requests');
    const next = h('button', { class: 'sm', disabled: offset + 50 >= s.requests || offset >= 100000, onclick: () => { offset += 50; load(); } }, 'Next requests');
    const logs = table([
      { t: 'Created (UTC)', v: (x) => when(x.created_at) },
      ...(operator ? [{ t: 'Customer', v: (x) => h('code', {}, x.customer) }] : []),
      { t: 'Request / operation', v: (x) => h('div', {}, h('code', {}, x.request_id), h('div', { class: 'small muted' }, x.operation)) },
      { t: 'Provider / model', v: (x) => h('div', {}, x.provider, h('div', { class: 'small muted' }, x.model)) },
      { t: 'Outcome', v: (x) => x.finished_at ? pill(x.outcome) : pill('reserved') },
      { t: 'Input', num: true, v: (x) => tokenValue(x.input_tokens) }, { t: 'Output', num: true, v: (x) => tokenValue(x.output_tokens) },
      { t: 'Total', num: true, v: (x) => tokenValue(x.total_tokens) }, { t: 'Held', num: true, v: (x) => number(x.total_tokens === null ? x.reserved_tokens : 0) },
      { t: 'Duration', num: true, v: (x) => x.duration_ms === null ? 'Not finalized' : number(x.duration_ms) + ' ms' }
    ], r.requests);
    const customerTable = operator ? card('Consumption by customer', table([
      { t: 'Customer', v: (c) => h('button', { class: 'ghost sm', onclick: () => { customer.value = c.customer; active = { ...active, customer: c.customer }; offset = 0; load(); } }, c.customer) },
      { t: 'Requests', num: true, v: (c) => number(c.requests) }, { t: 'Input', num: true, v: (c) => number(c.input_tokens) }, { t: 'Output', num: true, v: (c) => number(c.output_tokens) },
      { t: 'Reported tokens', num: true, v: (c) => number(c.reported_tokens) }, { t: 'Held tokens', num: true, v: (c) => number(c.unreported_reserved_tokens) },
      { t: 'Unsuccessful', num: true, v: (c) => number(c.failed_requests) }
    ], r.customers), h('span', { class: 'small muted' }, number(r.customer_count) + ' accounts' + (r.customer_count > 200 ? ' (top 200 shown; filter by account id for others)' : ''))) : document.createDocumentFragment();
    results.replaceChildren(
      h('div', { class: 'kpis usage-kpis', 'data-testid': 'ai-totals' }, kpi(s.requests, 'AI requests'), kpi(s.reported_tokens, 'reported tokens'), kpi(s.input_tokens, 'reported input'), kpi(s.output_tokens, 'reported output'),
        kpi(s.unreported_reserved_tokens, 'tokens held against budget'), kpi(s.failed_requests, 'unsuccessful requests'), kpi(s.pending_requests, 'not finalized'), kpi(s.unknown_requests, 'finished without usage')),
      h('p', { class: 'small muted' }, 'Reported tokens come from provider responses. Missing usage stays unknown. Held tokens are budget reservations for each request\'s UTC start day, not measured consumption or today\'s remaining balance. Unfinalized requests may have been interrupted. Application requests may contain provider retries. This is not a provider invoice.'),
      customerTable,
      card('Daily token usage', daily, h('div', { class: 'row small' }, h('span', { class: 'usage-key usage-reported' }), 'Reported', h('span', { class: 'usage-key usage-held' }), 'Held')),
      card('Usage by model and operation', table([
        { t: 'Provider', v: (x) => x.provider }, { t: 'Model', v: (x) => h('code', {}, x.model) }, { t: 'Operation', v: (x) => x.operation },
        { t: 'Requests', num: true, v: (x) => number(x.requests) }, { t: 'Reported tokens', num: true, v: (x) => number(x.reported_tokens) }, { t: 'Held tokens', num: true, v: (x) => number(x.unreported_reserved_tokens) }
      ], r.breakdown)),
      card('AI request logs', logs, h('div', { class: 'row' }, h('span', { class: 'small muted' }, s.requests ? (offset + 1) + '-' + Math.min(offset + 50, s.requests) + ' of ' + number(s.requests) : 'No requests'), previous, next)),
      h('p', { class: 'small muted' }, 'Logs contain request ids, model, operation, outcome, timestamps and token counts. Prompts, answers, keys and source records are excluded. No AI call is needed to view this dashboard.')
    );
  }
  const form = h('form', { class: 'row usage-filters', onsubmit: async (e) => {
    e.preventDefault();
    const duration = Date.parse(to.value + 'T00:00:00Z') - Date.parse(from.value + 'T00:00:00Z');
    if (!Number.isFinite(duration) || duration < 0 || duration > 89 * 86400000) { error.textContent = 'Choose an ordered range of up to 90 UTC days.'; return; }
    active = { from: from.value, to: to.value, customer: customer.value.trim() }; offset = 0;
    await busy(refresh, () => load());
  } }, label('From (UTC)', from), label('To (UTC)', to), operator ? label('Customer account', customer) : null, refresh);
  v.replaceChildren(header(operator ? 'AI usage across customers' : 'AI usage', operator ? 'Compare customers, then select an account to inspect its request history.' : 'Consumption and request history for account ' + S.tenant + '.'), form, error, results);
  await load(initial);
}
