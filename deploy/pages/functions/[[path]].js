// Same-origin proxy: the console's static files are served by Pages; every
// other path (the API, /ui/ocsf.json, /) goes to the backend through this
// Function, so the browser only ever talks to one origin (SameSite=Strict
// session cookies and the API's same-origin check keep working unchanged).
//
// Pages settings (Production): BACKEND_ORIGIN (plain variable, e.g.
// https://configbridge-api.example.com) and PROXY_SECRET (secret, equal to the
// backend's CB_PROXY_SECRET). Nothing is defaulted: missing settings fail.
export async function onRequest({ request, env }) {
  if (!env.BACKEND_ORIGIN || !env.PROXY_SECRET) {
    return new Response(JSON.stringify({ error: 'proxy_not_configured' }), { status: 503, headers: { 'Content-Type': 'application/json' } });
  }
  const url = new URL(request.url);
  const target = new URL(url.pathname + url.search, env.BACKEND_ORIGIN);
  const headers = new Headers(request.headers);
  // set (never append): a client cannot smuggle its own values through
  headers.set('X-CB-Proxy-Secret', env.PROXY_SECRET);
  headers.set('X-CB-Client-IP', request.headers.get('CF-Connecting-IP') || '');
  headers.set('X-CB-Forwarded-Host', url.host);
  const body = request.method === 'GET' || request.method === 'HEAD' ? undefined : request.body;
  return fetch(target, { method: request.method, headers, body, redirect: 'manual' });
}
