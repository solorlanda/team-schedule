const http = require('node:http');
const { createHmac, randomBytes, timingSafeEqual } = require('node:crypto');
const { readFileSync } = require('node:fs');
const panel = readFileSync(require('node:path').join(__dirname, 'dist/index.html'));
const { GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, RENDER_EXTERNAL_URL, SESSION_SECRET } = process.env;
const managers = new Set((process.env.MANAGER_EMAILS || '').split(',').map(email => email.trim().toLowerCase()).filter(Boolean));
const configured = Boolean(GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET && RENDER_EXTERNAL_URL && SESSION_SECRET?.length >= 32);
const callback = RENDER_EXTERNAL_URL + '/auth/google-callback';

function sign(value) {
  return createHmac('sha256', SESSION_SECRET).update(value).digest('base64url');
}

function issue(data, lifetime) {
  const value = Buffer.from(JSON.stringify({ ...data, exp: Date.now() + lifetime * 1000 })).toString('base64url');
  return value + '.' + sign(value);
}

function verify(token) {
  try {
    const [value, signature, extra] = token.split('.');
    if (extra !== undefined) return null;
    const actual = Buffer.from(signature);
    const expected = Buffer.from(sign(value));
    if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) return null;
    const data = JSON.parse(Buffer.from(value, 'base64url'));
    return data.exp > Date.now() ? data : null;
  } catch {
    return null;
  }
}

function cookie(name, value, age) {
  return name + '=' + value + '; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=' + age;
}

http.createServer(async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');
  const send = (status, body) => { res.writeHead(status, { 'Content-Type': 'text/plain; charset=utf-8' }); res.end(body); };
  const redirect = (location, cookies = []) => { res.writeHead(303, { Location: location, 'Set-Cookie': cookies }); res.end(); };
  try {
    const url = new URL(req.url, 'http://localhost');
    if (req.method === 'GET' && url.pathname === '/health') return send(200, 'OK');
    if (!configured) return send(503, 'Manager sign-in is awaiting configuration.');
    const cookies = Object.fromEntries((req.headers.cookie || '').split(/;\s*/).filter(v => v.includes('=')).map(v => v.split('=', 2)));
    if (req.method === 'POST' && url.pathname === '/logout') return redirect('/', [cookie('__Host-manager', '', 0)]);
    if (req.method !== 'GET') return send(405, 'Method not allowed.');
    if (url.pathname === '/login') {
      const state = randomBytes(32).toString('base64url');
      const verifier = randomBytes(48).toString('base64url');
      const challenge = require('node:crypto').createHash('sha256').update(verifier).digest('base64url');
      const query = new URLSearchParams({ client_id: GOOGLE_CLIENT_ID, redirect_uri: callback, response_type: 'code', scope: 'openid email', state, prompt: 'select_account', code_challenge: challenge, code_challenge_method: 'S256' });
      return redirect('https://accounts.google.com/o/oauth2/v2/auth?' + query, [cookie('__Host-google-flow', issue({ state, verifier }, 600), 600)]);
    }
    if (url.pathname === '/auth/google-callback') {
      res.setHeader('Set-Cookie', cookie('__Host-google-flow', '', 0));
      const flow = verify(cookies['__Host-google-flow']);
      const code = url.searchParams.get('code');
      if (!flow || flow.state !== url.searchParams.get('state') || !code) return send(400, 'Sign-in expired or was cancelled. Return to the home page and try again.');
      const token = await fetch('https://oauth2.googleapis.com/token', { method: 'POST', body: new URLSearchParams({ code, client_id: GOOGLE_CLIENT_ID, client_secret: GOOGLE_CLIENT_SECRET, redirect_uri: callback, grant_type: 'authorization_code', code_verifier: flow.verifier }), signal: AbortSignal.timeout(10000) });
      if (!token.ok) return send(502, 'Google sign-in could not be completed.');
      const { access_token } = await token.json();
      const profile = await fetch('https://openidconnect.googleapis.com/v1/userinfo', { headers: { Authorization: 'Bearer ' + access_token }, signal: AbortSignal.timeout(10000) });
      if (!profile.ok) return send(502, 'Google account could not be verified.');
      const identity = await profile.json();
      const email = String(identity.email || '').toLowerCase();
      if (identity.email_verified !== true || !managers.has(email)) return send(403, 'This Google account is not authorized to manage shifts.');
      return redirect('/', [cookie('__Host-google-flow', '', 0), cookie('__Host-manager', issue({ email }, 28800), 28800)]);
    }
    if (url.pathname !== '/') return send(404, 'Not found.');
    const session = verify(cookies['__Host-manager']);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    if (!session || !managers.has(session.email)) return res.end('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Team Schedule</title><main style="max-width:30rem;margin:5rem auto;padding:1rem;font:18px system-ui"><h1>Team Schedule</h1><p>Sign in with an authorized manager account.</p><a href="/login">Sign in with Google</a></main></html>');
    res.end(panel);
  } catch {
    send(500, 'Unable to complete the request. Please try again.');
  }
}).listen(process.env.PORT || 3000, '0.0.0.0');
