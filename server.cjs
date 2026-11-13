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


const escapeHtml = value => String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const hash = value => require('node:crypto').createHash('sha256').update(value).digest('hex');
let collection;
function page(title, body) {
  return '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>'+title+'</title><style>body{font:16px system-ui;margin:2rem auto;padding:0 1rem;max-width:55rem;color:#18382b}input,select,button{font:inherit;margin:.3rem;padding:.4rem}label{display:block;margin:.5rem 0}table{border-collapse:collapse}td,th{border:1px solid #ccc;padding:.5rem}.scroll{overflow:auto}code{overflow-wrap:anywhere}</style><h1>'+title+'</h1>'+body+'</html>';
}
function week(value) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value || '')) return null;
  const date = new Date(value+'T00:00:00Z');
  if (!Number.isFinite(+date) || date.getUTCDay() !== 1 || date.toISOString().slice(0,10) !== value) return null;
  return Array.from({length:7}, (_, i) => new Date(+date + i*86400000).toISOString().slice(0,10));
}
function monthDays(value) {
  if (!/^\d{4}-(0[1-9]|1[0-2])$/.test(value || '')) return null;
  const start = new Date(value+'-01T00:00:00Z');
  const end = new Date(start);
  end.setUTCMonth(end.getUTCMonth()+1);
  return Array.from({length:(end-start)/86400000},(_,i)=>new Date(+start+i*86400000).toISOString().slice(0,10));
}
function monthLabel(value) {
  return new Intl.DateTimeFormat('en-GB',{month:'long',year:'numeric',timeZone:'UTC'}).format(new Date(value+'-01T00:00:00Z'));
}
function currentMonth() {
  return new Intl.DateTimeFormat('sv-SE',{timeZone:'Europe/Copenhagen',dateStyle:'short'}).format(new Date()).slice(0,7);
}
async function availability(req, res, url, cookies, send) {
  const employee = url.pathname === '/availability/respond';
  const session = verify(cookies['__Host-manager']);
  if (!employee && (!session || !managers.has(session.email))) return send(403,'Manager sign-in required.');
  if (!process.env.MONGODB_URI) return send(503,'Availability is awaiting database configuration.');
  if (!['GET','POST'].includes(req.method)) return send(405,'Method not allowed.');
  let form;
  if (req.method === 'POST') {
    if (req.headers.origin !== RENDER_EXTERNAL_URL) return send(403,'Invalid request origin.');
    let body = '';
    for await (const chunk of req) {
      body += chunk;
      if (body.length > 8192) return send(413,'Form too large.');
    }
    form = new URLSearchParams(body);
  }
  collection ??= new (require('mongodb').MongoClient)(process.env.MONGODB_URI,{serverSelectionTimeoutMS:5000}).db(process.env.MONGODB_DB || 'team_schedule').collection('availability');
  const html = (title, body) => {res.setHeader('Content-Type','text/html; charset=utf-8');res.end(page(title,body));};
  if (employee) {
    const token = (form || url.searchParams).get('token') || '';
    if (!/^[a-f0-9]{64}$/.test(token)) return send(404,'Invitation not found.');
    const key = hash(token);
    const invite = await collection.findOne({tokenHash:key});
    if (!invite || invite.expiresAt <= new Date()) return send(404,'This invitation is invalid or has expired.');
    const days = invite.month ? monthDays(invite.month) : week(invite.week);
    if (form) {
      const values = days.map(day => form.get(day));
      if (values.some(value => !['available','unavailable',''].includes(value))) return send(400,'Invalid availability.');
      const result = await collection.updateOne({_id:invite._id,tokenHash:key,expiresAt:{$gt:new Date()}},{$set:{values}});
      if (!result.matchedCount) return send(404,'This invitation has expired or been replaced.');
      return html('Availability saved','<p>Your manager can now see your responses. Use your personal invitation link to make changes.</p>');
    }
    return html('Your availability','<p>'+escapeHtml(invite.name)+' · '+(invite.month ? monthLabel(invite.month) : 'Week of '+invite.week)+'</p><form method="post" action="/availability/respond"><input type="hidden" name="token" value="'+token+'">'+days.map((day,i)=>'<label>'+new Intl.DateTimeFormat('en-GB',{weekday:'long',day:'numeric',month:'short',timeZone:'UTC'}).format(new Date(day))+' <select name="'+day+'">'+[['','No response'],['available','Available'],['unavailable','Unavailable']].map(([value,label])=>'<option value="'+value+'"'+((invite.values?.[i]||'')===value?' selected':'')+'>'+label+'</option>').join('')+'</select></label>').join('')+'<button>Save availability</button></form>');
  }
  const selected = (form || url.searchParams).get('month') || currentMonth();
  const days = monthDays(selected);
  if (!days) return send(400,'Choose a valid month.');
  let invitation = '';
  if (form) {
    const name = (form.get('name') || '').trim();
    const email = (form.get('email') || '').trim().toLowerCase();
    if (!name || name.length > 100 || email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return send(400,'Enter a name and valid email address.');
    const expiresAt = new Date(+new Date(days.at(-1)) + 2*86400000);
    if (expiresAt <= new Date()) return send(400,'Choose a current or upcoming month.');
    const token = randomBytes(32).toString('hex');
    await collection.updateOne({_id:selected+'|'+email},{$set:{name,email,month:selected,expiresAt,tokenHash:hash(token)}},{upsert:true});
    const link = RENDER_EXTERNAL_URL+'/availability/respond?token='+token;
    const draft = 'mailto:'+encodeURIComponent(email)+'?subject='+encodeURIComponent('Your availability for '+monthLabel(selected))+'&body='+encodeURIComponent('Please mark your availability using your personal link: '+link);
    const gmail = 'https://mail.google.com/mail/?' + new URLSearchParams({
      view: 'cm', fs: '1', to: email, su: 'Your availability for ' + monthLabel(selected),
      body: 'Please mark your availability using your personal link: ' + link
    });
    invitation = '<p>Copy this personal link or send it by email. Generating a new link for this employee and month replaces the previous link.</p><p><code>'+escapeHtml(link)+'</code></p><p><a href="'+escapeHtml(draft)+'">Open in mail app</a> · <a target="_blank" rel="noopener noreferrer" href="'+escapeHtml(gmail)+'">Open in Gmail</a></p>';
  }
  const people = await collection.find({month:selected},{projection:{name:1,email:1,values:1}}).sort({name:1}).toArray();
  if (!form && url.searchParams.get('format') === 'csv') {
    const quote = value => {
      const cell = String(value);
      return '"' + (/^\s*[=+@-]|^[\t\r\n]/.test(cell) ? "'" : '') + cell.replaceAll('"','""') + '"';
    };
    const records = [['Employee','Email',...days], ...people.map(person => [
      person.name, person.email, ...days.map((_,i) => ({available:'Available',unavailable:'Unavailable'}[person.values?.[i]] || 'No response'))
    ])];
    res.setHeader('Content-Type','text/csv; charset=utf-8');
    res.setHeader('Content-Disposition','attachment; filename="availability-'+selected+'.csv"');
    return res.end('\uFEFF' + records.map(row => row.map(quote).join(';')).join('\r\n'));
  }
  const rows = people.map(person=>'<tr><th>'+escapeHtml(person.name)+'<br>'+escapeHtml(person.email)+'</th>'+days.map((_,i)=>'<td>'+({available:'Available',unavailable:'Unavailable'}[person.values?.[i]]||'No response')+'</td>').join('')+'</tr>').join('');
  return html('Team availability','<p><a href="/">Back to shift schedule</a></p><form method="get"><label>Month <input type="month" name="month" value="'+selected+'" required></label><button>Show month</button></form><h2>Invite an employee</h2><form method="post"><input type="hidden" name="month" value="'+selected+'"><label>Employee <input name="name" maxlength="100" required></label><label>Email <input type="email" name="email" maxlength="254" required></label><button>Generate personal link</button></form>'+invitation+'<h2>Responses</h2>'+(rows?'<p><a href="/availability?month='+selected+'&amp;format=csv">Download for Excel (CSV)</a></p>':'')+(rows?'<div class="scroll"><table><tr><th>Employee</th>'+days.map(day=>'<th>'+day.slice(5)+'</th>').join('')+'</tr>'+rows+'</table></div>':'<p>No invitations for this month yet.</p>'));
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
    if (['/availability','/availability/respond'].includes(url.pathname)) {
      res.setHeader('Referrer-Policy', 'same-origin');
      return await availability(req,res,url,cookies,send);
    }
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
    res.end(panel.toString().replace('<main>','<main><p><a href="/availability">Team availability</a></p>'));
  } catch {
    send(500, 'Unable to complete the request. Please try again.');
  }
}).listen(process.env.PORT || 3000, '0.0.0.0');
