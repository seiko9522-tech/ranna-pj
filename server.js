/**
 * Digital Pager — server.js
 * -------------------------------------------------------------
 * Run:   npm init -y && npm install express socket.io cors qrcode
 *        CASHIER_PASSWORD=yourpass API_KEY=secret PUBLIC_URL=https://pager.example.com node server.js
 *
 *   Cashier screen : http://localhost:3000/
 *   Customer pager : http://<server-ip>:3000/pager   (serves index.html next to this file)
 *   Printable QR   : http://localhost:3000/qr        (print once, stick at the counter)
 *   POS webhook    : POST http://localhost:3000/api/v1/tickets   { "reference": "27" }
 */

const http = require('http');
const os = require('os');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const express = require('express');
const cors = require('cors');
const { Server } = require('socket.io');
const QRCode = require('qrcode');

const PORT = process.env.PORT || 3000;
// Customers can take a number themselves from the QR page. Disable with:  SELF_TICKET=off node server.js
const ALLOW_SELF_TICKET = process.env.SELF_TICKET !== 'off';

// Security (set these when the server is on the internet):
//   CASHIER_PASSWORD  -> password for the cashier screen and /qr
//   API_KEY           -> secret the POS sends in the "x-api-key" header
const CASHIER_PASSWORD = process.env.CASHIER_PASSWORD || '';
const API_KEY = process.env.API_KEY || '';
const CASHIER_TOKEN = crypto.randomBytes(24).toString('hex');   // proves a socket came from the cashier page

const sha = (v) => crypto.createHash('sha256').update(String(v)).digest();
const safeEqual = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));

// Brute-force guard: 8 wrong passwords from one address -> locked 10 minutes.
// Plus a global brake: 60 wrong passwords in 10 minutes from anywhere -> everyone waits 5 minutes.
const failLog = new Map();
let globalFails = { n: 0, t: 0 }, globalLockUntil = 0;
const WINDOW = 10 * 60 * 1000;
function lockedOut(ip) {
  const now = Date.now();
  if (now < globalLockUntil) return true;
  const r = failLog.get(ip);
  return !!(r && r.n >= 8 && now - r.t < WINDOW);
}
function noteFail(ip) {
  const now = Date.now();
  const r = failLog.get(ip);
  if (!r || now - r.t >= WINDOW) failLog.set(ip, { n: 1, t: now }); else r.n++;
  if (now - globalFails.t >= WINDOW) globalFails = { n: 1, t: now }; else globalFails.n++;
  if (globalFails.n >= 60) { globalLockUntil = now + 5 * 60 * 1000; globalFails = { n: 0, t: now }; console.log('[security] too many wrong passwords: logins paused 5 min'); }
}
const ON_RENDER = !!process.env.RENDER;   // Render sets this automatically
const needSetup = (res) => res.status(503).send('Server is not configured: set CASHIER_PASSWORD in the hosting dashboard.');

function requireCashier(req, res, next) {
  if (!CASHIER_PASSWORD) return ON_RENDER ? needSetup(res) : next();   // online: never open without a password
  if (lockedOut(req.ip)) return res.status(429).send('Too many attempts. Try again later.');
  const m = /^Basic\s+(.+)$/i.exec(req.get('authorization') || '');
  if (m) {
    const decoded = Buffer.from(m[1], 'base64').toString('utf8');
    const pass = decoded.slice(decoded.indexOf(':') + 1);
    if (safeEqual(pass, CASHIER_PASSWORD)) { failLog.delete(req.ip); return next(); }
    noteFail(req.ip);
  }
  res.set('WWW-Authenticate', 'Basic realm="Pager", charset="UTF-8"');
  res.status(401).send('Unauthorized');
}

// POS: API key, or the cashier password
function requirePos(req, res, next) {
  if (!API_KEY && !CASHIER_PASSWORD) return ON_RENDER ? needSetup(res) : next();
  if (lockedOut(req.ip)) return res.status(429).send('Too many attempts. Try again later.');
  const auth = req.get('authorization') || '';
  const key = req.get('x-api-key') || auth.replace(/^Bearer\s+/i, '');
  if (API_KEY && key && safeEqual(key, API_KEY)) return next();
  if (key && !/^Basic\s/i.test(auth)) noteFail(req.ip);    // wrong API key counts as a failed attempt
  requireCashier(req, res, next);
}

// at most 3 self-service numbers per phone / 10 minutes, and 40 in total (stops fake-number flooding)
const selfLog = new Map();
let selfAll = [];
function selfTicketAllowed(ip) {
  const now = Date.now();
  selfAll = selfAll.filter((t) => now - t < 10 * 60 * 1000);
  if (selfAll.length >= 40) return false;
  const list = (selfLog.get(ip) || []).filter((t) => now - t < 10 * 60 * 1000);
  if (list.length >= 3) { selfLog.set(ip, list); return false; }
  list.push(now); selfLog.set(ip, list); selfAll.push(now);
  return true;
}
setInterval(() => {                                  // forget old records so memory never grows
  const now = Date.now();
  selfLog.forEach((v, k) => { if (!v.length || now - v[v.length - 1] > 10 * 60 * 1000) selfLog.delete(k); });
  failLog.forEach((v, k) => { if (now - v.t >= WINDOW) failLog.delete(k); });
}, 10 * 60 * 1000).unref();

const app = express();
app.set('trust proxy', Number(process.env.TRUST_PROXY || 1));   // trust ONE proxy hop only (Render), not the whole header chain
app.disable('x-powered-by');
app.use((req, res, next) => {                      // basic browser-side protections
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',                     // nobody can embed the cashier page in another site
    'Referrer-Policy': 'no-referrer',
    'Strict-Transport-Security': 'max-age=15552000',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  });
  next();
});
app.use(cors());                                  // full CORS support
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] },
  maxHttpBufferSize: 1e4,        // tiny messages only (10 KB)
});

/* ------------------------------------------------------------------ *
 * State (in memory)
 * ------------------------------------------------------------------ */
let counter = 0;             // last auto-generated order number
const tickets = new Map();   // orderId -> { id, createdAt }
const viewers = new Map();   // orderId -> Set(socket.id)  (customer phones)

// Arabic-Indic digits (٢٧) -> Latin (27), so both sides always match
const norm = (v) => String(v == null ? '' : v)
  .replace(/[\u0660-\u0669]/g, (d) => d.charCodeAt(0) - 0x0660)
  .replace(/[\u06F0-\u06F9]/g, (d) => d.charCodeAt(0) - 0x06F0)
  .trim();

const room = (id) => 'order:' + id;
const isConnected = (id) => !!(viewers.get(id) && viewers.get(id).size);

function snapshot() {
  return Array.from(tickets.values()).map((t) => ({
    id: t.id,
    createdAt: t.createdAt,
    connected: isConnected(t.id),
  }));
}

function broadcast() {
  io.to('cashier').emit('tickets', snapshot());
}

function addTicket(rawId) {
  const id = norm(rawId);
  if (!id || id.length > 20) return { ok: false, error: 'bad-id' };
  if (!tickets.has(id) && tickets.size >= 500) return { ok: false, error: 'full' };
  if (/^[0-9]+$/.test(id)) counter = Math.max(counter, parseInt(id, 10));
  if (!tickets.has(id)) tickets.set(id, { id, createdAt: Date.now() });
  broadcast();
  return { ok: true, id, connected: isConnected(id) };
}

// Cashier presses "new order": next free number, no POS needed
function nextTicket() {
  do { counter++; } while (tickets.has(String(counter)));
  return addTicket(counter);
}

function callReady(rawId) {
  const id = norm(rawId);
  if (!tickets.has(id)) return { ok: false, error: 'not-found' };
  const delivered = isConnected(id);
  io.to(room(id)).emit('vibrate-and-sound', { orderId: id });   // ring the customer's phone
  tickets.delete(id);                                           // clear it from the cashier screen
  broadcast();
  return { ok: true, id, delivered };
}

/* ------------------------------------------------------------------ *
 * REST API
 * ------------------------------------------------------------------ */
// Receives tickets automatically from the POS
app.post('/api/v1/tickets', requirePos, (req, res) => {
  const b = req.body || {};
  const id = b.reference ?? b.orderId ?? b.order_id ?? b.number ?? b.ticket;
  if (id === undefined || id === null || String(id).trim() === '') {
    return res.status(400).json({ ok: false, error: 'reference or orderId is required' });
  }
  const result = addTicket(id);
  console.log('[ticket] +', result.id);
  res.status(201).json(result);
});

app.get('/api/v1/tickets', requireCashier, (req, res) => res.json(snapshot()));

app.post('/api/v1/tickets/:id/ready', requirePos, (req, res) => {
  const result = callReady(req.params.id);
  res.status(result.ok ? 200 : 404).json(result);
});

/* ------------------------------------------------------------------ *
 * Pages
 * ------------------------------------------------------------------ */
// Hidden cashier address.
//   CASHIER_PATH=my-secret-123  ->  cashier screen moves to /my-secret-123
//                                   and "/" shows the marketing page (site.html next to this file).
//   Not set                     ->  cashier stays at "/" exactly as before.
let CASHIER_SLUG = (process.env.CASHIER_PATH || '').trim().replace(/^\/+|\/+$/g, '');
if (CASHIER_SLUG && !/^[A-Za-z0-9_-]{6,80}$/.test(CASHIER_SLUG)) {
  console.log('  !! CASHIER_PATH must be 6-80 chars of letters, digits, - or _  (ignored, cashier stays at "/")');
  CASHIER_SLUG = '';
}
const CASHIER_ROUTE = CASHIER_SLUG ? '/' + CASHIER_SLUG : '/';

app.get(CASHIER_ROUTE, requireCashier, (req, res) => {
  res.set('X-Robots-Tag', 'noindex, nofollow');   // keep search engines away from the cashier page
  res.set('Cache-Control', 'no-store');
  res.type('html').send(CASHIER_HTML.replace('__TOKEN__', CASHIER_TOKEN));
});

// Typing /admin asks for the password, then forwards to the real (secret) cashier address
app.get('/admin', requireCashier, (req, res) => res.redirect(CASHIER_ROUTE));

if (CASHIER_ROUTE !== '/') {
  // Public home page: your marketing site (site.html), or a simple placeholder until you add it
  app.get('/', (req, res) => {
    const file = path.join(__dirname, 'site.html');
    if (fs.existsSync(file)) return res.sendFile(file);
    res.type('html').send(
      '<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="UTF-8">' +
      '<meta name="viewport" content="width=device-width, initial-scale=1"><title>رنّة</title></head>' +
      '<body style="font-family:Tahoma,Arial,sans-serif;text-align:center;padding:90px 20px;background:#fff;color:#1a1c19">' +
      '<h1 style="font-size:44px;margin:0 0 12px">رنّة</h1>' +
      '<p style="font-size:20px;color:#555">نظام نداء رقمي للطلبات: يهتز جوال الزبون ويرنّ عندما يصبح طلبه جاهزاً.</p>' +
      '</body></html>'
    );
  });
}
// One-time printable QR that opens the customer pager
function lanAddress() {
  const all = Object.values(os.networkInterfaces()).flat();
  const hit = all.find((n) => n && n.family === 'IPv4' && !n.internal);
  return hit ? hit.address : null;
}

app.get('/qr', requireCashier, async (req, res) => {
  try {
    // A phone can't reach "localhost" of this PC, so swap it for the LAN address
    let host = req.get('host') || ('localhost:' + PORT);
    const name = host.split(':')[0];
    if (name === 'localhost' || name === '127.0.0.1') {
      const ip = lanAddress();
      if (ip) host = ip + ':' + PORT;
    }
    // On a real domain set PUBLIC_URL=https://pager.example.com
    const url = process.env.PUBLIC_URL
      ? process.env.PUBLIC_URL.replace(/\/+$/, '') + '/pager'
      : req.protocol + '://' + host + '/pager';
    const svg = await QRCode.toString(url, {
      type: 'svg', margin: 2, width: 480,
      color: { dark: '#000000', light: '#ffffff' },
    });

    res.type('html').send(
      '<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="UTF-8">' +
      '<meta name="viewport" content="width=device-width, initial-scale=1">' +
      '<meta name="color-scheme" content="light"><title>QR للزبائن</title>' +
      '<style>' +
      'html,body{background:#ffffff !important;color:#1a1c19 !important;margin:0}' +
      'body{font-family:Tahoma,Arial,sans-serif;text-align:center;padding:40px 20px}' +
      'h1{font-size:32px;margin:0 0 8px}p{font-size:19px;color:#555;margin:6px 0}' +
      '.qr{width:min(80vw,400px);margin:26px auto;background:#fff;padding:12px;border:1px solid #ddd;border-radius:16px}' +
      '.qr svg{width:100%;height:auto;display:block}' +
      'code{direction:ltr;display:inline-block;font-size:17px;color:#444;background:#f3f3f3;padding:6px 12px;border-radius:8px}' +
      'button{font-size:18px;padding:10px 24px;margin-top:22px;cursor:pointer}' +
      '@media print{.np{display:none}}' +
      '</style></head><body>' +
      '<h1>تابع طلبك من جوالك</h1>' +
      '<p>امسح الرمز، ثم اكتب رقم طلبك لنُنبّهك عندما يكون جاهزاً</p>' +
      '<div class="qr">' + svg + '</div>' +
      '<code>' + url + '</code>' +
      '<p class="np"><button onclick="print()">طباعة</button></p>' +
      '</body></html>'
    );
  } catch (err) {
    console.error('[qr] failed:', err);
    res.status(500).type('html').send(
      '<meta charset="UTF-8"><body style="font-family:Tahoma;padding:30px;background:#fff;color:#000" dir="rtl">' +
      '<h2>تعذّر توليد الـ QR</h2><p>' + String(err && err.message) + '</p>' +
      '<p>تأكد من تثبيت المكتبة: <code>npm install qrcode</code></p></body>'
    );
  }
});

app.get('/health', (req, res) => res.json({ ok: true, tickets: tickets.size }));

// Finds the customer page even if Windows renamed it (index_html.html, index (1).html ...)
function findPagerFile() {
  let names = [];
  try { names = fs.readdirSync(__dirname); } catch (e) { return { file: null, names }; }
  const pick =
    names.find((n) => n.toLowerCase() === 'index.html') ||
    names.find((n) => /^index.*\.html?$/i.test(n));
  return { file: pick ? path.join(__dirname, pick) : null, names };
}

app.get(['/pager', '/index.html'], (req, res) => {
  const found = findPagerFile();
  if (!found.file) {
    console.log('[pager] no index*.html in', __dirname);
    const list = found.names.map((n) => '<li dir="ltr">' + n.replace(/[<>&]/g, '') + '</li>').join('');
    return res.status(404).type('html').send(
      '<meta charset="UTF-8"><body dir="rtl" style="font-family:Tahoma;padding:30px;background:#fff;color:#000">' +
      '<h2>ملف صفحة الزبون غير موجود</h2><p>حط ملف index.html داخل هذا المجلد:</p>' +
      '<p dir="ltr"><code>' + __dirname + '</code></p><p>الملفات الموجودة الآن:</p><ul>' + list + '</ul></body>'
    );
  }
  res.sendFile(found.file, (err) => {
    if (err && !res.headersSent) res.status(500).send('Error: ' + err.message);
  });
});

/* ------------------------------------------------------------------ *
 * Sockets
 * ------------------------------------------------------------------ */
io.use((socket, next) => {
  const t = socket.handshake.auth && socket.handshake.auth.token;
  socket.data.isCashier = typeof t === 'string' && t.length > 0 && safeEqual(t, CASHIER_TOKEN);
  next();
});

const STAFF_EVENTS = new Set(['cashier-join', 'new-ticket', 'add-ticket', 'ready']);
const clientIp = (socket) =>
  String(socket.handshake.headers['x-forwarded-for'] || socket.handshake.address || '').split(',')[0].trim();

io.on('connection', (socket) => {
  socket.data.orders = new Set();
  console.log('[socket] connected:', socket.data.isCashier ? 'CASHIER' : 'customer');

  // customers (no token) can never use cashier events
  socket.use((packet, next) => {
    if (STAFF_EVENTS.has(packet[0]) && !socket.data.isCashier) {
      console.log('[blocked] "' + packet[0] + '" from a non-cashier connection (reload the cashier page with Ctrl+F5)');
      return;
    }
    next();
  });

  // Cashier screen
  socket.on('cashier-join', () => {
    socket.join('cashier');
    socket.emit('tickets', snapshot());
  });
  socket.on('new-ticket', (ack) => {
    const r = nextTicket();
    console.log('[ticket] new', r.id);
    if (typeof ack === 'function') ack(r);
  });
  // Customer asks for a number himself (no printed receipt needed)
  socket.on('self-ticket', (ack) => {
    if (typeof ack !== 'function') return;
    if (!ALLOW_SELF_TICKET) return ack({ ok: false, error: 'disabled' });
    if (!selfTicketAllowed(clientIp(socket))) return ack({ ok: false, error: 'rate-limit' });
    const r = nextTicket();
    console.log('[ticket] self', r.id);
    ack(r);
  });
  socket.on('add-ticket', (id, ack) => {
    const r = addTicket(id);
    if (typeof ack === 'function') ack(r);
  });
  socket.on('ready', (id, ack) => {
    const r = callReady(id);
    console.log('[ready]', id, r.ok ? (r.delivered ? 'delivered' : 'customer offline') : r.error);
    if (typeof ack === 'function') ack(r);
  });

  // Customer phone (index.html)
  socket.on('join-order', (rawId) => {
    const id = norm(rawId);
    if (!id || id.length > 20 || socket.data.orders.size >= 5) return;
    socket.join(room(id));
    socket.data.orders.add(id);
    if (!viewers.has(id)) viewers.set(id, new Set());
    viewers.get(id).add(socket.id);
    broadcast();                                    // card turns green on the cashier screen
  });

  socket.on('disconnect', () => {
    socket.data.orders.forEach((id) => {
      const set = viewers.get(id);
      if (set) {
        set.delete(socket.id);
        if (!set.size) viewers.delete(id);
      }
    });
    broadcast();
  });
});

/* ------------------------------------------------------------------ *
 * Start
 * ------------------------------------------------------------------ */
server.listen(PORT, '0.0.0.0', () => {
  console.log('\nDigital Pager is running');
  console.log('  Cashier : http://localhost:' + PORT + CASHIER_ROUTE);
  Object.values(os.networkInterfaces()).flat().forEach((n) => {
    if (n && n.family === 'IPv4' && !n.internal) {
      console.log('  Phones  : http://' + n.address + ':' + PORT + '/pager');
    }
  });
  console.log('  QR print: http://localhost:' + PORT + '/qr');
  if (!CASHIER_PASSWORD) console.log('  !! CASHIER_PASSWORD is not set: the cashier screen is ' + (ON_RENDER ? 'LOCKED until you set it' : 'open to everyone'));
  else if (CASHIER_PASSWORD.length < 10) console.log('  !! CASHIER_PASSWORD is short: use 12+ characters');
  if (!API_KEY) console.log('  !! API_KEY is not set: the POS endpoint is not protected by a key');
  console.log('  POS API : POST /api/v1/tickets  { "reference": "27" }\n');
});

/* ------------------------------------------------------------------ *
 * Cashier UI (served at "/")
 * ------------------------------------------------------------------ */
const CASHIER_HTML = `<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>شاشة الكاشير</title>
<link href="https://fonts.googleapis.com/css2?family=Tajawal:wght@400;500;700;800&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #f3f5f1; --card: #fff; --ink: #1a1c19; --muted: #81867d; --line: #e2e5de;
    --wait: #f2a35a; --wait-soft: #fff4e8;
    --ok: #22c55e; --ok-soft: #eafbf0;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Tajawal', 'Segoe UI', Tahoma, sans-serif; background: var(--bg); color: var(--ink); min-height: 100vh; }
  header {
    background: var(--card); border-bottom: 1px solid var(--line);
    padding: 16px 28px; display: flex; align-items: center; gap: 24px; flex-wrap: wrap;
    position: sticky; top: 0; z-index: 2;
  }
  h1 { font-size: 22px; font-weight: 800; }
  .count { font-size: 15px; color: var(--muted); }
  .count b { color: var(--ink); font-size: 18px; }
  .legend { display: flex; gap: 16px; font-size: 14px; color: var(--muted); margin-inline-start: auto; }
  .legend i { display: inline-block; width: 11px; height: 11px; border-radius: 50%; margin-inline-end: 6px; vertical-align: -1px; }
  .add { display: flex; gap: 8px; }
  .add input {
    width: 110px; border: 1.5px solid var(--line); border-radius: 12px; padding: 9px 12px;
    font-family: inherit; font-size: 16px; direction: ltr; text-align: center;
  }
  .add input:focus { outline: none; border-color: var(--ink); }
  .add button {
    border: 0; background: var(--ink); color: #fff; border-radius: 12px; padding: 0 18px;
    font-family: inherit; font-size: 15px; font-weight: 700; cursor: pointer;
  }
  .newbtn {
    border: 0; background: var(--ok); color: #fff; border-radius: 12px; padding: 10px 20px;
    font-family: inherit; font-size: 16px; font-weight: 800; cursor: pointer;
  }
  .qrlink { font-size: 14px; color: var(--muted); }
  .conn { width: 10px; height: 10px; border-radius: 50%; background: #d33; }
  .conn.on { background: var(--ok); }

  main { padding: 28px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(170px, 1fr)); gap: 16px; }
  .ticket {
    border: 2px solid transparent; cursor: pointer; text-align: center;
    background: var(--wait-soft); border-color: #f7d9b8; color: var(--ink);
    border-radius: 22px; padding: 22px 12px 16px; font-family: inherit;
    transition: transform .12s, background .3s, border-color .3s, box-shadow .3s;
  }
  .ticket:hover { transform: translateY(-2px); }
  .ticket:active { transform: scale(.97); }
  .ticket:focus-visible { outline: 3px solid var(--ink); outline-offset: 3px; }
  .num { display: block; font-size: 58px; font-weight: 800; line-height: 1.05; direction: ltr; }
  .state { display: block; margin-top: 10px; font-size: 14px; font-weight: 700; color: #b8701f; }
  .age { display: block; margin-top: 4px; font-size: 13px; color: var(--muted); }
  .ticket.connected {
    background: var(--ok-soft); border-color: var(--ok);
    box-shadow: 0 0 0 4px rgba(34, 197, 94, .15), 0 0 26px rgba(34, 197, 94, .45);
  }
  .ticket.connected .state { color: #138a3e; }
  .empty { text-align: center; color: var(--muted); padding: 90px 0; font-size: 18px; }
  .hint { text-align: center; color: var(--muted); font-size: 14px; margin-top: 28px; }

  .toast {
    position: fixed; bottom: 26px; left: 50%; transform: translate(-50%, 30px); opacity: 0;
    background: var(--ink); color: #fff; padding: 13px 22px; border-radius: 14px; font-size: 16px; font-weight: 700;
    transition: all .25s; pointer-events: none;
  }
  .toast.show { opacity: 1; transform: translate(-50%, 0); }
  .toast.warn { background: #b45309; }
</style>
</head>
<body>
<header>
  <span class="conn" id="conn" title="الاتصال بالسيرفر"></span>
  <h1>طلبات بانتظار التجهيز</h1>
  <span class="count"><b id="count">0</b> طلب</span>
  <div class="legend">
    <span><i style="background:var(--wait)"></i>بانتظار جوال الزبون</span>
    <span><i style="background:var(--ok)"></i>الجوال متصل</span>
  </div>
  <button class="newbtn" id="newBtn" type="button">+ طلب جديد</button>
  <a class="qrlink" href="/qr" target="_blank">رمز QR للزبائن</a>
  <form class="add" id="addForm">
    <input id="addInput" placeholder="رقم يدوي" inputmode="numeric" autocomplete="off" aria-label="إضافة رقم يدوياً">
    <button type="submit">إضافة</button>
  </form>
</header>

<main>
  <div class="grid" id="grid"></div>
  <div class="empty" id="empty">لا توجد طلبات بانتظار التجهيز</div>
  <p class="hint">اضغط على رقم الطلب عندما يصبح جاهزاً لتنبيه الزبون.</p>
</main>
<div class="toast" id="toast"></div>

<script src="/socket.io/socket.io.js"></script>
<script>
  var socket = io({ auth: { token: '__TOKEN__' } });
  var tickets = [];
  var grid = document.getElementById('grid');
  var empty = document.getElementById('empty');
  var toastEl = document.getElementById('toast'), toastTimer;

  function toast(msg, warn) {
    toastEl.textContent = msg;
    toastEl.className = 'toast show' + (warn ? ' warn' : '');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { toastEl.className = 'toast'; }, 2600);
  }

  function minutesAgo(ts) {
    var m = Math.floor((Date.now() - ts) / 60000);
    return m < 1 ? 'الآن' : 'منذ ' + m + ' د';
  }

  function sortKey(a, b) {
    var na = parseFloat(a.id), nb = parseFloat(b.id);
    if (!isNaN(na) && !isNaN(nb) && na !== nb) return na - nb;
    return a.createdAt - b.createdAt;
  }

  var els = {};

  function sendReady(t, el) {
    el.disabled = true;
    var done = false;
    var timer = setTimeout(function () {
      if (done) return;
      el.disabled = false;
      toast('لا يوجد اتصال بالسيرفر، حاول مرة أخرى', true);
    }, 4000);
    socket.emit('ready', t.id, function (r) {
      done = true; clearTimeout(timer);
      if (!r || !r.ok) { el.disabled = false; return toast('تعذّر إرسال التنبيه', true); }
      if (r.delivered) toast('تم تنبيه الطلب ' + r.id);
      else toast('الطلب ' + r.id + ' أُزيل، لكن جوال الزبون غير متصل', true);
    });
  }

  function makeCard(t) {
    var b = document.createElement('button');
    b.type = 'button';
    b.setAttribute('aria-label', 'تجهيز الطلب ' + t.id);
    b.innerHTML = '<span class="num"></span><span class="state"></span><span class="age"></span>';
    b.firstChild.textContent = t.id;
    b.addEventListener('click', function () { sendReady(t, b); });
    return b;
  }

  function render() {
    tickets.sort(sortKey);
    document.getElementById('count').textContent = tickets.length;
    empty.style.display = tickets.length ? 'none' : 'block';

    var keep = {};
    tickets.forEach(function (t, i) {
      keep[t.id] = true;
      var el = els[t.id];
      if (!el) { el = els[t.id] = makeCard(t); }
      el.className = 'ticket' + (t.connected ? ' connected' : '');
      el.children[1].textContent = t.connected ? 'الجوال متصل' : 'بانتظار الزبون';
      el.children[2].textContent = minutesAgo(t.createdAt);
      if (grid.children[i] !== el) grid.insertBefore(el, grid.children[i] || null);
    });
    Object.keys(els).forEach(function (id) {
      if (!keep[id]) { els[id].remove(); delete els[id]; }
    });
  }

  socket.on('connect', function () {
    document.getElementById('conn').classList.add('on');
    socket.emit('cashier-join');
  });
  socket.on('disconnect', function () { document.getElementById('conn').classList.remove('on'); });
  socket.on('connect_error', function () { toast('تعذّر الاتصال بالسيرفر', true); });
  socket.on('tickets', function (list) { tickets = list; render(); });
  setInterval(render, 30000);

  document.getElementById('newBtn').addEventListener('click', function () {
    var got = false;
    setTimeout(function () {
      if (!got) toast('السيرفر ما رد. حدّث الصفحة بـ Ctrl+F5 وشوف الطرفية', true);
    }, 3000);
    socket.emit('new-ticket', function (r) {
      got = true;
      if (r && r.ok) toast('رقم الطلب الجديد: ' + r.id + ' (أعطِه للزبون)');
      else toast('تعذّرت الإضافة', true);
    });
  });

  document.getElementById('addForm').addEventListener('submit', function (e) {
    e.preventDefault();
    var input = document.getElementById('addInput');
    var v = input.value.trim();
    if (!v) return;
    socket.emit('add-ticket', v);
    input.value = '';
  });
</script>
</body>
</html>`;
