// Install: npm i express qrcode pino @whiskeysockets/baileys
// Jalankan: node server.js   (password admin default: x)
const express = require('express');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const { execFile } = require('child_process');
const QR = require('qrcode');

const E = process.env;
const ADMIN = E.ADMIN_TOKEN || 'x';
const XBIN = E.XCTL_BIN || 'depsukctl';
const ALLOW = (E.XCTL_ALLOW || '*').split(',').map(s => s.trim());
const AI = (E.AI_BASE_URL || 'https://bandelbanget.xyz/v1').replace(/\/$/, '');
const ORIGIN = new URL(AI).origin;
const SESS = E.WA_SESSION_DIR || '.wa-session';

const app = express();
app.use(express.json());
const sha = s => crypto.createHash('sha256').update(String(s)).digest();
const hits = new Map();
const tooMany = (k, max, ms = 60000) => {
  const n = Date.now(), a = (hits.get(k) || []).filter(t => n - t < ms);
  a.push(n); hits.set(k, a); return a.length > max;
};

// ---------- Halaman
const CORS = E.CORS_ORIGIN; // isi jika xozen.html dibuka dari domain lain, mis. https://bandelbanget.xyz
app.use((req, res, next) => {
  if (CORS) {
    res.set({ 'Access-Control-Allow-Origin': CORS, 'Access-Control-Allow-Headers': 'Authorization, Content-Type', 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS', Vary: 'Origin' });
    if (req.method === 'OPTIONS') return res.sendStatus(204);
  }
  next();
});
const home = fs.existsSync(path.join(__dirname, 'xozen.html')) ? 'xozen.html' : 'token.html';
app.get('/', (_, r) => r.sendFile(path.join(__dirname, home)));
app.get('/token', (_, r) => r.sendFile(path.join(__dirname, 'token.html')));
app.get('/admin', (_, r) => r.sendFile(path.join(__dirname, 'admin.html')));

// ---------- Cek sisa token (publik, key milik pengguna sendiri, tidak disimpan)
app.post('/token/check', async (req, res) => {
  if (tooMany('tok:' + req.ip, 20)) return res.status(429).json({ error: 'Terlalu sering, coba lagi sebentar' });
  const key = String(req.body.key || '').trim();
  if (!/^[\w.\-]{8,200}$/.test(key)) return res.status(400).json({ error: 'Format API key tidak valid' });
  const H = { Authorization: 'Bearer ' + key, Accept: 'application/json' };
  const get = async u => {
    try {
      const r = await fetch(u, { headers: H, signal: AbortSignal.timeout(10000) });
      const t = await r.text(); let d; try { d = JSON.parse(t); } catch { d = t.slice(0, 300); }
      return { url: u, status: r.status, data: d };
    } catch (e) { return { url: u, status: 0, data: e.message }; }
  };
  const out = { usage: await get(ORIGIN + '/api/usage/token') }; // gaya new-api / one-api
  if (out.usage.status !== 200) { // gaya OpenAI billing
    out.sub = await get(AI + '/dashboard/billing/subscription');
    out.bill = await get(AI + '/dashboard/billing/usage');
  }
  out.models = await get(AI + '/models'); // validasi key
  res.json(out);
});

// ---------- Auth admin (5 salah per menit = dikunci 1 menit)
app.use('/api', (req, res, next) => {
  if (tooMany('bad:' + req.ip, 5) && !crypto.timingSafeEqual(sha((req.headers.authorization || '').replace(/^Bearer /, '')), sha(ADMIN)))
    return res.status(429).json({ error: 'Terlalu banyak percobaan, coba lagi 1 menit' });
  if (crypto.timingSafeEqual(sha((req.headers.authorization || '').replace(/^Bearer /, '')), sha(ADMIN))) { hits.delete('bad:' + req.ip); return next(); }
  res.status(401).json({ error: 'Password salah' });
});
app.get('/api/config', (_, r) => r.json({ xctl: XBIN, allow: ALLOW }));

// ---------- Bot WhatsApp (Baileys)
let sock = null, want = false, B = null;
const st = { state: 'stopped', qr: null, code: null, me: null, log: [] };
const log = m => { st.log.push(new Date().toLocaleTimeString('id-ID') + '  ' + m); st.log = st.log.slice(-60); };
const digits = p => String(p || '').replace(/\D/g, '') || undefined;

async function waStart(phone) {
  if (sock) return;
  B = B || await import('@whiskeysockets/baileys');
  want = true; Object.assign(st, { state: 'starting', qr: null, code: null }); log('Memulai bot');
  const { state, saveCreds } = await B.useMultiFileAuthState(SESS);
  const { version } = await B.fetchLatestBaileysVersion().catch(() => ({}));
  const s = sock = B.default({ version, auth: state, logger: require('pino')({ level: 'silent' }), browser: B.Browsers.ubuntu('Chrome'), printQRInTerminal: false });
  let asked = false;
  s.ev.on('creds.update', saveCreds);
  s.ev.on('connection.update', async ({ connection, lastDisconnect, qr }) => {
    if (qr && !asked && !s.authState.creds.registered) {
      asked = true;
      if (phone) {
        try {
          st.code = (await s.requestPairingCode(phone)).match(/.{1,4}/g).join('-'); st.state = 'pair';
          log('Kode pairing siap. Buka WhatsApp > Perangkat tertaut > Tautkan dengan nomor telepon');
        } catch (e) { log('Gagal meminta kode: ' + e.message); }
      } else {
        st.qr = await QR.toDataURL(qr, { margin: 1, width: 280 }); st.state = 'qr';
        log('QR siap, scan lewat WhatsApp > Perangkat tertaut');
      }
    }
    if (connection === 'open') {
      Object.assign(st, { state: 'ready', qr: null, code: null, me: (s.user?.id || '').split(':')[0].split('@')[0] });
      log('Terhubung sebagai ' + st.me);
    }
    if (connection === 'close' && sock === s) {
      const code = lastDisconnect?.error?.output?.statusCode;
      sock = null; st.me = null;
      if (code === B.DisconnectReason.loggedOut) {
        fs.rmSync(SESS, { recursive: true, force: true }); want = false; st.state = 'stopped'; log('Logout dari HP, sesi dihapus');
      } else if (want) {
        st.state = 'starting'; log('Terputus (kode ' + code + '), menyambung ulang');
        setTimeout(() => want && waStart(phone).catch(e => log('Error: ' + e.message)), 3000);
      } else st.state = 'stopped';
    }
  });
  s.ev.on('messages.upsert', async ({ messages }) => { // contoh handler, ganti sesuai kebutuhan
    const m = messages[0], t = m?.message?.conversation || m?.message?.extendedTextMessage?.text;
    if (m && !m.key.fromMe && t === '!ping') await s.sendMessage(m.key.remoteJid, { text: 'pong' });
  });
}
function waStop() {
  want = false; const s = sock; sock = null;
  try { s && s.end(undefined); } catch (e) { log(e.message); }
  Object.assign(st, { state: 'stopped', qr: null, code: null, me: null }); log('Dihentikan');
}
async function waLogout() {
  try { sock && await sock.logout(); } catch (e) { log(e.message); }
  waStop(); fs.rmSync(SESS, { recursive: true, force: true }); log('Sesi dihapus');
}

app.get('/api/wa', (_, r) => r.json(st));
app.post('/api/wa/:act', async (req, res) => {
  const a = req.params.act;
  try {
    if (a === 'start') await waStart(digits(req.body.phone));
    else if (a === 'stop') waStop();
    else if (a === 'restart') { waStop(); await waStart(digits(req.body.phone)); }
    else if (a === 'logout') await waLogout();
    else return res.status(400).json({ error: 'Aksi tidak dikenal' });
  } catch (e) { log('Error: ' + e.message); sock = null; st.state = 'stopped'; }
  res.json(st);
});

// ---------- xctl (tanpa shell)
app.post('/api/xctl', (req, res) => {
  const cmd = String(req.body.cmd || '').trim();
  const args = (cmd.match(/"[^"]*"|'[^']*'|\S+/g) || []).map(s => s.replace(/^(["'])(.*)\1$/, '$2'));
  if (!args.length || args.length > 30) return res.status(400).json({ error: 'Perintah kosong atau terlalu panjang' });
  if (!ALLOW.includes('*') && !ALLOW.includes(args[0])) return res.status(403).json({ error: 'Subcommand tidak diizinkan: ' + args[0] });
  execFile(XBIN, args, { timeout: 30000, maxBuffer: 1 << 20 }, (err, stdout, stderr) =>
    res.json({ code: err ? (err.code ?? 1) : 0, stdout, stderr: stderr || (err && err.message) || '' }));
});

const port = E.PORT || 3000, host = E.HOST || '127.0.0.1';
app.listen(port, host, () => {
  console.log(`Cek token: http://${host}:${port}/   Admin: http://${host}:${port}/admin`);
  if (ADMIN === 'x') console.log('Peringatan: password admin "x" sangat lemah, jangan buka ke internet tanpa proteksi tambahan.');
});
