// Depsuk Admin backend. Jalankan: ADMIN_TOKEN=rahasia-minimal-16-char node server.js
// Install: npm i express qrcode whatsapp-web.js
const express = require('express');
const crypto = require('crypto');
const path = require('path');
const { execFile } = require('child_process');
const QR = require('qrcode');
const { Client, LocalAuth } = require('whatsapp-web.js');

const E = process.env;
const ADMIN = E.ADMIN_TOKEN || '';
if (ADMIN.length < 16) { console.error('Set ADMIN_TOKEN (minimal 16 karakter)'); process.exit(1); }

const XBIN = E.XCTL_BIN || 'depsukctl';
const ALLOW = (E.XCTL_ALLOW || '*').split(',').map(s => s.trim()); // '*' = semua subcommand
const D = { // SESUAIKAN dengan dokumentasi dattioai.com
  base: (E.DATTIO_BASE_URL || 'https://dattioai.com').replace(/\/$/, ''),
  path: E.DATTIO_TOKEN_PATH || '/v1/usage',
  key: E.DATTIO_API_KEY || '',
  header: E.DATTIO_AUTH_HEADER || 'Authorization',
  scheme: E.DATTIO_AUTH_SCHEME ?? 'Bearer',
  docs: E.DATTIO_DOCS_URL || ((E.DATTIO_BASE_URL || 'https://dattioai.com') + '/docs'),
};

const app = express();
app.use(express.json());
app.get('/', (_, r) => r.sendFile(path.join(__dirname, 'admin.html')));

app.use('/api', (req, res, next) => {
  const got = Buffer.from((req.headers.authorization || '').replace(/^Bearer /, ''));
  const want = Buffer.from(ADMIN);
  if (got.length === want.length && crypto.timingSafeEqual(got, want)) return next();
  res.status(401).json({ error: 'Token admin salah' });
});

app.get('/api/config', (_, r) => r.json({ docs: D.docs, base: D.base, path: D.path, xctl: XBIN, allow: ALLOW }));

// ---- Sisa token dattioai (API key tetap di server, tidak dikirim ke browser)
app.get('/api/tokens', async (_, res) => {
  try {
    const headers = { Accept: 'application/json' };
    if (D.key) headers[D.header] = (D.scheme ? D.scheme + ' ' : '') + D.key;
    const r = await fetch(D.base + D.path, { headers });
    const text = await r.text();
    let data; try { data = JSON.parse(text); } catch { data = text; }
    res.json({ status: r.status, url: D.base + D.path, data });
  } catch (e) { res.status(502).json({ error: e.message }); }
});

// ---- Bot WhatsApp
let wa = null;
const st = { state: 'stopped', qr: null, me: null, log: [] };
const log = m => { st.log.push(new Date().toLocaleTimeString('id-ID') + '  ' + m); st.log = st.log.slice(-60); };

async function waStart() {
  if (wa) return;
  st.state = 'starting'; st.qr = null; log('Memulai bot');
  const c = new Client({ authStrategy: new LocalAuth({ dataPath: '.wa-session' }), puppeteer: { headless: true, args: ['--no-sandbox'] } });
  wa = c;
  c.on('qr', async q => { st.state = 'qr'; st.qr = await QR.toDataURL(q, { margin: 1, width: 280 }); log('QR siap, scan lewat WhatsApp > Perangkat tertaut'); });
  c.on('ready', () => { st.state = 'ready'; st.qr = null; st.me = c.info?.wid?.user || null; log('Terhubung sebagai ' + st.me); });
  c.on('auth_failure', m => log('Autentikasi gagal: ' + m));
  c.on('disconnected', r => { log('Terputus: ' + r); if (wa === c) { wa = null; st.state = 'stopped'; st.me = null; } });
  c.on('message', async m => { if (m.body === '!ping') await m.reply('pong'); }); // contoh handler, ganti sesuai kebutuhan
  c.initialize().catch(e => { log('Error: ' + e.message); if (wa === c) { wa = null; st.state = 'stopped'; } });
}
async function waStop() {
  if (!wa) return;
  const c = wa; wa = null;
  try { await c.destroy(); } catch (e) { log(e.message); }
  Object.assign(st, { state: 'stopped', qr: null, me: null }); log('Dihentikan');
}
async function waLogout() {
  if (wa) { try { await wa.logout(); log('Logout, sesi dihapus'); } catch (e) { log(e.message); } }
  await waStop();
}

app.get('/api/wa', (_, r) => r.json(st));
app.post('/api/wa/:act', async (req, res) => {
  const act = req.params.act;
  if (act === 'start') await waStart();
  else if (act === 'stop') await waStop();
  else if (act === 'restart') { await waStop(); await waStart(); }
  else if (act === 'logout') await waLogout();
  else return res.status(400).json({ error: 'Aksi tidak dikenal' });
  res.json(st);
});

// ---- xctl (tanpa shell, argumen dipisah aman)
app.post('/api/xctl', (req, res) => {
  const cmd = String(req.body.cmd || '').trim();
  const args = (cmd.match(/"[^"]*"|'[^']*'|\S+/g) || []).map(s => s.replace(/^(["'])(.*)\1$/, '$2'));
  if (!args.length || args.length > 30) return res.status(400).json({ error: 'Perintah kosong atau terlalu panjang' });
  if (!ALLOW.includes('*') && !ALLOW.includes(args[0])) return res.status(403).json({ error: 'Subcommand tidak diizinkan: ' + args[0] });
  execFile(XBIN, args, { timeout: 30000, maxBuffer: 1 << 20 }, (err, stdout, stderr) =>
    res.json({ code: err ? (err.code ?? 1) : 0, stdout, stderr: stderr || (err && err.message) || '' }));
});

const port = E.PORT || 3000, host = E.HOST || '127.0.0.1';
app.listen(port, host, () => console.log(`Admin di http://${host}:${port}`));
