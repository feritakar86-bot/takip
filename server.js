require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const AWS = require('aws-sdk');
const cors = require('cors');
const http = require('http');
const WebSocket = require('ws');
const { pool, init } = require('./db');
const { requireAuth, requireParent } = require('./auth');

const app = express();
app.use(cors());
app.use(express.json({ limit: '2mb' }));

// R2 (Cloudflare) Yapılandırması
const s3 = new AWS.S3({
  endpoint: process.env.R2_ENDPOINT,
  accessKeyId: process.env.R2_ACCESS_KEY,
  secretAccessKey: process.env.R2_SECRET_KEY,
  region: 'auto',
  signatureVersion: 'v4'
});

// --- HTTP API ROTALARI ---
app.post('/api/register', async (req, res) => {
  const { email, password, role, name } = req.body;
  if (!['parent', 'child'].includes(role)) return res.status(400).json({ error: 'rol hatali' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const r = await pool.query(
      `INSERT INTO users (email, password_hash, role, name) VALUES ($1,$2,$3,$4) RETURNING id, role`,
      [email, hash, role, name]
    );
    const u = r.rows[0];
    const token = jwt.sign({ id: u.id, role: u.role }, process.env.JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, role: u.role, userId: u.id });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'email kayitli' });
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const r = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
  const u = r.rows[0];
  if (!u) return res.status(401).json({ error: 'kullanici yok' });
  const ok = await bcrypt.compare(password, u.password_hash);
  if (!ok) return res.status(401).json({ error: 'sifre hatali' });
  const token = jwt.sign({ id: u.id, role: u.role }, process.env.JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, role: u.role, name: u.name, userId: u.id });
});

app.post('/api/location', requireAuth, async (req, res) => {
  const { lat, lng, accuracy, speed, captured_at } = req.body;
  await pool.query(`INSERT INTO locations (user_id, lat, lng, accuracy, speed, captured_at) VALUES ($1,$2,$3,$4,$5,$6)`,
    [req.user.id, lat, lng, accuracy, speed, captured_at]);
  res.json({ ok: true });
});

app.get('/api/locations', requireAuth, async (req, res) => {
  const targetId = parseInt(req.query.user_id) || req.user.id;
  const r = await pool.query(`SELECT user_id, lat, lng, accuracy, speed, captured_at FROM locations WHERE user_id=$1 ORDER BY captured_at DESC LIMIT 100`, [targetId]);
  res.json(r.rows);
});

app.get('/api/users', requireAuth, async (req, res) => {
  const q = req.user.role === 'parent' ? `SELECT id, role, name FROM users ORDER BY role` : `SELECT id, role, name FROM users WHERE role='parent'`;
  const r = await pool.query(q);
  res.json(r.rows);
});

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });

app.post('/api/audio', requireAuth, upload.single('audio'), async (req, res) => {
  if (req.user.role !== 'child') return res.status(403).json({ error: 'sadece cocuk ses yukler' });
  const key = `user_${req.user.id}/${Date.now()}.m4a`;
  await s3.putObject({ Bucket: process.env.R2_BUCKET, Key: key, Body: req.file.buffer, ContentType: 'audio/mp4' }).promise();
  await pool.query(`INSERT INTO audio_files (user_id, r2_key) VALUES ($1,$2)`, [req.user.id, key]);
  res.json({ ok: true, key });
});

app.get('/api/audio/list', requireAuth, requireParent, async (req, res) => {
  const childId = parseInt(req.query.user_id);
  const r = await pool.query(`SELECT id, user_id, r2_key, recorded_at FROM audio_files WHERE user_id=$1 ORDER BY recorded_at DESC LIMIT 100`, [childId]);
  res.json(r.rows);
});

app.get('/api/audio/:id/url', requireAuth, requireParent, async (req, res) => {
  const r = await pool.query('SELECT r2_key FROM audio_files WHERE id=$1', [req.params.id]);
  if (!r.rows.length) return res.status(404).json({ error: 'yok' });
  const url = s3.getSignedUrl('getObject', { Bucket: process.env.R2_BUCKET, Key: r.rows[0].r2_key, Expires: 300 });
  res.json({ url });
});

// Test için ana sayfa
app.get('/', (req, res) => res.send('cocuk-takip-backend calisiyor'));

// --- WEBSOCKET (CANLI DİNLEME) ---
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });
const rooms = {};

wss.on('connection', (ws, req) => {
  const urlParams = new URLSearchParams(req.url.split('?')[1]);
  const userId = urlParams.get('id');
  const role = urlParams.get('role');

  if (!userId || !role) return ws.close();
  const roomId = `target_${userId}`;

  if (!rooms[roomId]) rooms[roomId] = { parent: null, child: null };
  rooms[roomId][role] = ws;

  ws.on('message', (data) => {
    if (role === 'child' && rooms[roomId] && rooms[roomId].parent) {
      if (rooms[roomId].parent.readyState === WebSocket.OPEN) {
        rooms[roomId].parent.send(data);
      }
    }
  });

  ws.on('close', () => {
    if (rooms[roomId] && rooms[roomId][role] === ws) rooms[roomId][role] = null;
  });
});

// --- SUNUCUYU BAŞLATMA (SUGA UYUMLU) ---
const PORT = 3000;
init().then(() => {
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`Sunucu ${PORT} portunda calisiyor (WebSocket Aktif)`);
  });
});
