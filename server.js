const express = require('express');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = 'ganti-ini-kata-rahasia-panjang-12345';
const DATA_FILE = path.join(__dirname, 'users.json');

app.use(express.json());
app.use(express.static('public'));

// ========== DATABASE ==========
function loadData() {
  if (!fs.existsSync(DATA_FILE)) return { users: [] };
  return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
}
function saveData(data) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}

// Bikin admin default
const initData = loadData();
if (!initData.users.find(u => u.email === 'admin@admin.com')) {
  initData.users.push({
    email: 'admin@admin.com',
    password: bcrypt.hashSync('admin123', 10),
    role: 'admin',
    tanggalDaftar: new Date().toLocaleString('id-ID')
  });
  saveData(initData);
  console.log('✅ Admin dibuat → admin@admin.com / admin123');
}

// ========== HALAMAN ==========
app.get('/', (req, res) => res.redirect('/login.html'));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));

// ========== REGISTER (cuma email & password) ==========
app.post('/api/register', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) return res.status(400).json({ error: 'Email dan password wajib diisi' });
  if (!email.includes('@') || !email.includes('.')) return res.status(400).json({ error: 'Format email tidak valid' });
  if (password.length < 6) return res.status(400).json({ error: 'Password minimal 6 karakter' });

  const data = loadData();
  if (data.users.find(u => u.email.toLowerCase() === email.toLowerCase())) {
    return res.status(400).json({ error: 'Email sudah terdaftar, silakan login' });
  }

  data.users.push({
    email: email.toLowerCase(),
    password: bcrypt.hashSync(password, 10),
    role: 'user',
    tanggalDaftar: new Date().toLocaleString('id-ID', {
      day: '2-digit', month: '2-digit', year: 'numeric',
      hour: '2-digit', minute: '2-digit'
    })
  });
  saveData(data);
  res.json({ ok: true });
});

// ========== LOGIN ==========
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email dan password wajib diisi' });

  const data = loadData();
  const user = data.users.find(u => u.email.toLowerCase() === email.toLowerCase());
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Email atau password salah' });
  }

  const token = jwt.sign({ email: user.email, role: user.role }, SECRET, { expiresIn: '7d' });
  res.json({ token, email: user.email, role: user.role });
});

// ========== AUTH ==========
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Belum login' });
  try { req.user = jwt.verify(token, SECRET); next(); }
  catch { res.status(401).json({ error: 'Sesi habis' }); }
}

app.get('/api/me', auth, (req, res) => {
  const data = loadData();
  const user = data.users.find(u => u.email === req.user.email);
  if (!user) return res.status(404).json({ error: 'User tidak ditemukan' });
  res.json({
    email: user.email,
    role: user.role,
    tanggalDaftar: user.tanggalDaftar
  });
});

// ========== ADMIN: LIHAT SEMUA USER ==========
app.get('/api/users', auth, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Hanya admin' });
  const data = loadData();
  res.json(data.users.map(u => ({
    email: u.email,
    role: u.role,
    tanggalDaftar: u.tanggalDaftar
  })));
});

// ========== JALANKAN ==========
app.listen(PORT, () => {
  console.log(`🚀 Server jalan: http://localhost:${PORT}`);
  console.log(`🔑 Admin: admin@admin.com / admin123`);
});