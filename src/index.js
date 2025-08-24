const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();

// ====== FIXED SESSION AND CORS CONFIG FOR CROSS-DOMAIN LOGIN ======
app.use(cors({
  origin: ['https://justyydev.github.io', 'http://localhost:3000'],
  credentials: true
}));
app.use(express.json());
app.use(session({
  secret: 'peaceoutSecret',
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: true,           // IMPORTANT: only send cookie over HTTPS
    sameSite: 'none'       // CRITICAL: allow cross-site cookies
    // domain: 'peaceout-backend.onrender.com' // REMOVE THIS LINE
  }
}));

// ====== FILE UPLOAD SETUP ======
const UPLOAD_DIR = path.join(__dirname, '../../uploads');
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, UPLOAD_DIR);
  },
  filename: function (req, file, cb) {
    const user = req.session.userId || 'anon';
    cb(null, user + '-' + Date.now() + path.extname(file.originalname));
  }
});
const upload = multer({ storage });

// ====== SQLITE DB SETUP ======
const db = new sqlite3.Database('./peaceout.db');
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    avatarUrl TEXT,
    bio TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS videos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER,
    title TEXT,
    description TEXT,
    filename TEXT,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(userId) REFERENCES users(id)
  )`);
});

// ====== USER APIS ======

// Register
app.post('/api/register', async (req, res) => {
  const { username, password, passwordRepeat } = req.body;
  if (!username || !password || !passwordRepeat)
    return res.status(400).json({ error: 'Missing fields' });
  if (password !== passwordRepeat)
    return res.status(400).json({ error: 'Passwords do not match' });
  const hash = await bcrypt.hash(password, 10);
  db.run('INSERT INTO users (username, password, avatarUrl) VALUES (?, ?, ?)',
    [username, hash, `https://api.dicebear.com/7.x/thumbs/svg?seed=${encodeURIComponent(username)}`],
    function (err) {
      if (err) return res.status(400).json({ error: 'Username taken' });
      req.session.userId = this.lastID;
      res.json({ id: this.lastID, username });
    });
});

// Login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (!user) return res.status(401).json({ error: 'Invalid login' });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Invalid login' });
    req.session.userId = user.id;
    res.json({ id: user.id, username: user.username, avatarUrl: user.avatarUrl, bio: user.bio });
  });
});

// Logout
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

// Get current user
app.get('/api/me', (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  db.get('SELECT id, username, avatarUrl, bio FROM users WHERE id = ?', [req.session.userId], (err, user) => {
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  });
});

// Update profile (avatar, bio)
app.post('/api/me', (req, res) => {
  const { avatarUrl, bio } = req.body;
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  db.run('UPDATE users SET avatarUrl = ?, bio = ? WHERE id = ?', [avatarUrl, bio, req.session.userId], function(err) {
    if (err) return res.status(500).json({ error: 'Update failed' });
    res.json({ success: true });
  });
});

// ====== VIDEO APIS ======

// Upload video
app.post('/api/videos/upload', upload.single('video'), (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  const { title, description } = req.body;
  if (!title || !req.file)
    return res.status(400).json({ error: 'Missing video or title' });
  db.run('INSERT INTO videos (userId, title, description, filename) VALUES (?, ?, ?, ?)',
    [req.session.userId, title, description || '', req.file.filename],
    function (err) {
      if (err) return res.status(500).json({ error: 'Failed to save video' });
      res.json({ id: this.lastID, title, description, filename: req.file.filename });
    });
});

// List all videos
app.get('/api/videos', (req, res) => {
  db.all(`SELECT videos.*, users.username, users.avatarUrl
          FROM videos
          LEFT JOIN users ON videos.userId = users.id
          ORDER BY videos.createdAt DESC`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch videos' });
    res.json(rows);
  });
});

// Get single video info
app.get('/api/videos/:id', (req, res) => {
  db.get(`SELECT videos.*, users.username, users.avatarUrl
          FROM videos
          LEFT JOIN users ON videos.userId = users.id
          WHERE videos.id = ?`, [req.params.id], (err, video) => {
    if (!video) return res.status(404).json({ error: 'Video not found' });
    res.json(video);
  });
});

// List videos by user
app.get('/api/users/:id/videos', (req, res) => {
  db.all(`SELECT * FROM videos WHERE userId = ? ORDER BY createdAt DESC`, [req.params.id], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch videos' });
    res.json(rows);
  });
});

// ====== DISCOVER/SEARCH API ======
app.get('/api/discover', (req, res) => {
  const { q = '', type = 'all' } = req.query;
  const searchQ = `%${q}%`;

  const results = {};
  let toSearch = [];

  if (!type || type === 'all') toSearch = ['users', 'videos'];
  else if (type === 'users') toSearch = ['users'];
  else if (type === 'videos') toSearch = ['videos'];

  let pending = toSearch.length;
  if (pending === 0) return res.json({ users: [], videos: [] });

  if (toSearch.includes('users')) {
    db.all(
      `SELECT id, username, avatarUrl, bio FROM users WHERE username LIKE ? OR bio LIKE ? LIMIT 10`,
      [searchQ, searchQ],
      (err, rows) => {
        results.users = rows || [];
        if (--pending === 0) res.json(results);
      }
    );
  }
  if (toSearch.includes('videos')) {
    db.all(
      `SELECT videos.id, videos.title, videos.description, videos.filename, users.username as uploaderUsername, users.avatarUrl as uploaderAvatar
       FROM videos LEFT JOIN users ON videos.userId = users.id
       WHERE videos.title LIKE ? OR videos.description LIKE ? OR users.username LIKE ?
       ORDER BY videos.createdAt DESC LIMIT 10`,
      [searchQ, searchQ, searchQ],
      (err, rows) => {
        results.videos = rows || [];
        if (--pending === 0) res.json(results);
      }
    );
  }
});

// Serve uploaded videos statically
app.use('/uploads', express.static(UPLOAD_DIR));

// --- Server start ---
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`PeaceOut API running on http://localhost:${PORT}`));
