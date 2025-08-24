require('dotenv').config({ 
  path: process.env.NODE_ENV === 'production' ? '/etc/secrets/.env' : '.env' 
});

const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');

// --- Use custom upload/transcode middleware instead of plain multerS3 ---
const { upload, transcodeAndUpload } = require('./transcode-upload');
const AWS = require('aws-sdk');

const app = express();

app.set('trust proxy', 1); // Trust first proxy (Render)

// ====== FIXED SESSION AND CORS CONFIG FOR CROSS-DOMAIN LOGIN ======
app.use(cors({
  origin: ['https://justyydev.github.io', 'http://localhost:3000'],
  credentials: true
}));
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'peaceoutSecret',
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: true,           // IMPORTANT: only send cookie over HTTPS
    sameSite: 'none'        // CRITICAL: allow cross-site cookies
  }
}));

app.use((req, res, next) => {
  if (process.env.NODE_ENV === 'production' && req.headers['x-forwarded-proto'] !== 'https') {
    return res.redirect('https://' + req.headers.host + req.url);
  }
  next();
});

// ====== SQLITE DB SETUP ======
const db = new sqlite3.Database(process.env.DATABASE_PATH || './peaceout.db');
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    avatarUrl TEXT,
    bio TEXT
  )`);
  // Add new columns for likes, dislikes, views if not exist (sqlite can't do ALTER IF NOT EXISTS, so try/catch)
  db.run(`CREATE TABLE IF NOT EXISTS videos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER,
    title TEXT,
    description TEXT,
    filename TEXT,
    likes INTEGER DEFAULT 0,
    dislikes INTEGER DEFAULT 0,
    views INTEGER DEFAULT 0,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(userId) REFERENCES users(id)
  )`);
  // Attempt to add columns in case running on old DB (ignore error if already present)
  db.run('ALTER TABLE videos ADD COLUMN likes INTEGER DEFAULT 0', [], ()=>{});
  db.run('ALTER TABLE videos ADD COLUMN dislikes INTEGER DEFAULT 0', [], ()=>{});
  db.run('ALTER TABLE videos ADD COLUMN views INTEGER DEFAULT 0', [], ()=>{});
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

// Upload video (transcodes to mp4/h264/aac and uploads to S3/e2)
app.post('/api/videos/upload', upload.single('video'), transcodeAndUpload, (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  const { title, description } = req.body;
  if (!title)
    return res.status(400).json({ error: 'Missing video title' });
  // Save the S3 location (req.transcodedVideoUrl) instead of filename
  db.run('INSERT INTO videos (userId, title, description, filename) VALUES (?, ?, ?, ?)',
    [req.session.userId, title, description || '', req.transcodedVideoUrl],
    function (err) {
      if (err) return res.status(500).json({ error: 'Failed to save video' });
      res.json({ id: this.lastID, title, description, filename: req.transcodedVideoUrl });
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

// Like a video
app.post('/api/videos/:id/like', (req, res) => {
  db.run('UPDATE videos SET likes = likes + 1 WHERE id = ?', [req.params.id], function (err) {
    if (err) return res.status(500).json({ error: 'Like failed' });
    res.json({ success: true });
  });
});

// Dislike a video
app.post('/api/videos/:id/dislike', (req, res) => {
  db.run('UPDATE videos SET dislikes = dislikes + 1 WHERE id = ?', [req.params.id], function (err) {
    if (err) return res.status(500).json({ error: 'Dislike failed' });
    res.json({ success: true });
  });
});

// Increment views (call this when video starts playing)
app.post('/api/videos/:id/view', (req, res) => {
  db.run('UPDATE videos SET views = views + 1 WHERE id = ?', [req.params.id], function (err) {
    if (err) return res.status(500).json({ error: 'View failed' });
    res.json({ success: true });
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
      `SELECT videos.id, videos.title, videos.description, videos.filename, videos.likes, videos.dislikes, videos.views, users.username as uploaderUsername, users.avatarUrl as uploaderAvatar
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

// --- Server start ---
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`PeaceOut API running on http://localhost:${PORT}`));
