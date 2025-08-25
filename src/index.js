require('dotenv').config({
  path: process.env.NODE_ENV === 'production' ? '/etc/secrets/.env' : '.env'
});

const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');
const multer = require('multer');
const AWS = require('aws-sdk');
const fs = require('fs');

// --- Use custom upload/transcode middleware instead of plain multerS3 ---
const { upload, transcodeAndUpload } = require('./transcode-upload');

const app = express();

app.set('trust proxy', 1);

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
    secure: true,
    sameSite: 'none'
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
  // Users table: displayName and theme for customization
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    avatarUrl TEXT,
    bio TEXT,
    displayName TEXT,
    theme TEXT
  )`);
  // Try to add missing columns for old DBs
  db.run('ALTER TABLE users ADD COLUMN displayName TEXT', [], () => {});
  db.run('ALTER TABLE users ADD COLUMN theme TEXT', [], () => {});

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
  db.run('ALTER TABLE videos ADD COLUMN likes INTEGER DEFAULT 0', [], () => {});
  db.run('ALTER TABLE videos ADD COLUMN dislikes INTEGER DEFAULT 0', [], () => {});
  db.run('ALTER TABLE videos ADD COLUMN views INTEGER DEFAULT 0', [], () => {});

  db.run(`CREATE TABLE IF NOT EXISTS video_reactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER,
    videoId INTEGER,
    type TEXT, -- 'like' or 'dislike'
    UNIQUE(userId, videoId),
    FOREIGN KEY(userId) REFERENCES users(id),
    FOREIGN KEY(videoId) REFERENCES videos(id)
  )`);

  // Comments on videos
  db.run(`CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    videoId INTEGER,
    userId INTEGER,
    text TEXT,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(videoId) REFERENCES videos(id),
    FOREIGN KEY(userId) REFERENCES users(id)
  )`);

  // Follows: user subscriptions
  db.run(`CREATE TABLE IF NOT EXISTS follows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    followerId INTEGER,
    followedId INTEGER,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(followerId, followedId),
    FOREIGN KEY(followerId) REFERENCES users(id),
    FOREIGN KEY(followedId) REFERENCES users(id)
  )`);
});

// ====== PROFILE THEMES ======
const PROFILE_THEMES = [
  { id: "peaceful", name: "Peaceful" },
  { id: "energetic", name: "Energetic" },
  { id: "classic", name: "Classic" },
  { id: "night", name: "Night" }
];
app.get('/api/profile-themes', (req, res) => {
  res.json(PROFILE_THEMES);
});

// ====== Avatar Upload Endpoint ======
const s3 = new AWS.S3({
  endpoint: process.env.E2_ENDPOINT,
  accessKeyId: process.env.E2_KEY,
  secretAccessKey: process.env.E2_SECRET,
  region: process.env.E2_REGION,
  signatureVersion: 'v4',
  s3ForcePathStyle: true
});
const avatarUpload = multer({ dest: '/tmp', limits: { fileSize: 2 * 1024 * 1024 } }); // 2MB limit

app.post('/api/avatar/upload', avatarUpload.single('avatar'), async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  const ext = (req.file.originalname.match(/\.(png|jpe?g|gif)$/i) || [])[0];
  if (!ext) { fs.unlink(req.file.path, () => {}); return res.status(400).json({ error: 'Invalid file type' }); }
  const s3Key = `avatars/${req.session.userId}-${Date.now()}${ext}`;
  try {
    const s3res = await s3.upload({
      Bucket: process.env.E2_BUCKET || 'peaceout-uploads',
      Key: s3Key,
      Body: fs.createReadStream(req.file.path),
      ContentType: req.file.mimetype,
      ACL: 'public-read'
    }).promise();
    res.json({ url: s3res.Location });
    fs.unlink(req.file.path, ()=>{});
  } catch (e) {
    fs.unlink(req.file.path, ()=>{});
    res.status(500).json({ error: 'Upload failed' });
  }
});

// ====== USER APIS ======

// Register with displayName and theme default
app.post('/api/register', async (req, res) => {
  const { username, password, passwordRepeat } = req.body;
  if (!username || !password || !passwordRepeat)
    return res.status(400).json({ error: 'Missing fields' });
  if (password !== passwordRepeat)
    return res.status(400).json({ error: 'Passwords do not match' });
  const hash = await bcrypt.hash(password, 10);
  db.run('INSERT INTO users (username, password, avatarUrl, displayName, theme) VALUES (?, ?, ?, ?, ?)',
    [
      username,
      hash,
      `https://api.dicebear.com/7.x/thumbs/svg?seed=${encodeURIComponent(username)}`,
      username,
      "peaceful"
    ],
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
    res.json({
      id: user.id,
      username: user.username,
      avatarUrl: user.avatarUrl,
      bio: user.bio,
      displayName: user.displayName,
      theme: user.theme
    });
  });
});

// Logout
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

// Get current user (with displayName, theme)
app.get('/api/me', (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  db.get('SELECT id, username, avatarUrl, bio, displayName, theme FROM users WHERE id = ?', [req.session.userId], (err, user) => {
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  });
});

// Update profile (avatar, bio, displayName, theme)
app.post('/api/me', (req, res) => {
  const { avatarUrl, bio, displayName, theme } = req.body;
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  db.run('UPDATE users SET avatarUrl = ?, bio = ?, displayName = ?, theme = ? WHERE id = ?',
    [avatarUrl, bio, displayName, theme, req.session.userId], function(err) {
    if (err) return res.status(500).json({ error: 'Update failed' });
    res.json({ success: true });
  });
});

// ====== USER PROFILE PAGE (by username) ======
app.get('/api/users/:username', (req, res) => {
  const username = req.params.username;
  db.get(`SELECT id, username, avatarUrl, bio, displayName, theme FROM users WHERE username = ?`, [username], (err, user) => {
    if (!user) return res.status(404).json({ error: 'User not found' });
    db.get(`SELECT COUNT(*) as followers FROM follows WHERE followedId = ?`, [user.id], (e1, f1) => {
      db.get(`SELECT COUNT(*) as following FROM follows WHERE followerId = ?`, [user.id], (e2, f2) => {
        db.all(`SELECT * FROM videos WHERE userId = ? ORDER BY createdAt DESC`, [user.id], (e3, videos) => {
          res.json({
            ...user,
            followers: f1 ? f1.followers : 0,
            following: f2 ? f2.following : 0,
            videos: videos || []
          });
        });
      });
    });
  });
});

// ====== VIDEO APIS ======

// Upload video (transcodes to mp4/h264/aac and uploads to S3/e2)
app.post('/api/videos/upload', upload.single('video'), transcodeAndUpload, (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  const { title, description } = req.body;
  if (!title)
    return res.status(400).json({ error: 'Missing video title' });
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

// List videos by user ID
app.get('/api/users/:id/videos', (req, res) => {
  db.all(`SELECT * FROM videos WHERE userId = ? ORDER BY createdAt DESC`, [req.params.id], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch videos' });
    res.json(rows);
  });
});

// Like a video (only once per user, cannot both like and dislike)
app.post('/api/videos/:id/like', (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Login required' });
  const userId = req.session.userId;
  const videoId = req.params.id;

  db.get('SELECT * FROM video_reactions WHERE userId = ? AND videoId = ?', [userId, videoId], (err, reaction) => {
    if (err) return res.status(500).json({ error: 'DB error' });

    if (reaction && reaction.type === 'like') {
      db.serialize(() => {
        db.run('DELETE FROM video_reactions WHERE userId = ? AND videoId = ?', [userId, videoId]);
        db.run('UPDATE videos SET likes = likes - 1 WHERE id = ? AND likes > 0', [videoId]);
      });
      return res.json({ liked: false, disliked: false });
    } else if (reaction && reaction.type === 'dislike') {
      db.serialize(() => {
        db.run('UPDATE video_reactions SET type = ? WHERE userId = ? AND videoId = ?', ['like', userId, videoId]);
        db.run('UPDATE videos SET likes = likes + 1, dislikes = dislikes - 1 WHERE id = ? AND dislikes > 0', [videoId]);
      });
      return res.json({ liked: true, disliked: false });
    } else {
      db.serialize(() => {
        db.run('INSERT OR IGNORE INTO video_reactions (userId, videoId, type) VALUES (?, ?, ?)', [userId, videoId, 'like']);
        db.run('UPDATE videos SET likes = likes + 1 WHERE id = ?', [videoId]);
      });
      return res.json({ liked: true, disliked: false });
    }
  });
});

app.post('/api/videos/:id/dislike', (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Login required' });
  const userId = req.session.userId;
  const videoId = req.params.id;

  db.get('SELECT * FROM video_reactions WHERE userId = ? AND videoId = ?', [userId, videoId], (err, reaction) => {
    if (err) return res.status(500).json({ error: 'DB error' });

    if (reaction && reaction.type === 'dislike') {
      db.serialize(() => {
        db.run('DELETE FROM video_reactions WHERE userId = ? AND videoId = ?', [userId, videoId]);
        db.run('UPDATE videos SET dislikes = dislikes - 1 WHERE id = ? AND dislikes > 0', [videoId]);
      });
      return res.json({ liked: false, disliked: false });
    } else if (reaction && reaction.type === 'like') {
      db.serialize(() => {
        db.run('UPDATE video_reactions SET type = ? WHERE userId = ? AND videoId = ?', ['dislike', userId, videoId]);
        db.run('UPDATE videos SET dislikes = dislikes + 1, likes = likes - 1 WHERE id = ? AND likes > 0', [videoId]);
      });
      return res.json({ liked: false, disliked: true });
    } else {
      db.serialize(() => {
        db.run('INSERT OR IGNORE INTO video_reactions (userId, videoId, type) VALUES (?, ?, ?)', [userId, videoId, 'dislike']);
        db.run('UPDATE videos SET dislikes = dislikes + 1 WHERE id = ?', [videoId]);
      });
      return res.json({ liked: false, disliked: true });
    }
  });
});

app.get('/api/videos/:id/reaction', (req, res) => {
  if (!req.session.userId) return res.json({ liked: false, disliked: false });
  db.get('SELECT type FROM video_reactions WHERE userId = ? AND videoId = ?', [req.session.userId, req.params.id], (err, row) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json({
      liked: row && row.type === 'like',
      disliked: row && row.type === 'dislike'
    });
  });
});

// Increment views (call this when video starts playing)
app.post('/api/videos/:id/view', (req, res) => {
  db.run('UPDATE videos SET views = views + 1 WHERE id = ?', [req.params.id], function (err) {
    if (err) return res.status(500).json({ error: 'View failed' });
    res.json({ success: true });
  });
});

// ====== COMMENTS API ======
// Get comments for a video
app.get('/api/videos/:id/comments', (req, res) => {
  db.all(
    `SELECT comments.*, users.username, users.displayName, users.avatarUrl
     FROM comments
     LEFT JOIN users ON comments.userId = users.id
     WHERE comments.videoId = ?
     ORDER BY comments.createdAt ASC`,
    [req.params.id],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Failed to fetch comments' });
      res.json(rows || []);
    }
  );
});
// Post a new comment on a video
app.post('/api/videos/:id/comments', (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  const { text } = req.body;
  if (!text || text.trim().length === 0) return res.status(400).json({ error: 'Comment cannot be empty' });
  db.run(
    `INSERT INTO comments (videoId, userId, text) VALUES (?, ?, ?)`,
    [req.params.id, req.session.userId, text.trim()],
    function (err) {
      if (err) return res.status(500).json({ error: 'Failed to post comment' });
      db.get(
        `SELECT comments.*, users.username, users.displayName, users.avatarUrl
         FROM comments LEFT JOIN users ON comments.userId = users.id
         WHERE comments.id = ?`, [this.lastID], (e, row) => {
          if (e) return res.json({ success: true });
          res.json(row);
        });
    }
  );
});

// ====== FOLLOW/SUBSCRIBE API ======
// Follow a user
app.post('/api/follow/:userId', (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  if (parseInt(req.params.userId) === req.session.userId) return res.status(400).json({ error: 'Cannot follow yourself' });
  db.run(
    `INSERT OR IGNORE INTO follows (followerId, followedId) VALUES (?, ?)`,
    [req.session.userId, req.params.userId],
    function (err) {
      if (err) return res.status(500).json({ error: 'Failed to follow' });
      res.json({ followed: true });
    }
  );
});
// Unfollow a user
app.delete('/api/follow/:userId', (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  db.run(
    `DELETE FROM follows WHERE followerId = ? AND followedId = ?`,
    [req.session.userId, req.params.userId],
    function (err) {
      if (err) return res.status(500).json({ error: 'Failed to unfollow' });
      res.json({ followed: false });
    }
  );
});
// Get who a user is following
app.get('/api/users/:id/following', (req, res) => {
  db.all(
    `SELECT users.id, users.username, users.displayName, users.avatarUrl
     FROM follows
     LEFT JOIN users ON follows.followedId = users.id
     WHERE follows.followerId = ?`,
    [req.params.id],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Failed' });
      res.json(rows || []);
    }
  );
});
// Get followers of a user
app.get('/api/users/:id/followers', (req, res) => {
  db.all(
    `SELECT users.id, users.username, users.displayName, users.avatarUrl
     FROM follows
     LEFT JOIN users ON follows.followerId = users.id
     WHERE follows.followedId = ?`,
    [req.params.id],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Failed' });
      res.json(rows || []);
    }
  );
});
// Get if current user follows another user
app.get('/api/follow/:userId', (req, res) => {
  if (!req.session.userId) return res.json({ follows: false });
  db.get(
    `SELECT 1 FROM follows WHERE followerId = ? AND followedId = ?`,
    [req.session.userId, req.params.userId],
    (err, row) => {
      if (err) return res.status(500).json({ error: 'Failed' });
      res.json({ follows: !!row });
    }
  );
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
      `SELECT id, username, avatarUrl, bio, displayName, theme FROM users WHERE username LIKE ? OR bio LIKE ? OR displayName LIKE ? LIMIT 10`,
      [searchQ, searchQ, searchQ],
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
