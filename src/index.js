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
const http = require('http'); // For Socket.IO
const { Server } = require('socket.io');

// --- Use custom upload/transcode middleware instead of plain multerS3 ---
const { upload, transcodeAndUpload } = require('./transcode-upload');
const plazaParty = require('./plaza-party');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: ['https://justyydev.github.io', 'http://localhost:3000'],
    credentials: true
  }
});

plazaParty.setupPlazaSocket(io);

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
const db = plazaParty.db; // Use shared db instance

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
    type TEXT,
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

  // Follows: for legacy support, but now replaced by friends/parties
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
const avatarUpload = multer({ dest: '/tmp', limits: { fileSize: 2 * 1024 * 1024 } });

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

// ====== FRIENDS API ======
// Send friend request
app.post('/api/friends/request', (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "Not logged in" });
  const { toUser } = req.body;
  plazaParty.sendFriendRequest(db, req.session.userId, toUser, result => res.json(result));
});
// Accept friend request
app.post('/api/friends/accept', (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "Not logged in" });
  const { fromUser } = req.body;
  plazaParty.acceptFriendRequest(db, req.session.userId, fromUser, result => res.json(result));
});
// Remove friend
app.delete('/api/friends/:friendId', (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "Not logged in" });
  plazaParty.removeFriend(db, req.session.userId, req.params.friendId, result => res.json(result));
});
// List my friends
app.get('/api/friends', (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "Not logged in" });
  plazaParty.getFriends(db, req.session.userId, result => res.json(result));
});

// ====== PARTY API ======
// Create party
app.post('/api/party/create', (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "Not logged in" });
  plazaParty.createParty(db, req.session.userId, result => res.json(result));
});
// Join party
app.post('/api/party/join', (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "Not logged in" });
  const { partyId } = req.body;
  plazaParty.joinParty(db, partyId, req.session.userId, result => res.json(result));
});
// Leave party
app.post('/api/party/leave', (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "Not logged in" });
  plazaParty.leaveParty(db, req.session.userId, result => res.json(result));
});
// Get my party
app.get('/api/party/me', (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "Not logged in" });
  plazaParty.getMyParty(db, req.session.userId, result => res.json(result));
});

// ====== MARKETSTAND/MINIGAME API ======
app.get('/api/minigames', (req, res) => {
  plazaParty.getMinigames(db, rows => res.json(rows));
});
app.post('/api/party/start-game', (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "Not logged in" });
  const { partyId, minigameId } = req.body;
  // Only party host can start games (should check in plazaParty)
  plazaParty.startPartyGame(db, partyId, minigameId, result => res.json(result));
});
app.get('/api/party/game', (req, res) => {
  const partyId = req.query.partyId;
  plazaParty.getPartyGameState(db, partyId, row => res.json(row));
});
app.post('/api/party/game/state', (req, res) => {
  const { partyId, state } = req.body;
  plazaParty.updatePartyGameState(db, partyId, state, result => res.json(result));
});

// ====== USER APIS (as before, unchanged) ======
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

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

app.get('/api/me', (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  db.get('SELECT id, username, avatarUrl, bio, displayName, theme FROM users WHERE id = ?', [req.session.userId], (err, user) => {
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  });
});

app.post('/api/me', (req, res) => {
  const { avatarUrl, bio, displayName, theme } = req.body;
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  db.run('UPDATE users SET avatarUrl = ?, bio = ?, displayName = ?, theme = ? WHERE id = ?',
    [avatarUrl, bio, displayName, theme, req.session.userId], function(err) {
    if (err) return res.status(500).json({ error: 'Update failed' });
    res.json({ success: true });
  });
});

// ====== VIDEO APIS ======
app.get('/api/videos', (req, res) => {
  db.all(`
    SELECT v.*, u.username, u.displayName, u.avatarUrl, 
           COUNT(DISTINCT vr.id) as totalReactions
    FROM videos v 
    LEFT JOIN users u ON v.userId = u.id 
    LEFT JOIN video_reactions vr ON v.id = vr.videoId
    GROUP BY v.id
    ORDER BY v.createdAt DESC 
    LIMIT 50
  `, [], (err, videos) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(videos || []);
  });
});

app.get('/api/videos/:id', (req, res) => {
  const videoId = req.params.id;
  // Increment view count
  db.run('UPDATE videos SET views = views + 1 WHERE id = ?', [videoId]);
  
  db.get(`
    SELECT v.*, u.username, u.displayName, u.avatarUrl
    FROM videos v 
    LEFT JOIN users u ON v.userId = u.id 
    WHERE v.id = ?
  `, [videoId], (err, video) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!video) return res.status(404).json({ error: 'Video not found' });
    res.json(video);
  });
});

app.post('/api/videos/upload', upload.single('video'), transcodeAndUpload, (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  const { title, description } = req.body;
  if (!title) return res.status(400).json({ error: 'Title required' });
  
  const videoUrl = req.videoUrl || ''; // Set by transcodeAndUpload middleware
  
  db.run('INSERT INTO videos (userId, title, description, filename) VALUES (?, ?, ?, ?)',
    [req.session.userId, title, description, videoUrl],
    function(err) {
      if (err) return res.status(500).json({ error: 'Upload failed' });
      res.json({ id: this.lastID, title, description, filename: videoUrl });
    });
});

app.post('/api/videos/:id/reaction', (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  const { type } = req.body; // 'like' or 'dislike'
  const videoId = req.params.id;
  
  if (!['like', 'dislike'].includes(type)) {
    return res.status(400).json({ error: 'Invalid reaction type' });
  }
  
  // Insert or update reaction
  db.run('INSERT OR REPLACE INTO video_reactions (userId, videoId, type) VALUES (?, ?, ?)',
    [req.session.userId, videoId, type], function(err) {
      if (err) return res.status(500).json({ error: 'Database error' });
      
      // Update video counts
      db.run(`UPDATE videos SET 
        likes = (SELECT COUNT(*) FROM video_reactions WHERE videoId = ? AND type = 'like'),
        dislikes = (SELECT COUNT(*) FROM video_reactions WHERE videoId = ? AND type = 'dislike')
        WHERE id = ?`, [videoId, videoId, videoId]);
      
      res.json({ success: true });
    });
});

// ====== COMMENTS API ======
app.get('/api/videos/:id/comments', (req, res) => {
  const videoId = req.params.id;
  db.all(`
    SELECT c.*, u.username, u.displayName, u.avatarUrl
    FROM comments c 
    LEFT JOIN users u ON c.userId = u.id 
    WHERE c.videoId = ? 
    ORDER BY c.createdAt DESC
  `, [videoId], (err, comments) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(comments || []);
  });
});

app.post('/api/videos/:id/comments', (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  const { text } = req.body;
  const videoId = req.params.id;
  
  if (!text || !text.trim()) return res.status(400).json({ error: 'Comment text required' });
  
  db.run('INSERT INTO comments (videoId, userId, text) VALUES (?, ?, ?)',
    [videoId, req.session.userId, text.trim()], function(err) {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json({ id: this.lastID, text: text.trim(), createdAt: new Date().toISOString() });
    });
});

// ====== DISCOVER/SEARCH API ======
app.get('/api/discover', (req, res) => {
  const { q, type = 'all' } = req.query;
  if (!q || !q.trim()) return res.json({ users: [], videos: [] });
  
  const searchTerm = `%${q.trim()}%`;
  const results = { users: [], videos: [] };
  
  const queries = [];
  
  if (type === 'all' || type === 'users') {
    queries.push(new Promise((resolve) => {
      db.all(`
        SELECT id, username, displayName, avatarUrl, bio, theme
        FROM users 
        WHERE username LIKE ? OR displayName LIKE ? OR bio LIKE ?
        LIMIT 20
      `, [searchTerm, searchTerm, searchTerm], (err, users) => {
        results.users = err ? [] : users;
        resolve();
      });
    }));
  }
  
  if (type === 'all' || type === 'videos') {
    queries.push(new Promise((resolve) => {
      db.all(`
        SELECT v.*, u.username as uploaderUsername, u.displayName as uploaderDisplayName
        FROM videos v 
        LEFT JOIN users u ON v.userId = u.id
        WHERE v.title LIKE ? OR v.description LIKE ?
        ORDER BY v.createdAt DESC
        LIMIT 20
      `, [searchTerm, searchTerm], (err, videos) => {
        results.videos = err ? [] : videos;
        resolve();
      });
    }));
  }
  
  Promise.all(queries).then(() => {
    res.json(results);
  });
});

// ====== USER PROFILE API ======
app.get('/api/users/:username', (req, res) => {
  const username = req.params.username;
  db.get(`
    SELECT id, username, displayName, avatarUrl, bio, theme, 
           (SELECT COUNT(*) FROM videos WHERE userId = users.id) as videoCount
    FROM users 
    WHERE username = ?
  `, [username], (err, user) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!user) return res.status(404).json({ error: 'User not found' });
    
    // Get user's videos
    db.all(`
      SELECT v.*, 
             (SELECT COUNT(*) FROM video_reactions WHERE videoId = v.id AND type = 'like') as likes,
             (SELECT COUNT(*) FROM video_reactions WHERE videoId = v.id AND type = 'dislike') as dislikes
      FROM videos v 
      WHERE v.userId = ? 
      ORDER BY v.createdAt DESC
    `, [user.id], (err, videos) => {
      user.videos = err ? [] : videos;
      res.json(user);
    });
  });
});

// ====== FOLLOW/UNFOLLOW API ======
app.get('/api/follow/:userId', (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  const targetUserId = req.params.userId;
  
  db.get('SELECT * FROM follows WHERE followerId = ? AND followedId = ?',
    [req.session.userId, targetUserId], (err, follow) => {
      res.json({ isFollowing: !!follow });
    });
});

app.post('/api/follow/:userId', (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  const targetUserId = req.params.userId;
  
  if (req.session.userId == targetUserId) {
    return res.status(400).json({ error: 'Cannot follow yourself' });
  }
  
  db.run('INSERT OR IGNORE INTO follows (followerId, followedId) VALUES (?, ?)',
    [req.session.userId, targetUserId], function(err) {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json({ success: true, isFollowing: true });
    });
});

app.delete('/api/follow/:userId', (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  const targetUserId = req.params.userId;
  
  db.run('DELETE FROM follows WHERE followerId = ? AND followedId = ?',
    [req.session.userId, targetUserId], function(err) {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json({ success: true, isFollowing: false });
    });
});

// --- Server start (important: use server.listen, not app.listen) ---
const PORT = process.env.PORT || 4000;
server.listen(PORT, () => console.log(`PeaceOut API + Plaza running on http://localhost:${PORT}`));