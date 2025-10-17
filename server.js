// server.js
const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const helmet = require('helmet');

const app = express();
const PORT = process.env.PORT || 3000;
const SALT_ROUNDS = 12;

app.use(helmet());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// Session (for demo use SQLite session store)
app.use(session({
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: '.' }),
  secret: process.env.SESSION_SECRET || 'replace-this-with-a-strong-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, httpOnly: true, maxAge: 1000 * 60 * 60 * 24 } // 1 day
}));

// Initialize SQLite DB
const db = new sqlite3.Database('./users.db', (err) => {
  if (err) console.error('DB open error', err);
  else console.log('Connected to SQLite DB');
});

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      email TEXT UNIQUE,
      password_hash TEXT,
      profile_json TEXT DEFAULT '{}',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
});

// Helper: get current user object by session
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ success: false, message: 'Unauthorized' });
  next();
}

// Signup endpoint
app.post('/api/signup', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) return res.status(400).json({ success: false, message: 'Missing fields' });
    if (password.length < 6) return res.status(400).json({ success: false, message: 'Password must be at least 6 characters' });

    const pwHash = await bcrypt.hash(password, SALT_ROUNDS);

    const stmt = db.prepare('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)');
    stmt.run(username, email.toLowerCase().trim(), pwHash, function(err) {
      if (err) {
        if (err.message.includes('UNIQUE')) return res.status(409).json({ success: false, message: 'Username or email already exists' });
        console.error(err);
        return res.status(500).json({ success: false, message: 'DB error' });
      }
      // set session
      req.session.userId = this.lastID;
      req.session.username = username;
      return res.json({ success: true, message: 'Account created', userId: this.lastID });
    });
    stmt.finalize();
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false });
  }
});

// Login endpoint
app.post('/api/login', (req, res) => {
  const { usernameOrEmail, password } = req.body;
  if (!usernameOrEmail || !password) return res.status(400).json({ success: false, message: 'Missing fields' });

  const query = `SELECT id, username, email, password_hash FROM users WHERE username = ? OR email = ? LIMIT 1`;
  db.get(query, [usernameOrEmail, usernameOrEmail.toLowerCase().trim()], async (err, row) => {
    if (err) { console.error(err); return res.status(500).json({ success: false }); }
    if (!row) return res.status(401).json({ success: false, message: 'Invalid credentials' });

    const match = await bcrypt.compare(password, row.password_hash);
    if (!match) return res.status(401).json({ success: false, message: 'Invalid credentials' });

    req.session.userId = row.id;
    req.session.username = row.username;
    return res.json({ success: true, message: 'Logged in' });
  });
});

// Logout
app.post('/api/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).json({ success: false });
    res.json({ success: true });
  });
});

// Get current user info
app.get('/api/me', (req, res) => {
  if (!req.session.userId) return res.json({ loggedIn: false });
  db.get('SELECT id, username, email, profile_json FROM users WHERE id = ?', [req.session.userId], (err, row) => {
    if (err) return res.status(500).json({ success: false });
    if (!row) return res.json({ loggedIn: false });
    const profile = JSON.parse(row.profile_json || '{}');
    res.json({ loggedIn: true, user: { id: row.id, username: row.username, email: row.email, profile } });
  });
});

// Save profile data (per-user saved data)
app.post('/api/profile', requireAuth, (req, res) => {
  const profile = req.body.profile || {};
  const profileStr = JSON.stringify(profile);
  db.run('UPDATE users SET profile_json = ? WHERE id = ?', [profileStr, req.session.userId], function(err) {
    if (err) { console.error(err); return res.status(500).json({ success: false }); }
    res.json({ success: true });
  });
});

// Serve index.html for everything else (SPA)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log('Server listening on', PORT);
});
