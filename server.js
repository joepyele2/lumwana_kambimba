const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const path = require('path');
const compression = require('compression');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// ============ DATABASE SETUP ============
const dbPath = process.env.DB_PATH || path.join(__dirname, 'dashboard.db');
const db = new Database(dbPath);

// Enable WAL mode for better performance
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// Create tables
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'foreman',
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS project_data (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_by TEXT,
    updated_at TEXT DEFAULT (datetime('now'))
  );
`);

// Create default admin if no users exist
const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get();
if (userCount.count === 0) {
  const adminEmail = process.env.ADMIN_EMAIL || 'admin@dashboard.com';
  const adminPassword = process.env.ADMIN_PASSWORD || 'Admin2024!';
  const hash = bcrypt.hashSync(adminPassword, 10);
  db.prepare('INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)').run('Administrator', adminEmail, hash, 'admin');
  console.log(`Default admin created: ${adminEmail} / ${adminPassword}`);
  console.log('IMPORTANT: Change this password after first login!');
}

// ============ MIDDLEWARE ============
app.use(compression());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: process.env.SESSION_SECRET || 'road-dashboard-secret-2024-change-this',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Auth middleware
function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });
  if (req.session.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
}

// ============ AUTH ROUTES ============
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase().trim());
  if (!user) return res.status(401).json({ error: 'Invalid email or password' });

  const valid = bcrypt.compareSync(password, user.password);
  if (!valid) return res.status(401).json({ error: 'Invalid email or password' });

  req.session.user = { id: user.id, name: user.name, email: user.email, role: user.role };
  res.json({ success: true, user: { name: user.name, email: user.email, role: user.role } });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.get('/api/me', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });
  res.json(req.session.user);
});

// ============ USER MANAGEMENT (Admin only) ============
app.get('/api/users', requireAdmin, (req, res) => {
  const users = db.prepare('SELECT id, name, email, role, created_at FROM users ORDER BY role, name').all();
  res.json(users);
});

app.post('/api/users', requireAdmin, (req, res) => {
  const { name, email, password, role } = req.body;
  if (!name || !email || !password || !role) return res.status(400).json({ error: 'All fields required' });
  const validRoles = ['admin', 'supervisor', 'foreman'];
  if (!validRoles.includes(role)) return res.status(400).json({ error: 'Invalid role' });

  try {
    const hash = bcrypt.hashSync(password, 10);
    const result = db.prepare('INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)').run(name, email.toLowerCase().trim(), hash, role);
    res.json({ success: true, id: result.lastInsertRowid });
  } catch (e) {
    if (e.message.includes('UNIQUE')) return res.status(400).json({ error: 'Email already exists' });
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/users/:id', requireAdmin, (req, res) => {
  const { name, email, role, password } = req.body;
  try {
    if (password) {
      const hash = bcrypt.hashSync(password, 10);
      db.prepare('UPDATE users SET name=?, email=?, role=?, password=? WHERE id=?').run(name, email.toLowerCase().trim(), role, hash, req.params.id);
    } else {
      db.prepare('UPDATE users SET name=?, email=?, role=? WHERE id=?').run(name, email.toLowerCase().trim(), role, req.params.id);
    }
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/users/:id', requireAdmin, (req, res) => {
  if (parseInt(req.params.id) === req.session.user.id) return res.status(400).json({ error: 'Cannot delete yourself' });
  db.prepare('DELETE FROM users WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

app.post('/api/change-password', requireAuth, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE id=?').get(req.session.user.id);
  if (!bcrypt.compareSync(currentPassword, user.password)) return res.status(400).json({ error: 'Current password is wrong' });
  const hash = bcrypt.hashSync(newPassword, 10);
  db.prepare('UPDATE users SET password=? WHERE id=?').run(hash, req.session.user.id);
  res.json({ success: true });
});

// ============ DATA ROUTES ============
// Get all project data
app.get('/api/data', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT key, value, updated_by, updated_at FROM project_data').all();
  const data = {};
  rows.forEach(row => {
    try { data[row.key] = JSON.parse(row.value); } catch(e) { data[row.key] = row.value; }
  });
  res.json(data);
});

// Get single key
app.get('/api/data/:key', requireAuth, (req, res) => {
  const row = db.prepare('SELECT value FROM project_data WHERE key=?').get(req.params.key);
  if (!row) return res.json(null);
  try { res.json(JSON.parse(row.value)); } catch(e) { res.json(row.value); }
});

// Save single key
app.post('/api/data/:key', requireAuth, (req, res) => {
  const { value } = req.body;
  const key = req.params.key;

  // Role-based write restrictions
  const foremanAllowed = ['dailyReports', 'taskCompletions', 'issues'];
  if (req.session.user.role === 'foreman' && !foremanAllowed.includes(key)) {
    return res.status(403).json({ error: 'Foreman cannot edit this section' });
  }
  const supervisorAllowed = [...foremanAllowed, 'weeklyPlans', 'monthlyReports', 'ganttTasks', 'dailyTargets'];
  if (req.session.user.role === 'supervisor' && !supervisorAllowed.includes(key)) {
    return res.status(403).json({ error: 'Supervisor cannot edit this section' });
  }

  db.prepare('INSERT OR REPLACE INTO project_data (key, value, updated_by, updated_at) VALUES (?, ?, ?, datetime("now"))').run(key, JSON.stringify(value), req.session.user.email);
  res.json({ success: true });
});

// Bulk import (for restore from backup)
app.post('/api/import', requireAdmin, (req, res) => {
  const data = req.body;
  const allowed = ['projectInfo','dailyReports','weeklyPlans','monthlyReports','workItems','equipment','issues','ganttTasks','taskCompletions','files','folders','customActivities','team','sicknessLog','dailyTargets'];
  const insert = db.prepare('INSERT OR REPLACE INTO project_data (key, value, updated_by, updated_at) VALUES (?, ?, ?, datetime("now"))');
  const insertMany = db.transaction((items) => {
    for (const [key, value] of items) {
      if (allowed.includes(key)) insert.run(key, JSON.stringify(value), req.session.user.email);
    }
  });
  insertMany(Object.entries(data));
  res.json({ success: true });
});

// Export all data as JSON backup
app.get('/api/export', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT key, value FROM project_data').all();
  const data = { exportDate: new Date().toISOString() };
  rows.forEach(row => {
    try { data[row.key] = JSON.parse(row.value); } catch(e) { data[row.key] = row.value; }
  });
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename="project-backup-${new Date().toISOString().split('T')[0]}.json"`);
  res.json(data);
});

// Long-polling for real-time updates
let lastUpdate = Date.now();
app.post('/api/data/:key', requireAuth, (req, res) => {
  lastUpdate = Date.now();
});

app.get('/api/poll', requireAuth, (req, res) => {
  const clientTime = parseInt(req.query.since) || 0;
  if (lastUpdate > clientTime) {
    res.json({ hasUpdate: true, timestamp: lastUpdate });
  } else {
    res.json({ hasUpdate: false, timestamp: lastUpdate });
  }
});

// ============ SERVE FRONTEND ============
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ============ START SERVER ============
app.listen(PORT, () => {
  console.log(`Road Construction Dashboard running on port ${PORT}`);
  console.log(`Open: http://localhost:${PORT}`);
});
