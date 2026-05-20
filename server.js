const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');
const compression = require('compression');

const app = express();
const PORT = process.env.PORT || 3000;

// ============ FILE DATABASE ============
const DB_DIR = process.env.DB_DIR || path.join(__dirname, 'data');
if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });

function dbRead(name) {
  try {
    const file = path.join(DB_DIR, name + '.json');
    if (!fs.existsSync(file)) return null;
    return JSON.parse(fs.readFileSync(file, 'utf-8'));
  } catch(e) { return null; }
}

function dbWrite(name, data) {
  try { fs.writeFileSync(path.join(DB_DIR, name + '.json'), JSON.stringify(data)); return true; }
  catch(e) { console.error('Write error:', e.message); return false; }
}

// ============ ROLE PERMISSIONS ============
// What each role can do
const ROLE_PERMISSIONS = {
  admin:      { canRead: true,  canWrite: true,  canApprove: true,  canManageUsers: true  },
  supervisor: { canRead: true,  canWrite: true,  canApprove: true,  canManageUsers: false },
  foreman:    { canRead: true,  canWrite: true,  canApprove: false, canManageUsers: false },
  viewer:     { canRead: true,  canWrite: false, canApprove: false, canManageUsers: false }
};

// What each role can write to
const WRITE_PERMISSIONS = {
  admin: 'all',
  supervisor: ['dailyReports','taskCompletions','issues','weeklyPlans','monthlyReports',
               'ganttTasks','dailyTargets','workItems','equipment','team','sicknessLog',
               'serviceMachines','serviceLog','attendance','customActivities','folders','files'],
  foreman: ['dailyReports','taskCompletions','issues','serviceLog','attendance'],
  viewer: [] // read only
};

// ============ INIT USERS ============
let users = dbRead('users') || [];
let projectData = dbRead('projectData') || {};
let lastUpdate = Date.now();

if (users.length === 0) {
  const adminEmail = (process.env.ADMIN_EMAIL || 'admin@dashboard.com').toLowerCase().trim();
  const adminPassword = process.env.ADMIN_PASSWORD || 'Admin2024!';
  users.push({
    id: Date.now(), name: 'Administrator',
    email: adminEmail, password: bcrypt.hashSync(adminPassword, 10),
    role: 'admin', created_at: new Date().toISOString()
  });
  dbWrite('users', users);
  console.log('============================');
  console.log('Admin created:', adminEmail);
  console.log('Password:', adminPassword);
  console.log('============================');
}

// ============ MIDDLEWARE ============
app.use(compression());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'road-dashboard-2024',
  resave: false, saveUninitialized: false,
  cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));

function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });
  if (req.session.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
}

// ============ AUTH ============
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const user = users.find(u => u.email === email.toLowerCase().trim());
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: 'Invalid email or password' });
  req.session.user = { id: user.id, name: user.name, email: user.email, role: user.role };
  res.json({ success: true, user: req.session.user });
});

app.post('/api/logout', (req, res) => { req.session.destroy(); res.json({ success: true }); });

app.get('/api/me', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });
  res.json(req.session.user);
});

// ============ USER MANAGEMENT (Admin only) ============
app.get('/api/users', requireAdmin, (req, res) => {
  res.json(users.map(u => ({ id: u.id, name: u.name, email: u.email, role: u.role, created_at: u.created_at })));
});

app.post('/api/users', requireAdmin, (req, res) => {
  const { name, email, password, role } = req.body;
  if (!name || !email || !password || !role) return res.status(400).json({ error: 'All fields required' });
  if (!ROLE_PERMISSIONS[role]) return res.status(400).json({ error: 'Invalid role. Use: admin, supervisor, foreman, or viewer' });
  const emailLower = email.toLowerCase().trim();
  if (users.find(u => u.email === emailLower)) return res.status(400).json({ error: 'Email already exists' });
  const newUser = { id: Date.now(), name, email: emailLower, password: bcrypt.hashSync(password, 10), role, created_at: new Date().toISOString() };
  users.push(newUser);
  dbWrite('users', users);
  res.json({ success: true, id: newUser.id });
});

app.put('/api/users/:id', requireAdmin, (req, res) => {
  const { name, email, role, password } = req.body;
  const idx = users.findIndex(u => u.id == req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'User not found' });
  if (role && !ROLE_PERMISSIONS[role]) return res.status(400).json({ error: 'Invalid role' });
  users[idx] = { ...users[idx], name, email: email.toLowerCase().trim(), role };
  if (password) users[idx].password = bcrypt.hashSync(password, 10);
  dbWrite('users', users);
  res.json({ success: true });
});

app.delete('/api/users/:id', requireAdmin, (req, res) => {
  if (String(req.session.user.id) === String(req.params.id))
    return res.status(400).json({ error: 'Cannot delete yourself' });
  users = users.filter(u => String(u.id) !== String(req.params.id));
  dbWrite('users', users);
  res.json({ success: true });
});

app.post('/api/change-password', requireAuth, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const user = users.find(u => u.id === req.session.user.id);
  if (!user || !bcrypt.compareSync(currentPassword, user.password))
    return res.status(400).json({ error: 'Current password is wrong' });
  user.password = bcrypt.hashSync(newPassword, 10);
  dbWrite('users', users);
  res.json({ success: true });
});

// ============ DATA ============
app.get('/api/data', requireAuth, (req, res) => {
  projectData = dbRead('projectData') || {};
  res.json(projectData);
});

app.get('/api/data/:key', requireAuth, (req, res) => {
  projectData = dbRead('projectData') || {};
  res.json(projectData[req.params.key] ?? null);
});

app.post('/api/data/:key', requireAuth, (req, res) => {
  const { value } = req.body;
  const key = req.params.key;
  const role = req.session.user.role;

  // Block viewers entirely
  if (role === 'viewer') return res.status(403).json({ error: 'Your account is view-only. Contact admin to make changes.' });

  // Check role write permissions
  const allowed = WRITE_PERMISSIONS[role];
  if (allowed !== 'all' && !allowed.includes(key))
    return res.status(403).json({ error: `Your role (${role}) cannot edit "${key}". Contact admin.` });

  projectData = dbRead('projectData') || {};
  projectData[key] = value;
  projectData['_lastUpdated'] = Date.now();
  projectData['_lastUpdatedBy'] = req.session.user.email;
  dbWrite('projectData', projectData);
  lastUpdate = Date.now();
  res.json({ success: true });
});

// ============ BULK IMPORT (RESTORE) ============
app.post('/api/import', requireAdmin, (req, res) => {
  const data = req.body;
  // Accept ALL keys from the backup — future-proof
  const ALL_DATA_KEYS = [
    'projectInfo','dailyReports','weeklyPlans','monthlyReports','workItems',
    'equipment','issues','ganttTasks','taskCompletions','files','folders',
    'customActivities','team','sicknessLog','dailyTargets','serviceMachines',
    'serviceLog','attendance'
  ];
  projectData = dbRead('projectData') || {};
  let imported = 0;
  ALL_DATA_KEYS.forEach(k => {
    if (data[k] !== undefined) { projectData[k] = data[k]; imported++; }
  });
  // Also import any EXTRA keys from newer backups
  Object.keys(data).forEach(k => {
    if (!k.startsWith('_') && k !== 'exportDate' && !ALL_DATA_KEYS.includes(k)) {
      projectData[k] = data[k]; imported++;
    }
  });
  projectData['_lastUpdated'] = Date.now();
  dbWrite('projectData', projectData);
  lastUpdate = Date.now();
  res.json({ success: true, imported });
});

// ============ EXPORT ============
app.get('/api/export', requireAuth, (req, res) => {
  const data = { ...(dbRead('projectData') || {}), exportDate: new Date().toISOString() };
  delete data['_lastUpdated']; delete data['_lastUpdatedBy'];
  res.setHeader('Content-Disposition', `attachment; filename="project-backup-${new Date().toISOString().split('T')[0]}.json"`);
  res.json(data);
});

// ============ POLLING (real-time updates) ============
app.get('/api/poll', requireAuth, (req, res) => {
  const since = parseInt(req.query.since) || 0;
  let ts = lastUpdate;
  try { ts = fs.statSync(path.join(DB_DIR, 'projectData.json')).mtimeMs; } catch(e) {}
  res.json({ hasUpdate: ts > since, timestamp: ts });
});

// ============ HEALTH CHECK ============
app.get('/health', (req, res) => res.json({ status: 'OK', users: users.length, port: PORT }));

// ============ SERVE FRONTEND ============
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, '0.0.0.0', () => {
  console.log('Road Construction Dashboard running on port', PORT);
  console.log('Users:', users.length, '| Data keys:', Object.keys(projectData).length);
});
