const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const compression = require('compression');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// ============ JSON FILE DATABASE ============
const DB_DIR = process.env.DB_DIR || path.join(__dirname, 'data');
if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });

function dbRead(name) {
  const file = path.join(DB_DIR, name + '.json');
  try {
    if (!fs.existsSync(file)) return null;
    return JSON.parse(fs.readFileSync(file, 'utf-8'));
  } catch (e) { return null; }
}

function dbWrite(name, data) {
  const file = path.join(DB_DIR, name + '.json');
  try { fs.writeFileSync(file, JSON.stringify(data), 'utf-8'); return true; }
  catch (e) { return false; }
}

let users = dbRead('users') || [];
let projectData = dbRead('projectData') || {};
let lastUpdate = Date.now();

if (users.length === 0) {
  const adminEmail = (process.env.ADMIN_EMAIL || 'admin@dashboard.com').toLowerCase().trim();
  const adminPassword = process.env.ADMIN_PASSWORD || 'Admin2024!';
  const hash = bcrypt.hashSync(adminPassword, 10);
  users.push({ id: Date.now(), name: 'Administrator', email: adminEmail, password: hash, role: 'admin', created_at: new Date().toISOString() });
  dbWrite('users', users);
  console.log('Admin created:', adminEmail, '/', adminPassword);
}

app.use(compression());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({ secret: process.env.SESSION_SECRET || 'road-secret-2024', resave: false, saveUninitialized: false, cookie: { secure: false, maxAge: 86400000 } }));

function requireAuth(req, res, next) { if (!req.session.user) return res.status(401).json({ error: 'Not logged in' }); next(); }
function requireAdmin(req, res, next) { if (!req.session.user) return res.status(401).json({ error: 'Not logged in' }); if (req.session.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' }); next(); }

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const user = users.find(u => u.email === email.toLowerCase().trim());
  if (!user || !bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: 'Invalid email or password' });
  req.session.user = { id: user.id, name: user.name, email: user.email, role: user.role };
  res.json({ success: true, user: { name: user.name, email: user.email, role: user.role } });
});

app.post('/api/logout', (req, res) => { req.session.destroy(); res.json({ success: true }); });
app.get('/api/me', (req, res) => { if (!req.session.user) return res.status(401).json({ error: 'Not logged in' }); res.json(req.session.user); });

app.get('/api/users', requireAdmin, (req, res) => { res.json(users.map(u => ({ id: u.id, name: u.name, email: u.email, role: u.role, created_at: u.created_at }))); });

app.post('/api/users', requireAdmin, (req, res) => {
  const { name, email, password, role } = req.body;
  if (!name || !email || !password || !role) return res.status(400).json({ error: 'All fields required' });
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
  users[idx] = { ...users[idx], name, email: email.toLowerCase().trim(), role };
  if (password) users[idx].password = bcrypt.hashSync(password, 10);
  dbWrite('users', users);
  res.json({ success: true });
});

app.delete('/api/users/:id', requireAdmin, (req, res) => {
  users = users.filter(u => u.id != req.params.id);
  dbWrite('users', users);
  res.json({ success: true });
});

app.post('/api/change-password', requireAuth, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const user = users.find(u => u.id === req.session.user.id);
  if (!user || !bcrypt.compareSync(currentPassword, user.password)) return res.status(400).json({ error: 'Current password is wrong' });
  user.password = bcrypt.hashSync(newPassword, 10);
  dbWrite('users', users);
  res.json({ success: true });
});

app.get('/api/data', requireAuth, (req, res) => { projectData = dbRead('projectData') || {}; res.json(projectData); });
app.get('/api/data/:key', requireAuth, (req, res) => { projectData = dbRead('projectData') || {}; res.json(projectData[req.params.key] || null); });

app.post('/api/data/:key', requireAuth, (req, res) => {
  const { value } = req.body;
  const key = req.params.key;
  const foremanAllowed = ['dailyReports', 'taskCompletions', 'issues'];
  const supervisorAllowed = [...foremanAllowed, 'weeklyPlans', 'monthlyReports', 'ganttTasks', 'dailyTargets'];
  if (req.session.user.role === 'foreman' && !foremanAllowed.includes(key)) return res.status(403).json({ error: 'Not allowed' });
  if (req.session.user.role === 'supervisor' && !supervisorAllowed.includes(key)) return res.status(403).json({ error: 'Not allowed' });
  projectData = dbRead('projectData') || {};
  projectData[key] = value;
  projectData['_lastUpdated'] = Date.now();
  dbWrite('projectData', projectData);
  lastUpdate = Date.now();
  res.json({ success: true });
});

app.post('/api/import', requireAdmin, (req, res) => {
  const data = req.body;
  const allowed = ['projectInfo','dailyReports','weeklyPlans','monthlyReports','workItems','equipment','issues','ganttTasks','taskCompletions','files','folders','customActivities','team','sicknessLog','dailyTargets'];
  projectData = dbRead('projectData') || {};
  allowed.forEach(k => { if (data[k] !== undefined) projectData[k] = data[k]; });
  projectData['_lastUpdated'] = Date.now();
  dbWrite('projectData', projectData);
  lastUpdate = Date.now();
  res.json({ success: true });
});

app.get('/api/export', requireAuth, (req, res) => {
  projectData = dbRead('projectData') || {};
  const backup = { ...projectData, exportDate: new Date().toISOString() };
  delete backup['_lastUpdated']; delete backup['_lastUpdatedBy'];
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename="project-backup-${new Date().toISOString().split('T')[0]}.json"`);
  res.json(backup);
});

app.get('/api/poll', requireAuth, (req, res) => {
  const clientTime = parseInt(req.query.since) || 0;
  const file = path.join(DB_DIR, 'projectData.json');
  let fileTime = lastUpdate;
  try { fileTime = fs.statSync(file).mtimeMs; } catch(e) {}
  res.json({ hasUpdate: fileTime > clientTime, timestamp: fileTime });
});

app.get('/health', (req, res) => res.json({ status: 'OK', users: users.length }));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, '0.0.0.0', () => {
  console.log('Road Construction Dashboard running on port', PORT);
  console.log('Users:', users.length);
});
