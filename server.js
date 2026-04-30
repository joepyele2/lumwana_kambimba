const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');
const compression = require('compression');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });

function dbRead(name) {
  try {
    const file = path.join(DB_DIR, name + '.json');
    if (!fs.existsSync(file)) return null;
    return JSON.parse(fs.readFileSync(file, 'utf-8'));
  } catch(e) { return null; }
}

function dbWrite(name, data) {
  try {
    fs.writeFileSync(path.join(DB_DIR, name + '.json'), JSON.stringify(data));
    return true;
  } catch(e) { return false; }
}

let users = dbRead('users') || [];
let lastUpdate = Date.now();

if (users.length === 0) {
  const email = (process.env.ADMIN_EMAIL || 'admin@dashboard.com').toLowerCase().trim();
  const pwd = process.env.ADMIN_PASSWORD || 'Admin2024!';
  users.push({ id: 1, name: 'Admin', email, password: bcrypt.hashSync(pwd, 10), role: 'admin', created_at: new Date().toISOString() });
  dbWrite('users', users);
  console.log('Admin created:', email, '/', pwd);
}

app.use(compression());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({ secret: process.env.SESSION_SECRET || 'secret123', resave: false, saveUninitialized: false, cookie: { secure: false, maxAge: 86400000 } }));

const auth = (req, res, next) => { if (!req.session.user) return res.status(401).json({ error: 'Not logged in' }); next(); };
const admin = (req, res, next) => { if (!req.session.user || req.session.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' }); next(); };

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === (email||'').toLowerCase().trim());
  if (!user || !bcrypt.compareSync(password||'', user.password)) return res.status(401).json({ error: 'Invalid email or password' });
  req.session.user = { id: user.id, name: user.name, email: user.email, role: user.role };
  res.json({ success: true, user: req.session.user });
});

app.post('/api/logout', (req, res) => { req.session.destroy(); res.json({ success: true }); });
app.get('/api/me', (req, res) => { if (!req.session.user) return res.status(401).json({ error: 'Not logged in' }); res.json(req.session.user); });

app.get('/api/users', admin, (req, res) => res.json(users.map(u => ({ id: u.id, name: u.name, email: u.email, role: u.role, created_at: u.created_at }))));

app.post('/api/users', admin, (req, res) => {
  const { name, email, password, role } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'All fields required' });
  const emailLower = email.toLowerCase().trim();
  if (users.find(u => u.email === emailLower)) return res.status(400).json({ error: 'Email already exists' });
  const u = { id: Date.now(), name, email: emailLower, password: bcrypt.hashSync(password, 10), role, created_at: new Date().toISOString() };
  users.push(u); dbWrite('users', users);
  res.json({ success: true, id: u.id });
});

app.put('/api/users/:id', admin, (req, res) => {
  const idx = users.findIndex(u => u.id == req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  const { name, email, role, password } = req.body;
  users[idx] = { ...users[idx], name, email: email.toLowerCase().trim(), role };
  if (password) users[idx].password = bcrypt.hashSync(password, 10);
  dbWrite('users', users); res.json({ success: true });
});

app.delete('/api/users/:id', admin, (req, res) => {
  users = users.filter(u => u.id != req.params.id);
  dbWrite('users', users); res.json({ success: true });
});

app.post('/api/change-password', auth, (req, res) => {
  const u = users.find(x => x.id === req.session.user.id);
  if (!u || !bcrypt.compareSync(req.body.currentPassword||'', u.password)) return res.status(400).json({ error: 'Wrong current password' });
  u.password = bcrypt.hashSync(req.body.newPassword, 10);
  dbWrite('users', users); res.json({ success: true });
});

app.get('/api/data', auth, (req, res) => res.json(dbRead('projectData') || {}));

app.post('/api/data/:key', auth, (req, res) => {
  const { value } = req.body; const key = req.params.key;
  const fAllowed = ['dailyReports','taskCompletions','issues'];
  const sAllowed = [...fAllowed,'weeklyPlans','monthlyReports','ganttTasks','dailyTargets'];
  if (req.session.user.role === 'foreman' && !fAllowed.includes(key)) return res.status(403).json({ error: 'Not allowed' });
  if (req.session.user.role === 'supervisor' && !sAllowed.includes(key)) return res.status(403).json({ error: 'Not allowed' });
  const data = dbRead('projectData') || {};
  data[key] = value; data['_ts'] = Date.now();
  dbWrite('projectData', data); lastUpdate = Date.now();
  res.json({ success: true });
});

app.post('/api/import', admin, (req, res) => {
  const allowed = ['projectInfo','dailyReports','weeklyPlans','monthlyReports','workItems','equipment','issues','ganttTasks','taskCompletions','files','folders','customActivities','team','sicknessLog','dailyTargets'];
  const data = dbRead('projectData') || {};
  allowed.forEach(k => { if (req.body[k] !== undefined) data[k] = req.body[k]; });
  data['_ts'] = Date.now(); dbWrite('projectData', data); lastUpdate = Date.now();
  res.json({ success: true });
});

app.get('/api/export', auth, (req, res) => {
  const data = { ...(dbRead('projectData') || {}), exportDate: new Date().toISOString() };
  delete data['_ts'];
  res.setHeader('Content-Disposition', `attachment; filename="backup-${new Date().toISOString().split('T')[0]}.json"`);
  res.json(data);
});

app.get('/api/poll', auth, (req, res) => {
  const since = parseInt(req.query.since) || 0;
  let ts = lastUpdate;
  try { ts = fs.statSync(path.join(DB_DIR,'projectData.json')).mtimeMs; } catch(e) {}
  res.json({ hasUpdate: ts > since, timestamp: ts });
});

app.get('/health', (req, res) => res.json({ status: 'OK', users: users.length, port: PORT }));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, '0.0.0.0', () => console.log('Dashboard running on port', PORT));
