require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 4000;
const SECRET = process.env.JWT_SECRET || 'dev_secret_key';

// ------------------- Middleware -------------------
app.use(express.json());
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// Debug logger
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// Serve static files (like admin.html)
app.use(express.static(path.join(__dirname, 'public')));

// ------------------- Database Init -------------------
const db = new sqlite3.Database('users.db');

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT,
      role TEXT DEFAULT 'user',
      canRunBot INTEGER DEFAULT 1,
      machineId TEXT
    )
  `);

  const adminUser = process.env.ADMIN_USER || 'admin';
  const adminPass = process.env.ADMIN_PASS || 'Admin@123';

  db.get(`SELECT * FROM users WHERE username = ?`, [adminUser], (err, row) => {
    if (!row) {
      const hash = bcrypt.hashSync(adminPass, 10);
      db.run(
        `INSERT INTO users (username, password, role) VALUES (?, ?, 'admin')`,
        [adminUser, hash]
      );
      console.log(`✅ Seeded admin: ${adminUser} / ${adminPass}`);
    }
  });
});

// ------------------- Auth Routes -------------------
app.post('/api/login', (req, res) => {
  const { username, password, machineId } = req.body;

  db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
    if (err || !user) return res.status(401).json({ error: 'invalid_credentials' });
    if (!bcrypt.compareSync(password, user.password))
      return res.status(401).json({ error: 'invalid_credentials' });

    if (user.role === 'user' && user.machineId && user.machineId !== machineId)
      return res.status(403).json({ error: 'machine_locked' });

    if (user.role === 'user' && !user.machineId)
      db.run(`UPDATE users SET machineId = ? WHERE id = ?`, [machineId, user.id]);

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      SECRET,
      { expiresIn: '7d' }
    );

    res.json({ token, role: user.role, canRunBot: !!user.canRunBot });
  });
});

// ------------------- Middleware for Admin Only -------------------
function authAdmin(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'no_token' });

  try {
    const decoded = jwt.verify(token, SECRET);
    if (decoded.role !== 'admin') return res.status(403).json({ error: 'forbidden' });
    req.user = decoded;
    next();
  } catch (err) {
    console.error('JWT Verify Error:', err.message);
    return res.status(401).json({ error: 'invalid_token' });
  }
}

// ------------------- Admin Routes -------------------

// ✅ Get all users
app.get('/api/users', authAdmin, (req, res) => {
  db.all(`SELECT id, username, role, canRunBot, machineId FROM users`, (err, rows) => {
    if (err) return res.status(500).json({ error: 'db_error' });
    res.json(rows);
  });
});

// ✅ Create user
app.post('/api/users', authAdmin, (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'missing_fields' });

  const hash = bcrypt.hashSync(password, 10);

  db.run(
    `INSERT INTO users (username, password, role, canRunBot) VALUES (?, ?, 'user', 1)`,
    [username, hash],
    function (err) {
      if (err) {
        console.error('❌ DB Error creating user:', err.message);
        if (err.message.includes('UNIQUE constraint'))
          return res.status(400).json({ error: 'duplicate_user' });
        return res.status(500).json({ error: 'db_error', details: err.message });
      }
      res.json({ success: true, id: this.lastID, username });
    }
  );
});

// ✅ Toggle bot access
app.put('/api/users/:id/toggle', authAdmin, (req, res) => {
  const { id } = req.params;
  db.get(`SELECT canRunBot FROM users WHERE id=?`, [id], (err, row) => {
    if (!row) return res.status(404).json({ error: 'user_not_found' });
    const newVal = row.canRunBot ? 0 : 1;
    db.run(`UPDATE users SET canRunBot=? WHERE id=?`, [newVal, id], function (err) {
      if (err) return res.status(500).json({ error: 'db_error' });
      res.json({ id, canRunBot: !!newVal });
    });
  });
});

// ✅ Delete user
app.delete('/api/users/:id', authAdmin, (req, res) => {
  db.run(`DELETE FROM users WHERE id=?`, [req.params.id], function (err) {
    if (err) return res.status(500).json({ error: 'db_error' });
    res.json({ success: true });
  });
});

// ✅ Update admin credentials
app.put('/api/admin/update', authAdmin, (req, res) => {
  const { username, password } = req.body;
  if (!username && !password)
    return res.status(400).json({ error: 'missing_fields' });

  const decoded = req.user;
  const updates = [];
  const params = [];

  if (username) {
    updates.push('username = ?');
    params.push(username);
  }
  if (password) {
    const hash = bcrypt.hashSync(password, 10);
    updates.push('password = ?');
    params.push(hash);
  }

  params.push(decoded.id);
  const query = `UPDATE users SET ${updates.join(', ')} WHERE id = ?`;

  db.run(query, params, function (err) {
    if (err) {
      if (err.message.includes('UNIQUE constraint failed'))
        return res.status(400).json({ error: 'username_exists' });
      return res.status(500).json({ error: 'update_failed', details: err.message });
    }
    res.json({ success: true, updatedFields: updates });
  });
});

// ✅ Promote/Demote user
app.put('/api/users/:id/role', authAdmin, (req, res) => {
  const { id } = req.params;
  const { role } = req.body;

  if (!['admin', 'user'].includes(role))
    return res.status(400).json({ error: 'invalid_role' });

  db.run(`UPDATE users SET role = ? WHERE id = ?`, [role, id], function (err) {
    if (err) return res.status(500).json({ error: 'db_error', details: err.message });
    if (this.changes === 0) return res.status(404).json({ error: 'user_not_found' });
    res.json({ success: true, id, newRole: role });
  });
});

// ------------------- Serve Admin Panel -------------------
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// ------------------- Root Route (Render Health Check) -------------------
app.get('/', (req, res) => {
  res.send('✅ Auth server is running successfully!');
});

// ------------------- Start Server -------------------
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Auth server running at http://127.0.0.1:${PORT}`);
});
