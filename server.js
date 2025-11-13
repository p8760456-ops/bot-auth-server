// server.js
require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const path = require('path');

const db = require('./database'); // pool
const app = express();

const PORT = process.env.PORT || 4000;
const SECRET = process.env.JWT_SECRET || 'dev_secret_key';

app.use(express.json());
app.use(cors({
  origin: '*',
  methods: ['GET','POST','PUT','DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Simple request logger
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// Serve admin static (if you have admin UI in ./public)
app.use(express.static(path.join(__dirname, 'public')));

// ------------------- Auth: Login -------------------
app.post('/api/login', async (req, res) => {
  const { username, password, machineId } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'missing_fields' });

  try {
    const result = await db.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'invalid_credentials' });

    const user = result.rows[0];

    if (!bcrypt.compareSync(password, user.password_hash)) {
      return res.status(401).json({ error: 'invalid_credentials' });
    }

    // Machine lock: if user already bound to a different machine
    if (user.role === 'user' && user.machine_id && user.machine_id !== machineId) {
      return res.status(403).json({ error: 'machine_locked' });
    }

    // Bind machine id for user first time
    if (user.role === 'user' && !user.machine_id && machineId) {
      await db.query('UPDATE users SET machine_id = $1 WHERE id = $2', [machineId, user.id]);
    }

    // Sign JWT
    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, SECRET, { expiresIn: '7d' });

    res.json({ token, role: user.role, canRunBot: !!user.canrunbot });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'server_error' });
  }
});

// ------------------- Admin middleware -------------------
function authAdmin(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'no_token' });
  const token = header.split(' ')[1];
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

// Get all users
app.get('/api/users', authAdmin, async (req, res) => {
  try {
    const result = await db.query('SELECT id, username, role, canRunBot, machine_id FROM users ORDER BY id DESC');
    res.json(result.rows);
  } catch (err) {
    console.error('Get users error:', err);
    res.status(500).json({ error: 'db_error' });
  }
});

// Create user
app.post('/api/users', authAdmin, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'missing_fields' });

  try {
    const hash = bcrypt.hashSync(password, 10);
    const result = await db.query(
      `INSERT INTO users (username, password_hash, role, canRunBot)
       VALUES ($1, $2, 'user', true) RETURNING id, username`,
      [username, hash]
    );
    res.json({ success: true, id: result.rows[0].id, username: result.rows[0].username });
  } catch (err) {
    console.error('Create user error:', err.message);
    if (err.message.includes('duplicate key')) return res.status(400).json({ error: 'duplicate_user' });
    res.status(500).json({ error: 'db_error' });
  }
});

// Toggle bot access
app.put('/api/users/:id/toggle', authAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const q = await db.query('SELECT canRunBot FROM users WHERE id=$1', [id]);
    if (q.rows.length === 0) return res.status(404).json({ error: 'user_not_found' });
    const newVal = !q.rows[0].canrunbot;
    await db.query('UPDATE users SET canRunBot=$1 WHERE id=$2', [newVal, id]);
    res.json({ id, canRunBot: !!newVal });
  } catch (err) {
    console.error('Toggle error:', err);
    res.status(500).json({ error: 'db_error' });
  }
});

// Delete user
app.delete('/api/users/:id', authAdmin, async (req, res) => {
  try {
    await db.query('DELETE FROM users WHERE id=$1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    console.error('Delete user error:', err);
    res.status(500).json({ error: 'db_error' });
  }
});

// Update admin credentials
app.put('/api/admin/update', authAdmin, async (req, res) => {
  const { username, password } = req.body;
  try {
    if (username) {
      await db.query('UPDATE users SET username=$1 WHERE role=$2', [username, 'admin']);
    }
    if (password) {
      const hash = bcrypt.hashSync(password, 10);
      await db.query('UPDATE users SET password_hash=$1 WHERE role=$2', [hash, 'admin']);
    }
    res.json({ success: true });
  } catch (err) {
    console.error('Update admin error:', err);
    res.status(500).json({ error: 'db_error' });
  }
});

// Fallback: return index.html for admin UI if single-page app
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
