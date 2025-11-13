// database.js
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const fs = require('fs');

// Path for persistent storage on Render
const DB_PATH = process.env.NODE_ENV === 'production'
  ? '/data/users.db'       // Render persistent disk
  : 'users.db';            // Local development

console.log('📌 Using SQLite DB at:', DB_PATH);

const db = new sqlite3.Database(DB_PATH);

// Initialize schema + seed admin
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('admin','user')),
      canRunBot INTEGER NOT NULL DEFAULT 0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  const adminUser = 'admin';
  const adminPass = '12345';
  const adminHash = bcrypt.hashSync(adminPass, 10);

  db.get(`SELECT * FROM users WHERE username = ?`, [adminUser], (err, row) => {
    if (err) {
      console.error('DB error:', err);
      return;
    }

    if (!row) {
      console.log('👑 Seeding default admin user...');
      db.run(
        `INSERT INTO users (username, password_hash, role, canRunBot)
         VALUES (?, ?, 'admin', 1)`,
        [adminUser, adminHash],
        (err2) => {
          if (err2) console.error('Admin seed error:', err2);
        }
      );
    } else {
      console.log('👑 Admin already exists ✔');
    }
  });
});

module.exports = db;
