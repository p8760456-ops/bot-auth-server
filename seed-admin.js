// seed-admin.js
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();

const DB_FILE = path.join(__dirname, 'users.db'); // common filename; if yours is different, edit
const ADMIN_USERNAME = process.env.ADMIN_USER || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASS || 'Admin@123';

console.log('Using DB file:', DB_FILE);

const db = new sqlite3.Database(DB_FILE, (err) => {
  if (err) return console.error('DB open error:', err.message);

  // Ensure users table exists - create if missing (uses same schema)
  const createSql = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
  db.exec(createSql, (err2) => {
    if (err2) console.error('Schema exec error (may be okay):', err2.message);

    // Check if admin exists
    db.get('SELECT id FROM users WHERE username = ?', [ADMIN_USERNAME], (err3, row) => {
      if (err3) return console.error('Query error:', err3.message);
      if (row) {
        console.log(`Admin user "${ADMIN_USERNAME}" already exists (id=${row.id}).`);
        return db.close();
      }

      const hash = bcrypt.hashSync(ADMIN_PASSWORD, 10);
      db.run(
        'INSERT INTO users (username, password_hash, role, canRunBot, created_at) VALUES (?, ?, ?, ?, datetime("now"))',
        [ADMIN_USERNAME, hash, 'admin', 1],
        function (err4) {
          if (err4) console.error('Insert error:', err4.message);
          else console.log(`✅ Seeded admin: ${ADMIN_USERNAME} / ${ADMIN_PASSWORD} (id=${this.lastID})`);
          db.close();
        }
      );
    });
  });
});
