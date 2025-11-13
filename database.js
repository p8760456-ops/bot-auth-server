// database.js
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

if (!process.env.DATABASE_URL) {
  console.error('ERROR: DATABASE_URL not set in environment.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function initDB() {
  // Create users table if not exists
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('admin','user')),
      canRunBot BOOLEAN DEFAULT false,
      machine_id TEXT,
      active_token TEXT,
      last_heartbeat TIMESTAMP,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  // Seed admin if missing
  const adminUser = process.env.ADMIN_USER || 'yigewo001';
  const adminPass = process.env.ADMIN_PASS || 'Localhost01@';
  const hashed = bcrypt.hashSync(adminPass, 10);

  const { rows } = await pool.query('SELECT id FROM users WHERE username = $1', [adminUser]);
  if (rows.length === 0) {
    console.log('👑 Creating default admin user...');
    await pool.query(
      `INSERT INTO users (username, password_hash, role, canRunBot)
       VALUES ($1, $2, 'admin', true)`,
      [adminUser, hashed]
    );
  } else {
    console.log('👑 Admin already exists ✔');
  }
}

initDB().catch(err => {
  console.error('Database initialization error:', err);
  process.exit(1);
});

module.exports = pool;
