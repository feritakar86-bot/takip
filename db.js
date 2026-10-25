const { Pool } = require('pg');
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});
async function init() {
  await pool.query(`CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('parent','child')),
    name TEXT, created_at TIMESTAMP DEFAULT NOW())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS locations (
    id SERIAL PRIMARY KEY, user_id INT REFERENCES users(id),
    lat DOUBLE PRECISION, lng DOUBLE PRECISION,
    accuracy REAL, speed REAL, captured_at BIGINT,
    created_at TIMESTAMP DEFAULT NOW())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS audio_files (
    id SERIAL PRIMARY KEY, user_id INT REFERENCES users(id),
    r2_key TEXT NOT NULL, duration_sec INT,
    recorded_at TIMESTAMP DEFAULT NOW())`);
  console.log('DB hazir');
}
module.exports = { pool, init };
