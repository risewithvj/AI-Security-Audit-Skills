// AI-Security-Audit-Skills test fixture | Vijaya Kumar L (Rise With VJ) | github.com/risewithvj | MIT
const { Pool } = require('pg');
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
module.exports = { query: (text, params) => pool.query(text, params) };
