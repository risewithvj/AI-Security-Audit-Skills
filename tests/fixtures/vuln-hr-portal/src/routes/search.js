// AI-Security-Audit-Skills test fixture | Vijaya Kumar L (Rise With VJ) | github.com/risewithvj | MIT
const router = require('express').Router();
const db = require('../lib/db');

router.get('/', async (req, res) => {
  const q = req.query.q || '';
  const rows = await db.query("SELECT id, name, department FROM employees WHERE org_id = " + req.user.orgId + " AND name LIKE '%" + q + "%'");
  res.json(rows.rows);
});

module.exports = router;
