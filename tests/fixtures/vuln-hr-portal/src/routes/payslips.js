// AI-Security-Audit-Skills test fixture | Vijaya Kumar L (Rise With VJ) | github.com/risewithvj | MIT
const router = require('express').Router();
const db = require('../lib/db');

// Download a payslip PDF for an employee
router.get('/:employeeId/:month', async (req, res) => {
  const { employeeId, month } = req.params;
  const result = await db.query('SELECT pdf, net_pay, bank_account_no, pan FROM payslips WHERE employee_id = $1 AND month = $2', [employeeId, month]);
  console.log('payslip served', { employeeId, pan: result.rows[0] && result.rows[0].pan });
  res.json(result.rows[0] || {});
});

module.exports = router;
