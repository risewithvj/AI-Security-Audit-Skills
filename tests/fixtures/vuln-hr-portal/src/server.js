// AI-Security-Audit-Skills test fixture | Vijaya Kumar L (Rise With VJ) | github.com/risewithvj | MIT
// Deliberately vulnerable. Never deploy.
const express = require('express');
const payslips = require('./routes/payslips');
const search = require('./routes/search');
const checkout = require('./routes/checkout');
const { requireLogin } = require('./lib/auth');

const app = express();
app.use(express.json());
app.use('/api/payslips', requireLogin, payslips);
app.use('/api/search', requireLogin, search);
app.use('/api/checkout', requireLogin, checkout);

app.listen(process.env.PORT || 3000);
