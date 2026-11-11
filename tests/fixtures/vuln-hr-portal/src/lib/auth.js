// AI-Security-Audit-Skills test fixture | Vijaya Kumar L (Rise With VJ) | github.com/risewithvj | MIT
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'secret';

function requireLogin(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    return next();
  } catch (e) {
    return res.status(401).json({ error: 'login required' });
  }
}

module.exports = { requireLogin, JWT_SECRET };

// Negative case for aisa.js.jwt-fallback-secret: an empty-string fallback fails
// closed (no secret to forge) and must NOT be flagged. Kept at the end of the
// file so the line numbers cited by the fixture findings stay stable.
const SESSION_SECRET = process.env.SESSION_SECRET || '';
module.exports.SESSION_SECRET = SESSION_SECRET;
