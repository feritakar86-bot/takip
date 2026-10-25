const jwt = require('jsonwebtoken');
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'token yok' });
  try { req.user = jwt.verify(token, process.env.JWT_SECRET); next(); }
  catch { return res.status(401).json({ error: 'gecersiz token' }); }
}
function requireParent(req, res, next) {
  if (req.user.role !== 'parent')
    return res.status(403).json({ error: 'sadece ebeveyn erisebilir' });
  next();
}
module.exports = { requireAuth, requireParent };
