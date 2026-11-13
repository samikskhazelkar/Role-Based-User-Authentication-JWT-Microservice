import { verifyAccessToken } from './tokens.js';

export function authenticate(req, res, next) {
  const [scheme, token] = (req.headers.authorization || '').split(' ');
  if (scheme !== 'Bearer' || !token) return res.status(401).json({ error: 'Missing bearer token' });
  try {
    const payload = verifyAccessToken(token);
    req.auth = { userId: payload.sub, role: payload.role };
    next();
  } catch (err) {
    const expired = err.name === 'TokenExpiredError';
    res.status(401).json({ error: expired ? 'Token expired' : 'Invalid token' });
  }
}

// Usage: authorize('admin') or authorize('admin', 'moderator')
export const authorize = (...allowed) => (req, res, next) => {
  if (!req.auth) return res.status(401).json({ error: 'Not authenticated' });
  if (!allowed.includes(req.auth.role)) return res.status(403).json({ error: 'Forbidden: insufficient role' });
  next();
};
