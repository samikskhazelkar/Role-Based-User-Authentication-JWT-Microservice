import { Router } from 'express';
import bcrypt from 'bcryptjs';
import { db, publicUser } from '../store.js';
import { authenticate } from '../middleware.js';
import { signAccessToken, issueRefreshToken, verifyRefreshToken } from '../tokens.js';

const router = Router();
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
// Used to keep login timing similar whether or not the email exists
const DUMMY_HASH = bcrypt.hashSync('dummy-password', 12);

const tokenPair = (user, family) => ({
  accessToken: signAccessToken(user),
  refreshToken: issueRefreshToken(user, family),
});

router.post('/register', async (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const password = String(req.body?.password || '');
  if (!EMAIL_RE.test(email)) return res.status(400).json({ error: 'Invalid email' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  if (db.findByEmail(email)) return res.status(409).json({ error: 'Email already registered' });

  // Role is NEVER taken from the request body: self-registered users are always 'user'.
  const user = db.createUser({ email, passwordHash: await bcrypt.hash(password, 12) });
  res.status(201).json({ user: publicUser(user), ...tokenPair(user) });
});

router.post('/login', async (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const password = String(req.body?.password || '');
  const user = db.findByEmail(email);
  const ok = await bcrypt.compare(password, user?.passwordHash || DUMMY_HASH);
  if (!user || !ok) return res.status(401).json({ error: 'Invalid credentials' });
  res.json({ user: publicUser(user), ...tokenPair(user) });
});

// Refresh-token rotation with reuse detection
router.post('/refresh', (req, res) => {
  let payload;
  try { payload = verifyRefreshToken(String(req.body?.refreshToken || '')); }
  catch { return res.status(401).json({ error: 'Invalid refresh token' }); }

  const record = db.getRefresh(payload.jti);
  if (!record) return res.status(401).json({ error: 'Refresh token revoked' });
  if (record.used) {
    // A rotated token was replayed: assume theft, kill the whole session family.
    db.revokeFamily(record.family);
    return res.status(401).json({ error: 'Refresh token reuse detected; session revoked' });
  }
  const user = db.findById(payload.sub);
  if (!user) return res.status(401).json({ error: 'User no longer exists' });

  db.markRefreshUsed(payload.jti);
  res.json(tokenPair(user, record.family));
});

router.post('/logout', (req, res) => {
  try {
    const payload = verifyRefreshToken(String(req.body?.refreshToken || ''));
    const record = db.getRefresh(payload.jti);
    if (record) db.revokeFamily(record.family);
  } catch { /* already invalid: nothing to revoke */ }
  res.status(204).end();
});

router.get('/me', authenticate, (req, res) => {
  const user = db.findById(req.auth.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ user: publicUser(user) });
});

export default router;
