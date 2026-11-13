import { Router } from 'express';
import { db, publicUser } from '../store.js';
import { authenticate, authorize } from '../middleware.js';
import { ROLES } from '../config.js';

const router = Router();
router.use(authenticate);

// Moderators and admins can view users
router.get('/users', authorize('admin', 'moderator'), (_req, res) => {
  res.json({ users: db.listUsers().map(publicUser) });
});

// Only admins can change roles
router.patch('/users/:id/role', authorize('admin'), (req, res) => {
  const { role } = req.body || {};
  if (!ROLES.includes(role)) return res.status(400).json({ error: `Role must be one of: ${ROLES.join(', ')}` });
  const user = db.findById(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (user.id === req.auth.userId) return res.status(400).json({ error: 'You cannot change your own role' });

  user.role = role;
  db.revokeAllForUser(user.id); // force re-login so new role takes effect on refresh
  res.json({ user: publicUser(user) });
});

export default router;
