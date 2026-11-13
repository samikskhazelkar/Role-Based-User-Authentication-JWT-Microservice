import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import bcrypt from 'bcryptjs';
import { config } from './config.js';
import { db } from './store.js';
import authRoutes from './routes/auth.js';
import adminRoutes from './routes/admin.js';

const app = express();
app.use(helmet());
app.use(express.json({ limit: '10kb' }));

// Strict limiter on credential endpoints to slow brute-force attempts
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: true, legacyHeaders: false });
app.use('/auth/login', authLimiter);
app.use('/auth/register', authLimiter);

app.get('/health', (_req, res) => res.json({ status: 'ok' }));
app.use('/auth', authRoutes);
app.use('/admin', adminRoutes);

app.use((_req, res) => res.status(404).json({ error: 'Not found' }));
app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(err.type === 'entity.parse.failed' ? 400 : 500).json({ error: 'Request failed' });
});

if (process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD) {
  db.createUser({
    email: process.env.ADMIN_EMAIL.toLowerCase(),
    passwordHash: bcrypt.hashSync(process.env.ADMIN_PASSWORD, 12),
    role: 'admin',
  });
  console.log(`Seeded admin: ${process.env.ADMIN_EMAIL}`);
}

app.listen(config.port, () => console.log(`auth-service listening on :${config.port}`));
