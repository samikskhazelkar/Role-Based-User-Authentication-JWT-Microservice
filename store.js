import { randomUUID } from 'node:crypto';

const users = new Map();        // id -> user
const emailIndex = new Map();   // email -> id
const refreshTokens = new Map(); // jti -> { userId, family, used }

export const db = {
  createUser({ email, passwordHash, role = 'user' }) {
    const user = { id: randomUUID(), email, passwordHash, role, createdAt: new Date().toISOString() };
    users.set(user.id, user);
    emailIndex.set(email, user.id);
    return user;
  },
  findByEmail: (email) => users.get(emailIndex.get(email)),
  findById: (id) => users.get(id),
  listUsers: () => [...users.values()],

  saveRefresh(jti, data) { refreshTokens.set(jti, { ...data, used: false }); },
  getRefresh: (jti) => refreshTokens.get(jti),
  markRefreshUsed(jti) { const t = refreshTokens.get(jti); if (t) t.used = true; },
  revokeFamily(family) {
    for (const [jti, t] of refreshTokens) if (t.family === family) refreshTokens.delete(jti);
  },
  revokeAllForUser(userId) {
    for (const [jti, t] of refreshTokens) if (t.userId === userId) refreshTokens.delete(jti);
  },
};

export const publicUser = ({ id, email, role, createdAt }) => ({ id, email, role, createdAt });
