import jwt from 'jsonwebtoken';
import { randomUUID } from 'node:crypto';
import { config } from './config.js';
import { db } from './store.js';

const base = { algorithm: 'HS256', issuer: config.issuer };

export function signAccessToken(user) {
  return jwt.sign({ role: user.role }, config.accessSecret, {
    ...base, subject: user.id, expiresIn: config.accessTtl,
  });
}

export function issueRefreshToken(user, family = randomUUID()) {
  const jti = randomUUID();
  const token = jwt.sign({ family }, config.refreshSecret, {
    ...base, subject: user.id, jwtid: jti, expiresIn: config.refreshTtl,
  });
  db.saveRefresh(jti, { userId: user.id, family });
  return token;
}

const verifyOpts = { algorithms: ['HS256'], issuer: config.issuer };
export const verifyAccessToken = (t) => jwt.verify(t, config.accessSecret, verifyOpts);
export const verifyRefreshToken = (t) => jwt.verify(t, config.refreshSecret, verifyOpts);
