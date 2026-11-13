const need = (k) => {
  if (!process.env[k]) throw new Error(`Missing required env var: ${k}`);
  return process.env[k];
};

export const config = {
  port: Number(process.env.PORT || 4000),
  accessSecret: need('JWT_ACCESS_SECRET'),
  refreshSecret: need('JWT_REFRESH_SECRET'),
  accessTtl: process.env.ACCESS_TTL || '15m',
  refreshTtl: process.env.REFRESH_TTL || '7d',
  issuer: 'auth-service',
};

export const ROLES = ['user', 'moderator', 'admin'];
