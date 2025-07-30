import { registerAs } from '@nestjs/config';

export default registerAs('auth', () => ({
  jwt: {
    accessTokenSecret: process.env.JWT_ACCESS_SECRET || 'jwt-access-secret',
    refreshTokenSecret: process.env.JWT_REFRESH_SECRET || 'jwt-refresh-secret',
    accessTokenExpiresIn: process.env.JWT_ACCESS_EXPIRES_IN || '15m',
    refreshTokenExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
  },
  bcrypt: {
    saltRounds: parseInt(process.env.BCRYPT_SALT_ROUNDS || '12', 10),
  },
}));