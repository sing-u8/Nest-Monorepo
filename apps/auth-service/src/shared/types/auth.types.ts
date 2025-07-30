export enum AuthProvider {
  LOCAL = 'local',
  GOOGLE = 'google',
  APPLE = 'apple',
}

export enum TokenType {
  ACCESS = 'access',
  REFRESH = 'refresh',
}

export interface ClientInfo {
  userAgent?: string;
  ipAddress?: string;
  deviceId?: string;
}