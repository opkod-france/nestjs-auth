export interface UserIdentity {
  sub: string;
  email?: string;
  [key: string]: unknown;
}

export interface AuthUserRecord {
  id: string;
  email: string;
  passwordHash: string;
  refreshTokenHash?: string | null;
}
