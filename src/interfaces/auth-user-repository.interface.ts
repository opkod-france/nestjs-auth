import { AuthUserRecord } from './user-identity.interface';

export abstract class AuthUserRepository {
  abstract findByEmail(email: string): Promise<AuthUserRecord | null>;
  abstract findById(id: string): Promise<AuthUserRecord | null>;
  abstract updateRefreshTokenHash(
    userId: string,
    hash: string | null,
  ): Promise<void>;
}
