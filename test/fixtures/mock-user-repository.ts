import { AuthUserRepository } from '../../src/interfaces/auth-user-repository.interface';
import { AuthUserRecord } from '../../src/interfaces/user-identity.interface';

export class MockUserRepository extends AuthUserRepository {
  private users: Map<string, AuthUserRecord> = new Map();

  seed(user: AuthUserRecord): void {
    this.users.set(user.id, { ...user });
  }

  async findByEmail(email: string): Promise<AuthUserRecord | null> {
    for (const user of this.users.values()) {
      if (user.email === email) return { ...user };
    }
    return null;
  }

  async findById(id: string): Promise<AuthUserRecord | null> {
    const user = this.users.get(id);
    return user ? { ...user } : null;
  }

  async updateRefreshTokenHash(
    userId: string,
    hash: string | null,
  ): Promise<void> {
    const user = this.users.get(userId);
    if (user) {
      user.refreshTokenHash = hash;
    }
  }
}
