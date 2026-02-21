import { describe, it, expect } from 'vitest';
import { Test } from '@nestjs/testing';
import { Global, Module } from '@nestjs/common';
import { AuthModule } from '../src/auth.module';
import { AuthService } from '../src/auth.service';
import { TokenService } from '../src/services/token.service';
import { HashService } from '../src/services/hash.service';
import { JwtAuthGuard } from '../src/guards/jwt-auth.guard';
import { MockUserRepository } from './fixtures/mock-user-repository';
import { AUTH_USER_REPOSITORY } from '../src/constants';

const TEST_SECRET = 'test-secret-key-for-testing-only';

@Global()
@Module({
  providers: [
    { provide: AUTH_USER_REPOSITORY, useClass: MockUserRepository },
  ],
  exports: [AUTH_USER_REPOSITORY],
})
class MockUserModule {}

describe('AuthModule', () => {
  it('should resolve all providers with forRoot', async () => {
    const module = await Test.createTestingModule({
      imports: [
        MockUserModule,
        AuthModule.forRoot({
          jwt: { secret: TEST_SECRET },
        }),
      ],
    }).compile();

    expect(module.get(AuthService)).toBeDefined();
    expect(module.get(TokenService)).toBeDefined();
    expect(module.get(HashService)).toBeDefined();
    expect(module.get(JwtAuthGuard)).toBeDefined();
  });

  it('should resolve all providers with forRootAsync', async () => {
    const module = await Test.createTestingModule({
      imports: [
        MockUserModule,
        AuthModule.forRootAsync({
          useFactory: () => ({
            jwt: { secret: TEST_SECRET },
          }),
        }),
      ],
    }).compile();

    expect(module.get(AuthService)).toBeDefined();
    expect(module.get(TokenService)).toBeDefined();
    expect(module.get(HashService)).toBeDefined();
    expect(module.get(JwtAuthGuard)).toBeDefined();
  });
});
