import { describe, it, expect, beforeEach, vi } from 'vitest';
import { Test } from '@nestjs/testing';
import { UnauthorizedException } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { AuthService } from '../src/auth.service';
import { TokenService } from '../src/services/token.service';
import { HashService, BcryptjsHashService } from '../src/services/hash.service';
import { MockUserRepository } from './fixtures/mock-user-repository';
import { AUTH_USER_REPOSITORY, AUTH_EVENT_EMITTER } from '../src/constants';
import { MODULE_OPTIONS_TOKEN } from '../src/auth.module-definition';
import type { AuthModuleOptions } from '../src/interfaces/auth-options.interface';

const TEST_SECRET = 'test-secret-key-for-testing-only';

describe('AuthService', () => {
  let authService: AuthService;
  let mockRepo: MockUserRepository;
  let hashService: BcryptjsHashService;
  let eventEmitter: { emit: ReturnType<typeof vi.fn> };

  const options: AuthModuleOptions = {
    jwt: {
      secret: TEST_SECRET,
      accessExpiresIn: '15m',
      refreshExpiresIn: '7d',
    },
  };

  beforeEach(async () => {
    mockRepo = new MockUserRepository();
    hashService = new BcryptjsHashService(4);
    eventEmitter = { emit: vi.fn() };

    const module = await Test.createTestingModule({
      imports: [JwtModule.register({ secret: TEST_SECRET })],
      providers: [
        AuthService,
        TokenService,
        { provide: HashService, useValue: hashService },
        { provide: AUTH_USER_REPOSITORY, useValue: mockRepo },
        { provide: AUTH_EVENT_EMITTER, useValue: eventEmitter },
        { provide: MODULE_OPTIONS_TOKEN, useValue: options },
      ],
    }).compile();

    authService = module.get(AuthService);
  });

  describe('login', () => {
    it('should return tokens for valid credentials', async () => {
      const passwordHash = await hashService.hash('password123');
      mockRepo.seed({
        id: 'user-1',
        email: 'test@example.com',
        passwordHash,
      });

      const tokens = await authService.login('test@example.com', 'password123');

      expect(tokens.accessToken).toBeDefined();
      expect(tokens.refreshToken).toBeDefined();
      expect(eventEmitter.emit).toHaveBeenCalledWith(
        'auth.login',
        expect.objectContaining({ userId: 'user-1' }),
      );
    });

    it('should throw for unknown email', async () => {
      await expect(
        authService.login('unknown@example.com', 'password'),
      ).rejects.toThrow(UnauthorizedException);

      expect(eventEmitter.emit).toHaveBeenCalledWith(
        'auth.login.failed',
        expect.objectContaining({ reason: 'user_not_found' }),
      );
    });

    it('should throw for wrong password', async () => {
      const passwordHash = await hashService.hash('correct');
      mockRepo.seed({
        id: 'user-1',
        email: 'test@example.com',
        passwordHash,
      });

      await expect(
        authService.login('test@example.com', 'wrong'),
      ).rejects.toThrow(UnauthorizedException);

      expect(eventEmitter.emit).toHaveBeenCalledWith(
        'auth.login.failed',
        expect.objectContaining({ reason: 'invalid_password' }),
      );
    });
  });

  describe('refresh', () => {
    it('should rotate tokens with a valid refresh token', async () => {
      const passwordHash = await hashService.hash('password123');
      mockRepo.seed({
        id: 'user-1',
        email: 'test@example.com',
        passwordHash,
      });

      // Login first to get a valid refresh token
      const initial = await authService.login('test@example.com', 'password123');

      // Wait 1s so JWT iat differs, producing distinct tokens
      await new Promise((r) => setTimeout(r, 1100));

      const newTokens = await authService.refresh(initial.refreshToken);

      expect(newTokens.accessToken).toBeDefined();
      expect(newTokens.refreshToken).toBeDefined();
      expect(newTokens.accessToken).not.toBe(initial.accessToken);
    });

    it('should reject an invalid refresh token', async () => {
      await expect(authService.refresh('garbage')).rejects.toThrow(
        UnauthorizedException,
      );
    });
  });

  describe('logout', () => {
    it('should clear the refresh token hash', async () => {
      const passwordHash = await hashService.hash('password123');
      mockRepo.seed({
        id: 'user-1',
        email: 'test@example.com',
        passwordHash,
      });

      await authService.login('test@example.com', 'password123');
      await authService.logout('user-1');

      const user = await mockRepo.findById('user-1');
      expect(user?.refreshTokenHash).toBeNull();
      expect(eventEmitter.emit).toHaveBeenCalledWith(
        'auth.logout',
        expect.objectContaining({ userId: 'user-1' }),
      );
    });
  });
});
