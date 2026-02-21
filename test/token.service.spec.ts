import { describe, it, expect, beforeEach } from 'vitest';
import { Test } from '@nestjs/testing';
import { JwtModule, JwtService } from '@nestjs/jwt';
import { TokenService } from '../src/services/token.service';
import { HashService, BcryptjsHashService } from '../src/services/hash.service';
import { MODULE_OPTIONS_TOKEN } from '../src/auth.module-definition';
import type { AuthModuleOptions } from '../src/interfaces/auth-options.interface';

const TEST_SECRET = 'test-secret-key-for-testing-only';

describe('TokenService', () => {
  let tokenService: TokenService;
  let jwtService: JwtService;

  const options: AuthModuleOptions = {
    jwt: {
      secret: TEST_SECRET,
      accessExpiresIn: '15m',
      refreshExpiresIn: '7d',
    },
  };

  beforeEach(async () => {
    const module = await Test.createTestingModule({
      imports: [JwtModule.register({ secret: TEST_SECRET })],
      providers: [
        TokenService,
        { provide: HashService, useValue: new BcryptjsHashService(4) },
        { provide: MODULE_OPTIONS_TOKEN, useValue: options },
      ],
    }).compile();

    tokenService = module.get(TokenService);
    jwtService = module.get(JwtService);
  });

  it('should generate an access and refresh token pair', async () => {
    const pair = await tokenService.generateTokenPair({
      sub: 'user-1',
      email: 'test@example.com',
    });

    expect(pair.accessToken).toBeDefined();
    expect(pair.refreshToken).toBeDefined();
    expect(pair.accessToken).not.toBe(pair.refreshToken);
  });

  it('should decode a valid token', async () => {
    const pair = await tokenService.generateTokenPair({
      sub: 'user-1',
      email: 'test@example.com',
    });

    const decoded = await tokenService.decodeToken(pair.accessToken);
    expect(decoded.sub).toBe('user-1');
    expect(decoded.email).toBe('test@example.com');
  });

  it('should hash and verify a refresh token', async () => {
    const token = 'some-refresh-token-value';
    const hash = await tokenService.hashRefreshToken(token);
    const isValid = await tokenService.verifyRefreshToken(token, hash);
    expect(isValid).toBe(true);
  });

  it('should reject an invalid refresh token', async () => {
    const hash = await tokenService.hashRefreshToken('real-token');
    const isValid = await tokenService.verifyRefreshToken('wrong-token', hash);
    expect(isValid).toBe(false);
  });
});
