import { Injectable, Inject, Optional, UnauthorizedException } from '@nestjs/common';
import { AuthUserRepository } from './interfaces/auth-user-repository.interface';
import { HashService } from './services/hash.service';
import { TokenService, TokenPair } from './services/token.service';
import { AUTH_USER_REPOSITORY, AUTH_EVENT_EMITTER } from './constants';
import { LoginEvent } from './events/login.event';
import { LogoutEvent } from './events/logout.event';
import { LoginFailedEvent } from './events/login-failed.event';

interface EventEmitter {
  emit(event: string, payload: unknown): void;
}

@Injectable()
export class AuthService {
  constructor(
    @Inject(AUTH_USER_REPOSITORY)
    private readonly userRepository: AuthUserRepository,
    private readonly hashService: HashService,
    private readonly tokenService: TokenService,
    @Optional()
    @Inject(AUTH_EVENT_EMITTER)
    private readonly eventEmitter?: EventEmitter,
  ) {}

  async login(email: string, password: string): Promise<TokenPair> {
    const user = await this.userRepository.findByEmail(email);

    if (!user) {
      this.emitEvent('auth.login.failed', new LoginFailedEvent(email, 'user_not_found'));
      throw new UnauthorizedException('Invalid credentials');
    }

    const isPasswordValid = await this.hashService.compare(
      password,
      user.passwordHash,
    );

    if (!isPasswordValid) {
      this.emitEvent('auth.login.failed', new LoginFailedEvent(email, 'invalid_password'));
      throw new UnauthorizedException('Invalid credentials');
    }

    const tokens = await this.tokenService.generateTokenPair({
      sub: user.id,
      email: user.email,
    });

    const refreshHash = await this.tokenService.hashRefreshToken(
      tokens.refreshToken,
    );
    await this.userRepository.updateRefreshTokenHash(user.id, refreshHash);

    this.emitEvent('auth.login', new LoginEvent(user.id, user.email));

    return tokens;
  }

  async refresh(refreshToken: string): Promise<TokenPair> {
    const payload = await this.tokenService
      .decodeToken(refreshToken)
      .catch(() => {
        throw new UnauthorizedException('Invalid refresh token');
      });

    const user = await this.userRepository.findById(payload.sub);

    if (!user?.refreshTokenHash) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    const isValid = await this.tokenService.verifyRefreshToken(
      refreshToken,
      user.refreshTokenHash,
    );

    if (!isValid) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    const tokens = await this.tokenService.generateTokenPair({
      sub: user.id,
      email: user.email,
    });

    const newHash = await this.tokenService.hashRefreshToken(
      tokens.refreshToken,
    );
    await this.userRepository.updateRefreshTokenHash(user.id, newHash);

    return tokens;
  }

  async logout(userId: string): Promise<void> {
    await this.userRepository.updateRefreshTokenHash(userId, null);
    this.emitEvent('auth.logout', new LogoutEvent(userId));
  }

  private emitEvent(event: string, payload: unknown): void {
    this.eventEmitter?.emit(event, payload);
  }
}
