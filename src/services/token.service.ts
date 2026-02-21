import { Injectable, Inject } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { AuthModuleOptions } from '../interfaces/auth-options.interface';
import { UserIdentity } from '../interfaces/user-identity.interface';
import { HashService } from './hash.service';
import { MODULE_OPTIONS_TOKEN } from '../auth.module-definition';

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

@Injectable()
export class TokenService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly hashService: HashService,
    @Inject(MODULE_OPTIONS_TOKEN)
    private readonly options: AuthModuleOptions,
  ) {}

  async generateTokenPair(payload: UserIdentity): Promise<TokenPair> {
    const { sub, email } = payload;
    const jwtPayload = { sub, email };

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(jwtPayload, {
        expiresIn: (this.options.jwt.accessExpiresIn ?? '15m') as number,
      }),
      this.jwtService.signAsync(jwtPayload, {
        expiresIn: (this.options.jwt.refreshExpiresIn ?? '7d') as number,
      }),
    ]);

    return { accessToken, refreshToken };
  }

  async hashRefreshToken(token: string): Promise<string> {
    return this.hashService.hash(token);
  }

  async verifyRefreshToken(
    token: string,
    hashedToken: string,
  ): Promise<boolean> {
    return this.hashService.compare(token, hashedToken);
  }

  async decodeToken(token: string): Promise<UserIdentity> {
    return this.jwtService.verifyAsync<UserIdentity>(token);
  }
}
