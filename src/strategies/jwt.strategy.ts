import { Injectable, Inject } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { AuthModuleOptions } from '../interfaces/auth-options.interface';
import { UserIdentity } from '../interfaces/user-identity.interface';
import { MODULE_OPTIONS_TOKEN } from '../auth.module-definition';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    @Inject(MODULE_OPTIONS_TOKEN) options: AuthModuleOptions,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: options.jwt.secret,
    });
  }

  validate(payload: UserIdentity): UserIdentity {
    return payload;
  }
}
