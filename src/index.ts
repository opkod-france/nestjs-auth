// Module
export { AuthModule } from './auth.module';
export { MODULE_OPTIONS_TOKEN } from './auth.module-definition';

// Service
export { AuthService } from './auth.service';

// Interfaces
export { AuthModuleOptions } from './interfaces/auth-options.interface';
export {
  UserIdentity,
  AuthUserRecord,
} from './interfaces/user-identity.interface';
export { AuthUserRepository } from './interfaces/auth-user-repository.interface';

// Services
export { HashService, BcryptjsHashService } from './services/hash.service';
export { TokenService, TokenPair } from './services/token.service';

// Guards
export { JwtAuthGuard } from './guards/jwt-auth.guard';

// Decorators
export { Public } from './decorators/public.decorator';
export { CurrentUser } from './decorators/current-user.decorator';

// Events
export { LoginEvent } from './events/login.event';
export { LogoutEvent } from './events/logout.event';
export { LoginFailedEvent } from './events/login-failed.event';

// Constants
export {
  IS_PUBLIC_KEY,
  AUTH_USER_REPOSITORY,
  AUTH_EVENT_EMITTER,
} from './constants';
