# @opkod-france/nestjs-auth

NestJS authentication module with JWT access/refresh tokens, bcryptjs password hashing, and optional event emission.

## Installation

```bash
npm install @opkod-france/nestjs-auth
```

### Peer dependencies

```bash
npm install @nestjs/common @nestjs/core @nestjs/jwt @nestjs/passport passport-jwt rxjs
```

Optional:

```bash
npm install bcryptjs                # required if using the default BcryptjsHashService
npm install @nestjs/event-emitter   # enables auth event emission
```

## Usage

### 1. Implement `AuthUserRepository`

```ts
import { Injectable } from '@nestjs/common';
import { AuthUserRepository, AuthUserRecord } from '@opkod-france/nestjs-auth';

@Injectable()
export class UserRepository extends AuthUserRepository {
  async findByEmail(email: string): Promise<AuthUserRecord | null> { /* ... */ }
  async findById(id: string): Promise<AuthUserRecord | null> { /* ... */ }
  async updateRefreshTokenHash(userId: string, hash: string | null): Promise<void> { /* ... */ }
}
```

### 2. Register the module

```ts
import { Module } from '@nestjs/common';
import { AuthModule, AUTH_USER_REPOSITORY } from '@opkod-france/nestjs-auth';
import { UserRepository } from './user.repository';

@Module({
  imports: [
    AuthModule.forRoot({
      jwt: {
        secret: process.env.JWT_SECRET,
        accessExpiresIn: '15m',
        refreshExpiresIn: '7d',
      },
    }),
  ],
  providers: [
    { provide: AUTH_USER_REPOSITORY, useClass: UserRepository },
  ],
})
export class AppModule {}
```

### 3. Use in controllers

```ts
import { Controller, Post, Body, UseGuards } from '@nestjs/common';
import { AuthService, JwtAuthGuard, CurrentUser, Public, UserIdentity } from '@opkod-france/nestjs-auth';

@UseGuards(JwtAuthGuard)
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Post('login')
  login(@Body() body: { email: string; password: string }) {
    return this.authService.login(body.email, body.password);
  }

  @Public()
  @Post('refresh')
  refresh(@Body() body: { refreshToken: string }) {
    return this.authService.refresh(body.refreshToken);
  }

  @Post('logout')
  logout(@CurrentUser('sub') userId: string) {
    return this.authService.logout(userId);
  }
}
```

## Events

When `@nestjs/event-emitter` is installed and `EventEmitterModule` is registered, the following events are emitted:

| Event | Payload | When |
|-------|---------|------|
| `auth.login` | `LoginEvent { userId, email }` | Successful login |
| `auth.login.failed` | `LoginFailedEvent { email, reason }` | Failed login attempt |
| `auth.logout` | `LogoutEvent { userId }` | User logout |

## Custom HashService

Override the default bcryptjs implementation:

```ts
import { HashService } from '@opkod-france/nestjs-auth';

@Injectable()
export class Argon2HashService extends HashService {
  async hash(data: string) { /* ... */ }
  async compare(data: string, hash: string) { /* ... */ }
}

// In your module:
{ provide: HashService, useClass: Argon2HashService }
```

## License

MIT
