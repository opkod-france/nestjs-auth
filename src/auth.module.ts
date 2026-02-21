import { Module, type DynamicModule, type Provider } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { ModuleRef } from '@nestjs/core';
import {
  ConfigurableModuleClass,
  MODULE_OPTIONS_TOKEN,
  OPTIONS_TYPE,
  ASYNC_OPTIONS_TYPE,
} from './auth.module-definition';
import { AuthModuleOptions } from './interfaces/auth-options.interface';
import { AuthService } from './auth.service';
import { TokenService } from './services/token.service';
import { HashService, BcryptjsHashService } from './services/hash.service';
import { JwtStrategy } from './strategies/jwt.strategy';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { AUTH_EVENT_EMITTER } from './constants';

const eventEmitterProvider: Provider = {
  provide: AUTH_EVENT_EMITTER,
  useFactory: (moduleRef: ModuleRef) => {
    try {
      return moduleRef.get('EventEmitter2', { strict: false });
    } catch {
      return undefined;
    }
  },
  inject: [ModuleRef],
};

@Module({})
export class AuthModule extends ConfigurableModuleClass {
  static forRoot(options: typeof OPTIONS_TYPE): DynamicModule {
    const base = super.forRoot(options);

    return {
      ...base,
      imports: [
        ...(base.imports ?? []),
        PassportModule,
        JwtModule.register({
          secret: options.jwt.secret,
        }),
      ],
      providers: [
        ...(base.providers ?? []),
        {
          provide: HashService,
          useFactory: () =>
            new BcryptjsHashService(options.hash?.rounds ?? 10),
        },
        TokenService,
        AuthService,
        JwtStrategy,
        JwtAuthGuard,
        eventEmitterProvider,
      ],
      exports: [
        ...(base.exports ?? []),
        AuthService,
        TokenService,
        HashService,
        JwtAuthGuard,
        MODULE_OPTIONS_TOKEN,
      ],
    };
  }

  static forRootAsync(options: typeof ASYNC_OPTIONS_TYPE): DynamicModule {
    const base = super.forRootAsync(options);

    // Extract the options provider from base so we can share it with JwtModule
    const optionsProvider = base.providers?.find(
      (p): p is Provider & { provide: unknown } =>
        typeof p === 'object' &&
        p !== null &&
        'provide' in p &&
        p.provide === MODULE_OPTIONS_TOKEN,
    );

    return {
      ...base,
      imports: [
        ...(base.imports ?? []),
        PassportModule,
        JwtModule.registerAsync({
          useFactory: (authOptions: AuthModuleOptions) => ({
            secret: authOptions.jwt.secret,
          }),
          inject: [MODULE_OPTIONS_TOKEN],
          extraProviders: optionsProvider ? [optionsProvider] : [],
        }),
      ],
      providers: [
        ...(base.providers ?? []),
        {
          provide: HashService,
          useFactory: (authOptions: AuthModuleOptions) =>
            new BcryptjsHashService(authOptions.hash?.rounds ?? 10),
          inject: [MODULE_OPTIONS_TOKEN],
        },
        TokenService,
        AuthService,
        JwtStrategy,
        JwtAuthGuard,
        eventEmitterProvider,
      ],
      exports: [
        ...(base.exports ?? []),
        AuthService,
        TokenService,
        HashService,
        JwtAuthGuard,
        MODULE_OPTIONS_TOKEN,
      ],
    };
  }
}
