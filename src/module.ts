import { DynamicModule, Global, MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { ConsoleModule } from 'nestjs-console';
import * as passport from 'passport';

import { IAuthModuleAsyncOptions, IAuthModuleOptions } from './interfaces/options';
import { AuthService } from './service';
import { LocalStrategy } from './strategies/local';
import { UserSerializer } from './user.serializer';

@Global()
@Module({})
export class AuthModule implements NestModule {
    configure(consumer: MiddlewareConsumer) {
        // TODO handle routes or let user configure this part
        consumer.apply(passport.initialize()).forRoutes('*');
        consumer.apply(passport.session()).forRoutes('*');
    }

    protected static createAuthService(opts: IAuthModuleOptions) {
        return new AuthService(opts.encrypt);
    }

    static register(options: IAuthModuleOptions): DynamicModule {
        const optionsToken = 'AuthModuleOptions';
        const optionsProvider = {
            provide: optionsToken,
            useValue: options
        };
        const authServiceProvider = {
            provide: AuthService,
            useValue: this.createAuthService(options)
        };
        return {
            module: AuthModule,
            imports: [ConsoleModule],
            providers: [optionsProvider, authServiceProvider, UserSerializer, LocalStrategy],
            exports: [authServiceProvider, UserSerializer, LocalStrategy]
        };
    }

    static registerAsync(options: IAuthModuleAsyncOptions): DynamicModule {
        const optionsToken = 'AuthModuleOptions';
        const optionsProvider = {
            provide: optionsToken,
            ...options
        };
        const authServiceProvider = {
            provide: AuthService,
            useFactory: this.createAuthService,
            inject: [optionsToken]
        };
        return {
            module: AuthModule,
            imports: [ConsoleModule],
            providers: [optionsProvider, authServiceProvider, UserSerializer, LocalStrategy],
            exports: [authServiceProvider, UserSerializer, LocalStrategy]
        };
    }
}
