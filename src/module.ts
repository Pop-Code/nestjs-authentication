import { Global, Module, NestModule, MiddlewareConsumer, DynamicModule } from '@nestjs/common';
import { ConsoleModule } from 'nestjs-console';
import { AuthService } from './service';
import { LocalStrategy } from './strategies/local';
import { UserSerializer } from './user.serializer';
import passport from 'passport';
import { IEncryptOptions } from './interfaces/encrypt';
import { IAuthModuleOptions, IAuthModuleAsyncOptions } from './interfaces/options';

@Global()
@Module({})
export class AuthModule implements NestModule {
    configure(consumer: MiddlewareConsumer) {
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
