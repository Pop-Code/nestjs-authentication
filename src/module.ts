import { DynamicModule, Global, MiddlewareConsumer, Module, NestModule, Provider } from '@nestjs/common';
import passport from 'passport';

import { MODULE_OPTIONS_TOKEN, MODULE_PROVIDER_REGISTER } from './constants';
import { Encryptor } from './encryptor';
import { IAuthModuleAsyncOptions, IAuthModuleOptions } from './interfaces/options';
import { AuthService } from './service';
import { EmailPasswordStrategy } from './strategies/emailpassword';
import { JwtStrategy } from './strategies/jwt';
import { UserSerializer } from './user.serializer';

@Global()
@Module({})
export class AuthModule implements NestModule {
    configure(consumer: MiddlewareConsumer): any {
        consumer.apply(passport.initialize()).forRoutes('*');
    }

    protected static createOptionsProvider(options: IAuthModuleOptions): Provider<IAuthModuleOptions> {
        return {
            provide: MODULE_OPTIONS_TOKEN,
            useValue: options
        };
    }
    protected static createAsyncOptionsProvider(
        options: IAuthModuleAsyncOptions
    ): Provider<Promise<IAuthModuleOptions> | IAuthModuleOptions> {
        return {
            provide: MODULE_OPTIONS_TOKEN,
            ...options
        };
    }

    protected static createAuthServiceProvider(): Provider<AuthService> {
        return {
            provide: AuthService,
            useClass: AuthService
        };
    }

    protected static createEncryptorProvider(): Provider<Encryptor | undefined> {
        return {
            provide: Encryptor,
            inject: [MODULE_OPTIONS_TOKEN],
            useFactory: (options: IAuthModuleOptions) =>
                options.encrypt !== undefined ? new Encryptor(options.encrypt) : undefined
        };
    }

    protected static createLocalEmailPasswordStrategyProvider(): Provider<EmailPasswordStrategy> {
        return {
            provide: EmailPasswordStrategy,
            useClass: EmailPasswordStrategy
        };
    }

    protected static createJWTStrategyProvider(): Provider<JwtStrategy | undefined> {
        return {
            provide: JwtStrategy,
            inject: [AuthService, MODULE_OPTIONS_TOKEN],
            useFactory: (authService: AuthService, options: IAuthModuleOptions) =>
                options.jwt !== undefined ? new JwtStrategy(authService, options.jwt) : undefined
        };
    }

    static createModule(optionsProvider: Provider): DynamicModule {
        const encryptorProvider = this.createEncryptorProvider();
        const authServiceProvider = this.createAuthServiceProvider();
        const localEmailPasswordStrategyProvider = this.createLocalEmailPasswordStrategyProvider();
        const jwtStrategyProvider = this.createJWTStrategyProvider();
        return {
            module: AuthModule,
            providers: [
                optionsProvider,
                encryptorProvider,
                authServiceProvider,
                localEmailPasswordStrategyProvider,
                jwtStrategyProvider,
                UserSerializer
            ],
            exports: [
                optionsProvider,
                encryptorProvider,
                authServiceProvider,
                UserSerializer,
                jwtStrategyProvider,
                UserSerializer
            ]
        };
    }

    static forRoot(options: IAuthModuleOptions): DynamicModule {
        return this.createModule(this.createOptionsProvider(options));
    }

    static forRootAsync(options: IAuthModuleAsyncOptions): DynamicModule {
        return this.createModule(this.createAsyncOptionsProvider(options));
    }

    static registerAuthProviders(providers: Provider[]): DynamicModule {
        const providerRegister: Provider = {
            provide: MODULE_PROVIDER_REGISTER,
            inject: [
                AuthService,
                ...providers.map((p) => {
                    if ((p as any).provide !== undefined) {
                        return (p as any).provide;
                    } else {
                        return p;
                    }
                })
            ],
            useFactory: (authService: AuthService, ...instances: any) => {
                for (const p of instances) {
                    authService.registerAuthProvider(p);
                }
            }
        };
        return {
            module: AuthModule,
            providers: [...providers, providerRegister]
        };
    }
}
