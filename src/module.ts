import { DynamicModule, Global, MiddlewareConsumer, Module, NestModule, Provider, Type } from '@nestjs/common';
import { APP_INTERCEPTOR, ModuleRef } from '@nestjs/core';
import passport from 'passport';

import { ENCRYPTOR, MODULE_OPTIONS_TOKEN, MODULE_PROVIDER_REGISTER, MODULE_TRANSPORTS_REGISTER } from './constants';
import { AuthContextInterceptor } from './context/interceptor';
import { AuthContextService } from './context/service';
import { Encryptor } from './encryptor';
import { IEncryptor } from './interfaces/encrypt';
import { IAuthModuleAsyncOptions, IAuthModuleOptions } from './interfaces/options';
import { IAuthProvider } from './interfaces/provider';
import { AuthService } from './service';
import { EmailPasswordStrategy } from './strategies/emailpassword';
import { JwtStrategy } from './strategies/jwt';
import { AuthTransports } from './transports/registry';
import { UserSerializer } from './user.serializer';

const isClass = (value: unknown): value is Type<any> => typeof value === 'function';

/**
 * The authentication module (global).
 *
 * - `forRoot()` / `forRootAsync()`: configures the module once, in the root module
 * - `registerAuthProviders()`: registers the auth providers (one per namespace)
 *
 * It provides the {@link AuthService}, the {@link AuthContextService}, the {@link ENCRYPTOR} (and the default
 * {@link Encryptor}), the passport strategies (`emailpassword`, and `jwt` when configured) and the session serializer,
 * registers the global {@link AuthContextInterceptor}, and applies `passport.initialize()` to all the http routes.
 */
@Global()
@Module({})
export class AuthModule implements NestModule {
    configure(consumer: MiddlewareConsumer): void {
        consumer.apply(passport.initialize()).forRoutes('*');
    }

    protected static createOptionsProvider(options: IAuthModuleOptions): Provider<IAuthModuleOptions> {
        return {
            provide: MODULE_OPTIONS_TOKEN,
            useValue: options
        };
    }

    protected static createAsyncOptionsProvider(options: IAuthModuleAsyncOptions): Provider<IAuthModuleOptions> {
        return {
            provide: MODULE_OPTIONS_TOKEN,
            useFactory: options.useFactory,
            inject: options.inject ?? []
        };
    }

    protected static createAuthServiceProvider(): Provider<AuthService> {
        return {
            provide: AuthService,
            useClass: AuthService
        };
    }

    /** The default implementation, when the `encrypt` option is set. */
    protected static createEncryptorProvider(): Provider<Encryptor | undefined> {
        return {
            provide: Encryptor,
            inject: [MODULE_OPTIONS_TOKEN],
            useFactory: (options: IAuthModuleOptions) =>
                options.encrypt !== undefined ? new Encryptor(options.encrypt) : undefined
        };
    }

    /**
     * The {@link ENCRYPTOR}: the `encryptor` option, else the default {@link Encryptor}.
     * With `forRoot()`, an `encryptor` class is a regular class provider.
     */
    protected static createEncryptorTokenProvider(options?: IAuthModuleOptions): Provider<IEncryptor | undefined> {
        if (options !== undefined && isClass(options.encryptor)) {
            return { provide: ENCRYPTOR, useClass: options.encryptor };
        }
        return {
            provide: ENCRYPTOR,
            inject: [MODULE_OPTIONS_TOKEN, Encryptor, ModuleRef],
            useFactory: async (opts: IAuthModuleOptions, encryptor: Encryptor | undefined, moduleRef: ModuleRef) => {
                if (isClass(opts.encryptor)) {
                    return await moduleRef.create(opts.encryptor);
                }
                return opts.encryptor ?? encryptor;
            }
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

    /** Registers the `transports` option in {@link AuthTransports}. */
    protected static createTransportsProvider(): Provider {
        return {
            provide: MODULE_TRANSPORTS_REGISTER,
            inject: [MODULE_OPTIONS_TOKEN],
            useFactory: (options: IAuthModuleOptions) => {
                AuthTransports.register(...(options.transports ?? []));
                return true;
            }
        };
    }

    static createModule(
        optionsProvider: Provider,
        imports: IAuthModuleAsyncOptions['imports'] = [],
        options?: IAuthModuleOptions
    ): DynamicModule {
        const providers = [
            optionsProvider,
            this.createEncryptorProvider(),
            this.createEncryptorTokenProvider(options),
            this.createAuthServiceProvider(),
            this.createLocalEmailPasswordStrategyProvider(),
            this.createJWTStrategyProvider(),
            this.createTransportsProvider(),
            AuthContextService,
            UserSerializer
        ];
        return {
            module: AuthModule,
            imports,
            providers: [...providers, { provide: APP_INTERCEPTOR, useClass: AuthContextInterceptor }],
            exports: providers
        };
    }

    /** Configures the module with static options. */
    static forRoot(options: IAuthModuleOptions): DynamicModule {
        return this.createModule(this.createOptionsProvider(options), [], options);
    }

    /** Configures the module with options returned by a factory (e.g. read from a `ConfigService`). */
    static forRootAsync(options: IAuthModuleAsyncOptions): DynamicModule {
        return this.createModule(this.createAsyncOptionsProvider(options), options.imports ?? []);
    }

    /**
     * Provides auth providers ({@link IAuthProvider}) and registers them in the {@link AuthService}.
     * Each one handles the users of its namespace (`getName()`).
     *
     * @param providers class, value, factory or existing providers that resolve to an {@link IAuthProvider}
     */
    static registerAuthProviders(providers: Provider<IAuthProvider<any, any>>[]): DynamicModule {
        const providerRegister: Provider = {
            provide: MODULE_PROVIDER_REGISTER,
            inject: [AuthService, ...providers.map((p) => (typeof p === 'function' ? p : p.provide))],
            useFactory: (authService: AuthService, ...instances: IAuthProvider<any, any>[]) => {
                for (const instance of instances) {
                    authService.registerAuthProvider(instance);
                }
                return authService;
            }
        };
        return {
            module: AuthModule,
            providers: [...providers, providerRegister],
            exports: providers
        };
    }
}
