import { DynamicModule, Global, Module, ModuleMetadata, Provider, Type } from '@nestjs/common';
import { APP_GUARD, APP_INTERCEPTOR, DiscoveryModule, ModuleRef } from '@nestjs/core';

import {
    ENCRYPTOR,
    MODULE_OPTIONS_TOKEN,
    MODULE_PROVIDER_REGISTER,
    MODULE_STRATEGY_REGISTER,
    MODULE_TRANSPORTS_REGISTER
} from './constants';
import { AuthContextInterceptor } from './context/interceptor';
import { AuthContextService } from './context/service';
import { Encryptor } from './encryptor';
import { AuthGuard } from './guard';
import { IEncryptor } from './interfaces/encrypt';
import { IAuthModuleAsyncOptions, IAuthModuleOptions } from './interfaces/options';
import { IAuthProvider } from './interfaces/provider';
import { AuthScopes } from './scopes/service';
import { AuthService } from './service';
import { EmailPasswordStrategy } from './strategies/emailpassword';
import { AuthStrategy } from './strategies/interfaces';
import { JwtStrategy } from './strategies/jwt';
import { AuthStrategyRegistry } from './strategies/registry';
import { SessionStrategy } from './strategies/session';
import { AuthTransports } from './transports/registry';

const isClass = (value: unknown): value is Type<any> => typeof value === 'function';

/**
 * The authentication module (global).
 *
 * - `forRoot()` / `forRootAsync()`: configures the module once, in the root module
 * - `registerAuthProviders()`: registers the auth providers (one per namespace)
 *
 * - `registerStrategies()`: registers your own strategies ({@link AuthStrategy})
 *
 * It provides the {@link AuthService}, the {@link AuthContextService}, the {@link AuthStrategyRegistry} with the
 * `emailpassword`, `session` and (when configured) `jwt` strategies, the {@link ENCRYPTOR} (and the default
 * {@link Encryptor}) and the {@link AuthScopes}, and registers the global {@link AuthGuard} and {@link AuthContextInterceptor}.
 */
@Global()
@Module({})
export class AuthModule {
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

    /** Registers the built-in strategies in the registry. */
    protected static createStrategiesProvider(): Provider {
        return {
            provide: MODULE_STRATEGY_REGISTER,
            inject: [AuthStrategyRegistry, EmailPasswordStrategy, SessionStrategy, JwtStrategy],
            useFactory: (registry: AuthStrategyRegistry, ...strategies: (AuthStrategy | undefined)[]) => {
                strategies.filter((s) => s !== undefined).forEach((s) => registry.register(s));
                return registry;
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
            AuthStrategyRegistry,
            SessionStrategy,
            this.createStrategiesProvider(),
            AuthContextService,
            AuthScopes
        ];
        return {
            module: AuthModule,
            imports: [DiscoveryModule, ...imports],
            providers: [
                ...providers,
                { provide: APP_GUARD, useClass: AuthGuard },
                { provide: APP_INTERCEPTOR, useClass: AuthContextInterceptor }
            ],
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
     * Provides strategies ({@link AuthStrategy}) and registers them in the {@link AuthStrategyRegistry}, under their
     * name. A strategy with the name of a built-in one (`jwt`, `emailpassword`, `session`) replaces it.
     *
     * @param providers class, value, factory or existing providers that resolve to an {@link AuthStrategy}
     * @param imports the modules that provide the dependencies of the strategies (if they are not global)
     */
    static registerStrategies(
        providers: Provider<AuthStrategy>[],
        imports: ModuleMetadata['imports'] = []
    ): DynamicModule {
        const register: Provider = {
            provide: Symbol(MODULE_STRATEGY_REGISTER),
            inject: [
                AuthStrategyRegistry,
                MODULE_STRATEGY_REGISTER,
                ...providers.map((p) => (typeof p === 'function' ? p : p.provide))
            ],
            useFactory: (registry: AuthStrategyRegistry, _builtIn: unknown, ...strategies: AuthStrategy[]) => {
                strategies.forEach((s) => registry.register(s));
                return registry;
            }
        };
        return {
            module: AuthModule,
            imports,
            providers: [...providers, register],
            exports: providers
        };
    }

    /**
     * Provides auth providers ({@link IAuthProvider}) and registers them in the {@link AuthService}.
     * Each one handles the users of its namespace (`getName()`).
     *
     * @param providers class, value, factory or existing providers that resolve to an {@link IAuthProvider}
     * @param imports the modules that provide the dependencies of the providers (if they are not global),
     * e.g. the module of a `UserRepository`
     */
    static registerAuthProviders(
        providers: Provider<IAuthProvider<any, any>>[],
        imports: ModuleMetadata['imports'] = []
    ): DynamicModule {
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
            imports,
            providers: [...providers, providerRegister],
            exports: providers
        };
    }
}
