import { InjectionToken, ModuleMetadata, OptionalFactoryDependency, Type } from '@nestjs/common';

import type { AuthContext } from '../context/auth.context';
import type { AuthGuardOptions } from '../guard';
import type { JwtStrategyOptions } from '../strategies/jwt';

import { AuthTransport } from '../transports/interfaces';
import { IEncryptor, IEncryptorOptions } from './encrypt';

/**
 * Options of the {@link AuthModule}.
 */
export interface IAuthModuleOptions {
    /**
     * Options of the default {@link Encryptor} (aes-256-ctr).
     * Provides the `Encryptor` class, and the {@link ENCRYPTOR} token if `encryptor` is not set.
     */
    encrypt?: IEncryptorOptions;
    /**
     * Your own {@link IEncryptor}, provided with the {@link ENCRYPTOR} token: an instance, or a class
     * instantiated by NestJS in the AuthModule. The dependencies of the class are injected: they must be
     * provided by a global module, or by the `imports` of `forRootAsync()`.
     */
    encryptor?: IEncryptor | Type<IEncryptor>;
    /** Creates the {@link JwtStrategy} provider and registers the `jwt` strategy. */
    jwt?: JwtStrategyOptions;
    /**
     * The options of the global guard (the routes with {@link Auth}, {@link Public} or {@link RequireScopes}, or all
     * of them with `globalGuard`), overridden by the {@link Auth} metadata.
     */
    defaults?: Partial<AuthGuardOptions>;
    /** Authenticates all the routes with the global guard and the `defaults` (opt out a route with {@link Public}). Default `false`. */
    globalGuard?: boolean;
    /** The session property that holds the login. Default `passport` (compatible with passport sessions). */
    sessionKey?: string;
    /** Adds scopes to an authenticated request, e.g. from the roles of the user. */
    scopes?: (auth: AuthContext) => string[] | Promise<string[]>;
    /**
     * Your own {@link AuthTransport}s, tried before the built-in ones (http, graphql, ws, rpc) by all the guards
     * and decorators.
     */
    transports?: AuthTransport[];
    /**
     * Registers the global {@link AuthContextInterceptor}, so {@link AuthContextService} and {@link getAuthContext}
     * return the auth context in everything the handlers call. Default `true`.
     */
    context?: boolean;
}

/**
 * Options of `AuthModule.forRootAsync()`.
 */
export interface IAuthModuleAsyncOptions extends Pick<ModuleMetadata, 'imports'> {
    /** Returns the module options. */
    useFactory: (...args: any[]) => Promise<IAuthModuleOptions> | IAuthModuleOptions;
    /** The providers injected in `useFactory`. They must be provided by a global module or one of the `imports`. */
    inject?: (InjectionToken | OptionalFactoryDependency)[];
}

/** Alias of {@link IAuthModuleOptions}. */
export type AuthModuleOptions = IAuthModuleOptions;
/** Alias of {@link IAuthModuleAsyncOptions}. */
export type AuthModuleAsyncOptions = IAuthModuleAsyncOptions;
