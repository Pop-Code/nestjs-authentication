import { InjectionToken, ModuleMetadata, OptionalFactoryDependency, Type } from '@nestjs/common';
import { StrategyOptions } from 'passport-jwt';

import { AuthTransport } from '../transports/interfaces';
import { IEncryptor, IEncryptorOptions } from './encrypt';

/**
 * Options of the {@link JwtStrategy}: the passport-jwt options.
 * `passReqToCallback` is not supported, `validate()` receives the token payload.
 */
export type JwtStrategyOptions = Extract<StrategyOptions, { passReqToCallback?: false }>;

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
    /** Creates the {@link JwtStrategy} provider and registers the `jwt` passport strategy. */
    jwt?: JwtStrategyOptions;
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
