import { CanActivate, ExecutionContext, ForbiddenException, Inject, Injectable, Optional, Type } from '@nestjs/common';
import { Reflector } from '@nestjs/core';

import { MODULE_OPTIONS_TOKEN } from './constants';
import { AuthContext, getRequestAuthContext, setRequestAuthContext } from './context/auth.context';
import { AuthExceptionFactory, toTransportException } from './errors';
import { AuthUserPayload } from './interfaces/auth.user';
import { IAuthModuleOptions } from './interfaces/options';
import {
    AUTH_OPTIONS_METADATA,
    AUTH_PUBLIC_METADATA,
    AUTH_SCOPES_METADATA,
    ScopesRequirement
} from './scopes/decorators';
import { hasScopes, normalizeScopes } from './scopes/utils';
import { DEFAULT_SESSION_KEY, sessionLogIn } from './session/manager';
import { decorateRequest } from './session/request';
import { AuthStrategy, AuthStrategyOptions, AuthStrategyResult } from './strategies/interfaces';
import { AuthStrategyRegistry } from './strategies/registry';
import { AuthRequest, AuthTransport } from './transports/interfaces';
import { AuthTransports } from './transports/registry';

/**
 * Options of the {@link AuthGuard}.
 */
export interface AuthGuardOptions {
    /** Authenticates the request from the session first (requires a session middleware such as express-session). */
    fromSession?: boolean;
    /** Rejects the requests that are not authenticated (403, see `exceptionFactory`). If `false`, they go through without a user. */
    required?: boolean;
    /**
     * The strategies to try, in order, with their options: the native ones (`jwt`, `emailpassword`, `session`, yours)
     * and the passport strategies. The first one that authenticates the request wins.
     * `session: true` stores the user in the session (login).
     */
    strategies: { [strategyName: string]: AuthStrategyOptions };
    /**
     * Creates the error thrown when a `required` request is not authenticated. If not set, the guard returns `false`
     * and NestJS throws a 403 Forbidden. Use {@link unauthorized} for a 401.
     */
    exceptionFactory?: AuthExceptionFactory;
    /** Creates the error thrown when the request does not have the required scopes. Default: 403 `Insufficient scope`. */
    scopeExceptionFactory?: AuthExceptionFactory;
    /** Transports tried before the registered and built-in ones, for this guard only. */
    transports?: AuthTransport[];
}

/** The request, response and next function of an execution context. */
export interface AuthGuardRequestResponse {
    request: AuthRequest;
    response: any;
    next: (err?: any) => void;
}

function throwError(err?: any): void {
    if (err !== undefined && err !== null) {
        throw err;
    }
}

/** The default `scopeExceptionFactory`: 403 Insufficient scope, converted for the transport. */
export const insufficientScope: AuthExceptionFactory = (_context, transport) =>
    toTransportException(new ForbiddenException('Insufficient scope'), transport);

/**
 * Authenticates the requests with the strategies, on every transport (http, GraphQL, websockets, microservices),
 * and checks the required scopes.
 *
 * Use it in two ways:
 *
 * - **global** (registered by the {@link AuthModule}): configure the routes with {@link Auth}, {@link Public},
 *   {@link RequireScopes}, and the `defaults` / `globalGuard` options of the module
 * - **per route**: `@UseGuards(new AuthGuard({ strategies: { jwt: {} }, required: true }))`
 *
 * On success, the user is set in `request.user`, the auth info of each strategy in `request.authInfo[strategyName]`,
 * and the {@link AuthContext} is available with {@link CurrentUser}, {@link CurrentAuth} and the {@link AuthContextService}.
 */
@Injectable()
export class AuthGuard implements CanActivate {
    /**
     * The scopes of the strategies options of the guards created with `new AuthGuard()`.
     *
     * @deprecated use the {@link AuthScopes} service, which also lists the scopes of {@link Auth} and {@link RequireScopes}
     */
    static scopes = new Map<string, string>();

    /** @deprecated used to fill {@link AuthGuard.scopes} */
    static registerScopes(_scopes: AuthStrategyOptions['scope']): void {
        normalizeScopes(_scopes).forEach((s) => AuthGuard.scopes.set(s, s));
    }

    /**
     * Returns a guard class with default options, merged with the options of each guard.
     *
     * ```ts
     * export const ApiGuard = AuthGuard.withDefaults({ required: true, exceptionFactory: unauthorized() });
     * @UseGuards(new ApiGuard({ strategies: { jwt: {} } }))
     * ```
     */
    static withDefaults(defaults: Partial<AuthGuardOptions>): Type<AuthGuard> & {
        new (options?: Partial<AuthGuardOptions>): AuthGuard;
    } {
        return class extends AuthGuard {
            constructor(options: Partial<AuthGuardOptions> = {}) {
                super({
                    ...defaults,
                    ...options,
                    strategies: { ...(options.strategies ?? defaults.strategies ?? {}) }
                });
            }
        };
    }

    protected readonly options?: AuthGuardOptions;
    protected readonly reflector: Reflector;

    /**
     * @param options the options of a guard created with `new AuthGuard()`; the global guard has none and reads the
     * metadata and the module options
     */
    constructor(
        @Optional() @Inject('nestjs-authentication:guard.options') options?: AuthGuardOptions,
        @Optional() protected readonly registry?: AuthStrategyRegistry,
        @Optional() reflector?: Reflector,
        @Optional() @Inject(MODULE_OPTIONS_TOKEN) protected readonly moduleOptions?: IAuthModuleOptions
    ) {
        this.reflector = reflector ?? new Reflector();
        if (options !== undefined && options !== null) {
            const strategies: AuthGuardOptions['strategies'] = {};
            for (const name in options.strategies ?? {}) {
                strategies[name] = this.normalizeStrategyOptions(options.strategies[name]);
                AuthGuard.registerScopes(strategies[name].scope);
            }
            options.strategies = strategies;
            this.options = options;
        }
    }

    protected normalizeStrategyOptions(options: AuthStrategyOptions | undefined): AuthStrategyOptions {
        return { authInfo: true, ...(options ?? {}), session: options?.session ?? false };
    }

    /** Returns the transport of the context. */
    protected getTransport(context: ExecutionContext): AuthTransport {
        return AuthTransports.get(context, this.options?.transports);
    }

    /**
     * Returns the request, response and next function of the context.
     *
     * @throws NotImplementedException if no transport supports the context
     */
    getRequestResponse(context: ExecutionContext): AuthGuardRequestResponse {
        const transport = this.getTransport(context);
        return {
            request: transport.getRequest(context),
            response: transport.getResponse?.(context),
            next: transport.getNext?.(context) ?? throwError
        };
    }

    protected getRegistry(): AuthStrategyRegistry {
        const registry = this.registry ?? AuthStrategyRegistry.current;
        if (registry === undefined) {
            throw new Error('AuthGuard: the AuthModule is not initialized (import AuthModule.forRoot())');
        }
        return registry;
    }

    /**
     * Returns the options of the guard for a context: the options of `new AuthGuard()`, or the module `defaults`,
     * overridden by the {@link Auth} metadata of the class, then of the method. `undefined` if the guard does not
     * apply (global guard on a route without metadata, and `globalGuard` is not set).
     */
    protected resolveOptions(context: ExecutionContext): AuthGuardOptions | undefined {
        const handler = context.getHandler?.();
        const type = context.getClass?.();
        const read = <T>(key: string, target: unknown) =>
            target !== undefined && target !== null ? this.reflector.get<T>(key, target as any) : undefined;
        const classAuth = read<Partial<AuthGuardOptions>>(AUTH_OPTIONS_METADATA, type);
        const handlerAuth = read<Partial<AuthGuardOptions>>(AUTH_OPTIONS_METADATA, handler);
        const isPublic =
            (read<boolean>(AUTH_PUBLIC_METADATA, handler) ?? read<boolean>(AUTH_PUBLIC_METADATA, type)) === true;
        const hasMetadata = classAuth !== undefined || handlerAuth !== undefined || isPublic;

        let base: Partial<AuthGuardOptions> | undefined = this.options;
        if (base === undefined) {
            const global = this.getModuleOptions()?.globalGuard === true;
            if (!hasMetadata && !global && this.getScopesRequirements(context).length === 0) {
                return undefined;
            }
            base = this.getModuleOptions()?.defaults ?? {};
        }
        const strategiesSource = handlerAuth?.strategies ?? classAuth?.strategies ?? base.strategies ?? {};
        const strategies: AuthGuardOptions['strategies'] = {};
        for (const name in strategiesSource) {
            strategies[name] = this.normalizeStrategyOptions(strategiesSource[name]);
        }
        const options: AuthGuardOptions = { ...base, ...classAuth, ...handlerAuth, strategies };
        if (isPublic) {
            options.required = false;
        }
        return options;
    }

    /** The module options: injected in the global guard, read from the registry for `new AuthGuard()`. */
    protected getModuleOptions(): IAuthModuleOptions | undefined {
        return this.moduleOptions ?? (this.registry ?? AuthStrategyRegistry.current)?.moduleOptions;
    }

    /** Returns the scopes required by the class and the method. */
    protected getScopesRequirements(context: ExecutionContext): ScopesRequirement[] {
        const targets = [context.getClass?.(), context.getHandler?.()].filter((t) => t !== undefined);
        return targets
            .map((t) => this.reflector.get<ScopesRequirement | undefined>(AUTH_SCOPES_METADATA, t))
            .filter((r): r is ScopesRequirement => r !== undefined);
    }

    /** Restores the user from the session. Returns `true` if the request is authenticated. */
    async authenticateFromSession(request: AuthRequest, response: any, context?: ExecutionContext): Promise<boolean> {
        const result = await this.getRegistry()
            .get('session')
            .authenticate({
                request,
                response,
                transport: context !== undefined ? this.getTransport(context).name : 'http',
                executionContext: context as ExecutionContext,
                options: {}
            });
        if (result === undefined) {
            return false;
        }
        request.user = result.user;
        if (context !== undefined) {
            await this.setAuthContext(request, 'session', result, context);
        }
        return true;
    }

    /** Authenticates the request with a strategy. Returns its result, or `undefined` if it did not authenticate it. */
    protected async authenticateWithStrategy(
        strategy: AuthStrategy,
        options: AuthStrategyOptions,
        { request, response }: AuthGuardRequestResponse,
        context: ExecutionContext
    ): Promise<AuthStrategyResult | undefined> {
        const result = await strategy.authenticate({
            request,
            response,
            transport: this.getTransport(context).name,
            executionContext: context,
            options
        });
        if (request.authInfo === undefined || request.authInfo === null) {
            request.authInfo = {};
        }
        request.authInfo[strategy.name] = result?.info;
        if (
            result === undefined ||
            result.handled === true ||
            typeof result.user !== 'object' ||
            result.user === null
        ) {
            return result?.handled === true ? result : undefined;
        }
        await this.login(result.user, options, request, result.namespace);
        return result;
    }

    /** Stores the {@link AuthContext} on the request, with the scopes of the strategy and of the `scopes` option. */
    protected async setAuthContext(
        request: AuthRequest,
        strategy: string,
        result: AuthStrategyResult,
        context: ExecutionContext
    ): Promise<AuthContext> {
        const auth: AuthContext = {
            user: result.user,
            strategy,
            namespace: result.namespace,
            info: result.info,
            transport: this.getTransport(context).name,
            scopes: normalizeScopes(result.scopes)
        };
        const resolver = this.getModuleOptions()?.scopes;
        if (resolver !== undefined) {
            auth.scopes = normalizeScopes([...(auth.scopes ?? []), ...(await resolver(auth))]);
        }
        setRequestAuthContext(request, auth);
        return auth;
    }

    protected reject(context: ExecutionContext, options: AuthGuardOptions): boolean {
        if (options.exceptionFactory !== undefined) {
            throw options.exceptionFactory(context, this.getTransport(context).name);
        }
        return false;
    }

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const options = this.resolveOptions(context);
        if (options === undefined) {
            return true;
        }
        const ctx = this.getRequestResponse(context);
        const { request, response } = ctx;
        decorateRequest(request, {
            key: this.getModuleOptions()?.sessionKey,
            serialize: (user) => this.serializeUser(user, getRequestAuthContext(request)?.namespace)
        });
        const scopes = this.getScopesRequirements(context);
        const required = options.required === true || scopes.length > 0;

        let authenticated = false;
        if (options.fromSession === true) {
            authenticated = await this.authenticateFromSession(request, response, context);
        }
        for (const name in options.strategies) {
            if (authenticated) {
                break;
            }
            const result = await this.authenticateWithStrategy(
                this.getRegistry().get(name),
                options.strategies[name],
                ctx,
                context
            );
            if (result?.handled === true) {
                // the strategy sent the response (e.g. an OAuth redirect)
                return false;
            }
            if (result !== undefined) {
                await this.setAuthContext(request, name, result, context);
                authenticated = true;
            }
        }

        authenticated = authenticated || request.isAuthenticated();
        if (!authenticated) {
            return required ? this.reject(context, options) : true;
        }
        const granted = getRequestAuthContext(request)?.scopes ?? [];
        if (!scopes.every((requirement) => hasScopes(granted, requirement))) {
            throw (options.scopeExceptionFactory ?? insufficientScope)(context, this.getTransport(context).name);
        }
        return true;
    }

    /** Returns the payload of a user for the session (see {@link AuthService.serializeUser}). */
    protected serializeUser(user: unknown, namespace?: string): AuthUserPayload {
        const authService = this.getRegistry().authService;
        if (authService !== undefined) {
            return authService.serializeUser(user, namespace);
        }
        if (typeof (user as any)?.authSerialize === 'function') {
            return (user as any).authSerialize();
        }
        throw new Error('Cannot store the user in the session: the AuthModule is not initialized');
    }

    /**
     * Logs the user in: sets `request.user`, and stores it in the session if `options.session` is `true`.
     *
     * @param namespace the namespace of the user (from the strategy), to serialize it
     */
    async login<U>(user: U, options: AuthStrategyOptions, request: AuthRequest, namespace?: string): Promise<U> {
        if (options.session === true) {
            await sessionLogIn(request, this.serializeUser(user, namespace), {
                keepSessionInfo: options.keepSessionInfo === true,
                key: this.getModuleOptions()?.sessionKey ?? DEFAULT_SESSION_KEY
            });
        }
        request.user = user;
        return user;
    }
}
