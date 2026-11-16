import { CanActivate, ExecutionContext, Type } from '@nestjs/common';
import passport, { AuthenticateOptions } from 'passport';

import { AuthContext, setRequestAuthContext } from './context/auth.context';
import { AuthExceptionFactory } from './errors';
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
     * The passport strategies to try, in order, with their authenticate options.
     * The first one that authenticates the request wins.
     * Defaults: `authInfo: true`, `session: false` (set `session: true` to store the user in the session).
     */
    strategies: { [strategyName: string]: AuthenticateOptions };
    /**
     * Creates the error thrown when a `required` request is not authenticated. If not set, the guard returns `false`
     * and NestJS throws a 403 Forbidden. Use {@link unauthorized} for a 401.
     */
    exceptionFactory?: AuthExceptionFactory;
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

/**
 * A guard that authenticates the request with one or more passport strategies.
 *
 * Works with http (express, fastify), GraphQL (queries, mutations, subscriptions), websockets (socket.io, ws) and
 * microservices: the {@link AuthTransport} of the context gives the request to passport.
 *
 * On success, the user is set in `request.user`, the auth info of each strategy in `request.authInfo[strategyName]`,
 * and the {@link AuthContext} is available with {@link CurrentUser}, {@link CurrentAuth} and the {@link AuthContextService}.
 *
 * ```ts
 * @UseGuards(new AuthGuard({ strategies: { emailpassword: { session: true } }, required: true }))
 * ```
 */
export class AuthGuard implements CanActivate {
    /**
     * All the scopes declared in the strategies options of the guards (`scope`), to list them in the application.
     */
    static scopes = new Map<string, string>();

    static registerScopes(_scopes: AuthenticateOptions['scope']): void {
        if (_scopes === undefined) {
            return;
        }
        const arrayScopes = Array.isArray(_scopes) ? _scopes : _scopes.split(' ');
        arrayScopes.filter((s) => s !== '').forEach((s) => AuthGuard.scopes.set(s, s));
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

    constructor(protected readonly options: AuthGuardOptions) {
        for (const strategy in this.options.strategies) {
            const options = { ...(this.options.strategies[strategy] ?? {}) };
            options.authInfo = options.authInfo ?? true;
            options.session = options.session ?? false;
            this.options.strategies[strategy] = options;
            AuthGuard.registerScopes(options.scope);
        }
    }

    /** Returns the transport of the context. */
    protected getTransport(context: ExecutionContext): AuthTransport {
        return AuthTransports.get(context, this.options.transports);
    }

    /**
     * Returns the request, response and next function of the context, with its transport.
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

    /** @deprecated use {@link getRequestResponse} */
    getRequestReponse(context: ExecutionContext): AuthGuardRequestResponse {
        return this.getRequestResponse(context);
    }

    /**
     * Adds the passport methods (`logIn()`, `isAuthenticated()`...) to the request if they are missing.
     * `passport.authenticate()` adds them too (passport >= 0.6), this covers a guard without strategy nor session.
     */
    protected initializeRequest(request: AuthRequest, response: any): void {
        if (typeof request.logIn !== 'function' || typeof request.isAuthenticated !== 'function') {
            passport.initialize()(request as any, response, throwError);
        }
    }

    /** Restores the user from the session. Returns `true` if the request is authenticated. */
    async authenticateFromSession(request: AuthRequest, response: any): Promise<boolean> {
        this.initializeRequest(request, response);
        return await new Promise<boolean>((resolve, reject) =>
            passport.session()(request as any, response, (err?: any) => {
                if (err !== undefined && err !== null) {
                    return reject(err);
                }
                resolve(request.isAuthenticated());
            })
        );
    }

    /** Authenticates the request with a strategy. Returns `true` if the strategy authenticated the user. */
    protected async authenticateWithStrategy(
        strategy: string,
        options: AuthenticateOptions,
        { request, response, next }: AuthGuardRequestResponse,
        onSuccess: (info: unknown) => void = () => undefined
    ): Promise<boolean> {
        return await new Promise<boolean>((resolve, reject) => {
            const callback = async (err: any, user: unknown, authInfo: unknown) => {
                try {
                    if (err !== undefined && err !== null) {
                        return reject(err);
                    }
                    if (request.authInfo === undefined || request.authInfo === null) {
                        request.authInfo = {};
                    }
                    request.authInfo[strategy] = authInfo;
                    if (typeof user === 'object' && user !== null) {
                        await this.login(user as Record<string, unknown>, options, request);
                        onSuccess(authInfo);
                        return resolve(true);
                    }
                    resolve(false);
                } catch (e) {
                    reject(e);
                }
            };
            passport.authenticate(strategy, options, callback)(request, response, next);
        });
    }

    /** Stores the {@link AuthContext} on the request. */
    protected setAuthContext(request: AuthRequest, auth: AuthContext): void {
        setRequestAuthContext(request, auth);
    }

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const transport = this.getTransport(context);
        const ctx = this.getRequestResponse(context);
        const { request, response } = ctx;
        this.initializeRequest(request, response);

        if (this.options.fromSession === true && (await this.authenticateFromSession(request, response))) {
            const payload = request.session?.passport?.user;
            this.setAuthContext(request, {
                user: request.user,
                strategy: 'session',
                namespace: typeof payload?.namespace === 'string' ? payload.namespace : undefined,
                transport: transport.name
            });
            return true;
        }

        for (const strategy in this.options.strategies) {
            const authenticated = await this.authenticateWithStrategy(
                strategy,
                this.options.strategies[strategy],
                ctx,
                (info: any) =>
                    this.setAuthContext(request, {
                        user: request.user,
                        strategy,
                        namespace: typeof info?.namespace === 'string' ? info.namespace : undefined,
                        info,
                        transport: transport.name
                    })
            );
            if (authenticated) {
                return true;
            }
        }

        if (this.options.required !== true || request.isAuthenticated()) {
            return true;
        }
        if (this.options.exceptionFactory !== undefined) {
            throw this.options.exceptionFactory(context, transport.name);
        }
        return false;
    }

    /** Logs the user in (`request.logIn()`), and stores it in the session if `options.session` is `true`. */
    async login<U extends Record<string, unknown>>(
        user: U,
        options: AuthenticateOptions,
        request: AuthRequest
    ): Promise<U> {
        return await new Promise<U>((resolve, reject) => {
            request.logIn(user, { ...options, session: options.session ?? false }, (e: any) => {
                if (e !== undefined && e !== null) {
                    return reject(e);
                }
                resolve(user);
            });
        });
    }
}
