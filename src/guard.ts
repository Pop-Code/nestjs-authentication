import { CanActivate, ExecutionContext, NotImplementedException } from '@nestjs/common';
import { Request, Response } from 'express';
import passport, { AuthenticateOptions } from 'passport';

/**
 * Options of the {@link AuthGuard}.
 */
export interface AuthGuardOptions {
    /** Authenticates the request from the session first (requires a session middleware such as express-session). */
    fromSession?: boolean;
    /** Rejects (403) the requests that are not authenticated. If `false`, they go through without a user. */
    required?: boolean;
    /**
     * The passport strategies to try, in order, with their authenticate options.
     * The first one that authenticates the request wins.
     * Defaults: `authInfo: true`, `session: false` (set `session: true` to store the user in the session).
     */
    strategies: { [strategyName: string]: AuthenticateOptions };
}

/** The request, response and next function of an execution context. */
export interface AuthGuardRequestResponse {
    request: Request;
    response: Response;
    next: (err?: any) => void;
}

/**
 * A guard that authenticates the request with one or more passport strategies.
 *
 * The user is set in `request.user`, and the auth info of each strategy in `request.authInfo[strategyName]`.
 * Supports http and graphql (http and websocket) contexts.
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

    constructor(protected readonly options: AuthGuardOptions) {
        for (const strategy in this.options.strategies) {
            const options = this.options.strategies[strategy] ?? {};
            options.authInfo = options.authInfo ?? true;
            options.session = options.session ?? false;
            this.options.strategies[strategy] = options;
            AuthGuard.registerScopes(options.scope);
        }
    }

    /**
     * Returns the request, response and next function of the context.
     * Supports http and graphql (http, websocket) contexts.
     *
     * @throws NotImplementedException for other contexts (rpc, ws)
     */
    getRequestResponse(context: ExecutionContext): AuthGuardRequestResponse {
        if (context.getType() === 'http') {
            const ctx = context.switchToHttp();
            return { request: ctx.getRequest(), response: ctx.getResponse(), next: ctx.getNext() };
        }
        if (context.getType<'graphql'>() === 'graphql') {
            const ctx = context.getArgByIndex(2);
            return {
                request: ctx.req,
                response: ctx.res,
                next: (err?: any) => {
                    if (err !== undefined && err !== null) {
                        throw err;
                    }
                }
            };
        }
        throw new NotImplementedException(`Auth Context ${context.getType()} not implemented`);
    }

    /** @deprecated use {@link getRequestResponse} */
    getRequestReponse(context: ExecutionContext): AuthGuardRequestResponse {
        return this.getRequestResponse(context);
    }

    /** Restores the user from the session. Returns `true` if the request is authenticated. */
    async authenticateFromSession(request: Request, response: Response): Promise<boolean> {
        return await new Promise<boolean>((resolve, reject) =>
            passport.session()(request, response, (err?: any) => {
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
        { request, response, next }: AuthGuardRequestResponse
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
                    (request.authInfo as Record<string, unknown>)[strategy] = authInfo;
                    if (typeof user === 'object' && user !== null) {
                        await this.login(user as Record<string, unknown>, options, request);
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

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const ctx = this.getRequestResponse(context);
        const { request, response } = ctx;

        if (this.options.fromSession === true && (await this.authenticateFromSession(request, response))) {
            return true;
        }

        for (const strategy in this.options.strategies) {
            if (await this.authenticateWithStrategy(strategy, this.options.strategies[strategy], ctx)) {
                return true;
            }
        }

        return this.options.required === true ? request.isAuthenticated() : true;
    }

    /** Logs the user in (`request.logIn()`), and stores it in the session if `options.session` is `true`. */
    async login<U extends Record<string, unknown>>(
        user: U,
        options: AuthenticateOptions,
        request: Request
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
