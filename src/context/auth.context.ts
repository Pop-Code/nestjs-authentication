import { AsyncLocalStorage } from 'async_hooks';

/**
 * The authentication of the current request, operation, connection or message.
 *
 * Set by the {@link AuthGuard} when it authenticates the request. Read it with {@link CurrentAuth} / {@link CurrentUser},
 * the {@link AuthContextService}, or {@link getAuthContext}.
 */
export interface AuthContext<User = any> {
    /** The authenticated user. */
    user: User;
    /** The strategy that authenticated the user, `session` when it was restored from the session. */
    strategy: string;
    /** The namespace of the auth provider that loaded the user, if known. */
    namespace?: string;
    /** The auth info returned by the strategy. */
    info?: unknown;
    /** The transport of the request (`http`, `graphql`, `ws`, `rpc`...). */
    transport: string;
}

/** The key of the {@link AuthContext} on the request. */
export const AUTH_CONTEXT = Symbol.for('nestjs-authentication:context');

interface AuthContextStore {
    auth?: AuthContext;
}

const storage = new AsyncLocalStorage<AuthContextStore>();

/**
 * Returns the {@link AuthContext} of the current async context, or `undefined` if the request is not authenticated.
 *
 * Available in the handlers and everything they call, when the {@link AuthContextInterceptor} is enabled (default).
 */
export function getAuthContext<User = any>(): AuthContext<User> | undefined {
    return storage.getStore()?.auth;
}

/**
 * Runs `fn` with an {@link AuthContext}: {@link getAuthContext} and the {@link AuthContextService} return it.
 * Used by the {@link AuthContextInterceptor}, and useful in tests and jobs (queues, crons) that run as a user.
 */
export function runWithAuthContext<R>(auth: AuthContext | undefined, fn: () => R): R {
    return storage.run({ auth }, fn);
}

/** Returns the {@link AuthContext} stored on a request by the guard. */
export function getRequestAuthContext<User = any>(request: unknown): AuthContext<User> | undefined {
    if (request === undefined || request === null || typeof request !== 'object') {
        return undefined;
    }
    return (request as Record<symbol, AuthContext<User> | undefined>)[AUTH_CONTEXT];
}

/** Stores an {@link AuthContext} on a request (`undefined` removes it). */
export function setRequestAuthContext(request: object, auth: AuthContext | undefined): void {
    (request as Record<symbol, AuthContext | undefined>)[AUTH_CONTEXT] = auth;
}
