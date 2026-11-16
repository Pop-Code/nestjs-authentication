import { ExecutionContext } from '@nestjs/common';

import { AuthRequest } from '../transports/interfaces';

/**
 * The options of a strategy in a guard: `@Auth({ strategies: { jwt: { ... } } })`.
 * Each strategy reads its own options; these ones are handled by the guard.
 */
export interface AuthStrategyOptions {
    /** Stores the user in the session after a successful authentication (login). Default `false`. */
    session?: boolean;
    /** Keeps the data of the session when the user logs in (the session is regenerated). Default `false`. */
    keepSessionInfo?: boolean;
    /** The scopes requested from the provider (OAuth strategies). Listed by {@link AuthScopes}. */
    scope?: string | string[];
    [option: string]: unknown;
}

/** What a strategy receives. */
export interface AuthStrategyContext {
    /** The request of the transport: `headers`, `query`, `body`, `session`. */
    request: AuthRequest;
    /** The response of the transport, if it has one. */
    response?: any;
    /** The name of the transport (`http`, `graphql`, `ws`, `rpc`...). */
    transport: string;
    /** The NestJS execution context. */
    executionContext: ExecutionContext;
    /** The options of the strategy in the guard. */
    options: AuthStrategyOptions;
}

/** A successful authentication. */
export interface AuthStrategyResult<User = any> {
    user: User;
    /** The namespace of the auth provider that loaded the user. */
    namespace?: string;
    /** Info about the authentication (token payload...), set in `request.authInfo[strategy]`. */
    info?: unknown;
    /** The scopes granted to this authentication (e.g. the `scope` claim of a token). */
    scopes?: string[];
    /**
     * `true` if the strategy already sent the response (e.g. an OAuth redirect): the guard stops and the handler
     * is not called.
     */
    handled?: boolean;
}

/**
 * An authentication strategy. Register it with `AuthModule.registerStrategies()`.
 *
 * `authenticate()` returns the result when the credentials are valid, `undefined` when there are none or they are
 * not valid (the next strategy is tried), and throws for the other errors.
 *
 * ```ts
 * @Injectable()
 * export class ApiKeyStrategy implements AuthStrategy<ApiClient> {
 *     readonly name = 'apikey';
 *     constructor(private readonly clients: ApiClientRepository) {}
 *
 *     async authenticate({ request }: AuthStrategyContext) {
 *         const key = request.headers['x-api-key'];
 *         const client = typeof key === 'string' ? await this.clients.findByKey(key) : undefined;
 *         return client ? { user: client, namespace: 'api', scopes: client.scopes } : undefined;
 *     }
 * }
 * ```
 */
export interface AuthStrategy<User = any> {
    /** The name used in the guards. */
    readonly name: string;
    authenticate(context: AuthStrategyContext): Promise<AuthStrategyResult<User> | undefined>;
}
