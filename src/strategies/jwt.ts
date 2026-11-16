import jwt, { Algorithm, Secret, SignOptions, VerifyOptions } from 'jsonwebtoken';

import { DEFAULT_NAMESPACE } from '../constants';
import { AuthUserPayload } from '../interfaces/auth.user';
import { AuthService } from '../service';
import { AuthRequest } from '../transports/interfaces';
import { ExtractJwt, JwtFromRequestFunction } from './extract';
import { AuthStrategy, AuthStrategyContext, AuthStrategyResult } from './interfaces';

/**
 * Returns the key that verifies a token: with a promise, or with the `done` callback of passport-jwt
 * (so `passportJwtSecret()` of jwks-rsa works for JWKS: Auth0, Cognito, Keycloak, Entra ID...).
 */
export type SecretOrKeyProvider = (
    request: AuthRequest,
    rawJwtToken: string,
    done: (err: any, secretOrKey?: Secret) => void
) => void | Promise<Secret | undefined>;

/**
 * Options of the {@link JwtStrategy}, the option names of passport-jwt.
 */
export interface JwtStrategyOptions {
    /** The key that verifies (and signs) the tokens: a secret (HS256...) or a public key (RS256, ES256...). */
    secretOrKey?: Secret;
    /** Returns the key of a token (key rotation, JWKS). */
    secretOrKeyProvider?: SecretOrKeyProvider;
    /** Reads the token. Default: the `authorization` header (`Bearer <token>`). */
    jwtFromRequest?: JwtFromRequestFunction;
    /** The accepted algorithms. Recommended: by default jsonwebtoken accepts the algorithms of the key type. */
    algorithms?: Algorithm[];
    /** The accepted issuer(s). */
    issuer?: string | string[];
    /** The accepted audience(s). */
    audience?: string | RegExp | (string | RegExp)[];
    /** Accepts the expired tokens. Default `false`. */
    ignoreExpiration?: boolean;
    /** Other jsonwebtoken verify options (`clockTolerance`, `maxAge`, `subject`...). */
    jsonWebTokenOptions?: VerifyOptions;
}

/** Returns the scopes of a token payload: `scope` (space separated), `scp` or `scopes` (array or string). */
export function getTokenScopes(payload: Record<string, unknown>): string[] {
    const value = payload.scope ?? payload.scp ?? payload.scopes;
    const list = Array.isArray(value) ? value : typeof value === 'string' ? value.split(' ') : [];
    return list.filter((s): s is string => typeof s === 'string' && s !== '');
}

/**
 * The `jwt` strategy, built on jsonwebtoken: verifies the token and loads the user of its payload with the auth
 * provider of `payload.namespace` (`default` if not set). The `scope` / `scp` claims are the scopes of the request.
 *
 * Provided by the {@link AuthModule} when the `jwt` option is set.
 */
export class JwtStrategy<User = any> implements AuthStrategy<User> {
    readonly name: string = 'jwt';
    protected readonly jwtFromRequest: JwtFromRequestFunction;

    constructor(
        protected readonly authService: AuthService,
        protected readonly options: JwtStrategyOptions
    ) {
        if (options.secretOrKey === undefined && options.secretOrKeyProvider === undefined) {
            throw new Error('JwtStrategy requires a secretOrKey or a secretOrKeyProvider');
        }
        this.jwtFromRequest = options.jwtFromRequest ?? ExtractJwt.fromAuthHeaderAsBearerToken();
    }

    protected getNamespace(payload: AuthUserPayload): string {
        return typeof payload.namespace === 'string' ? payload.namespace : DEFAULT_NAMESPACE;
    }

    /** Returns the key of a token. */
    protected async getKey(request: AuthRequest, token: string): Promise<Secret | undefined> {
        if (this.options.secretOrKeyProvider === undefined) {
            return this.options.secretOrKey;
        }
        const provider = this.options.secretOrKeyProvider;
        return await new Promise<Secret | undefined>((resolve, reject) => {
            const result = provider(request, token, (err, key) => (err ? reject(err) : resolve(key)));
            if (result instanceof Promise) {
                result.then(resolve, reject);
            }
        });
    }

    /** Verifies a token. Returns its payload, or `undefined` if it is not valid. */
    async verify(token: string, request: AuthRequest = { headers: {} }): Promise<AuthUserPayload | undefined> {
        let key: Secret | undefined;
        try {
            key = await this.getKey(request, token);
        } catch {
            return undefined;
        }
        if (key === undefined) {
            return undefined;
        }
        const { algorithms, issuer, audience, ignoreExpiration, jsonWebTokenOptions } = this.options;
        try {
            const verifyOptions: VerifyOptions = { ...jsonWebTokenOptions, complete: false };
            if (algorithms !== undefined) verifyOptions.algorithms = algorithms;
            if (issuer !== undefined) verifyOptions.issuer = issuer as VerifyOptions['issuer'];
            if (audience !== undefined) verifyOptions.audience = audience as VerifyOptions['audience'];
            if (ignoreExpiration !== undefined) verifyOptions.ignoreExpiration = ignoreExpiration;
            const payload = jwt.verify(token, key, verifyOptions);
            return typeof payload === 'object' && payload !== null ? (payload as AuthUserPayload) : undefined;
        } catch {
            return undefined;
        }
    }

    /**
     * Loads the user of a verified payload.
     * Returns the user (`undefined` fails the authentication) and the auth info.
     */
    async validate(payload: AuthUserPayload): Promise<[User | undefined, { namespace: string }]> {
        const user = await this.authService.loadUser<User>(payload);
        return [user, { namespace: this.getNamespace(payload) }];
    }

    async authenticate({ request }: AuthStrategyContext): Promise<AuthStrategyResult<User> | undefined> {
        const token = this.jwtFromRequest(request);
        if (typeof token !== 'string' || token === '') {
            return undefined;
        }
        const payload = await this.verify(token, request);
        if (payload === undefined) {
            return undefined;
        }
        const [user, info] = await this.validate(payload);
        if (user === undefined || user === null) {
            return undefined;
        }
        return { user, namespace: info.namespace, info: { ...info, payload }, scopes: getTokenScopes(payload) };
    }

    /**
     * Signs a token (jsonwebtoken).
     *
     * @param payload the payload, typically `user.authSerialize()`, and the `scope` claim
     * @param secretOrPrivateKey the key, the `secretOrKey` option of the strategy if not set
     * @param options the jsonwebtoken sign options (`expiresIn`, `algorithm`, `audience`, `issuer`...)
     * @throws Error if there is no key
     */
    sign(payload: AuthUserPayload, secretOrPrivateKey?: Secret, options?: SignOptions): string {
        const secret = secretOrPrivateKey ?? this.options.secretOrKey;
        if (secret === undefined) {
            throw new Error('JwtStrategy.sign(): a secretOrPrivateKey is required (no secretOrKey option)');
        }
        return jwt.sign(payload, secret, options);
    }
}
