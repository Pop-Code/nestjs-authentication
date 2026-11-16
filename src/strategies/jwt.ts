import { PassportStrategy } from '@nestjs/passport';
import jwt, { Secret, SignOptions } from 'jsonwebtoken';
import { Strategy } from 'passport-jwt';

import { DEFAULT_NAMESPACE } from '../constants';
import { AuthUserPayload } from '../interfaces/auth.user';
import { JwtStrategyOptions } from '../interfaces/options';
import { AuthService } from '../service';

/**
 * The `jwt` passport strategy (passport-jwt): verifies the token and loads the user of its payload
 * with the auth provider of `payload.namespace` (`default` if not set).
 *
 * Provided by the {@link AuthModule} when the `jwt` option is set.
 */
export class JwtStrategy<User = any> extends PassportStrategy(Strategy, 'jwt') {
    constructor(
        protected readonly authService: AuthService,
        protected readonly options: JwtStrategyOptions
    ) {
        super(options);
    }

    protected getNamespace(payload: AuthUserPayload): string {
        return typeof payload.namespace === 'string' ? payload.namespace : DEFAULT_NAMESPACE;
    }

    /**
     * Called by passport with the verified payload.
     * Returns the user (`undefined` fails the authentication) and the auth info.
     */
    async validate(payload: AuthUserPayload): Promise<[User | undefined, { namespace: string }]> {
        const user = await this.authService.loadUser<User>(payload);
        return [user, { namespace: this.getNamespace(payload) }];
    }

    /**
     * Signs a token (jsonwebtoken).
     *
     * @param payload the payload, typically `user.authSerialize()`
     * @param secretOrPrivateKey the key, the `secretOrKey` option of the strategy if not set
     * @param options the jsonwebtoken sign options (`expiresIn`, `algorithm`...)
     * @throws Error if there is no key
     */
    sign(payload: AuthUserPayload, secretOrPrivateKey?: Secret, options?: SignOptions): string {
        const secret = secretOrPrivateKey ?? ('secretOrKey' in this.options ? this.options.secretOrKey : undefined);
        if (secret === undefined) {
            throw new Error('JwtStrategy.sign(): a secretOrPrivateKey is required (no secretOrKey option)');
        }
        return jwt.sign(payload, secret, options);
    }
}
