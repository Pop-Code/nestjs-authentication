import { PassportStrategy } from '@nestjs/passport';
import jwt, { Secret, SignOptions } from 'jsonwebtoken';
import { Strategy, StrategyOptions } from 'passport-jwt';

import { AuthService } from '../service';

export class JwtStrategy<User = any> extends PassportStrategy(Strategy, 'jwt') {
    constructor(protected readonly authService: AuthService, protected readonly options: StrategyOptions) {
        super(options);
    }

    protected getNamespace(payload: Record<string, unknown> & { namespace?: string }) {
        return payload.namespace ?? 'default';
    }

    async validate(payload: Record<string, unknown> & { namespace?: string }): Promise<[User, { namespace: string }]> {
        const user = await this.authService.loadUser(payload);
        return [user, { namespace: this.getNamespace(payload) }];
    }

    sign(payload: Record<string, unknown> & { namespace?: string }, secretOrPrivateKey: Secret, options?: SignOptions) {
        return jwt.sign(payload, secretOrPrivateKey, options);
    }
}
