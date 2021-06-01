import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-local';

import { AuthService } from '../service';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy, 'local') {
    constructor(private readonly authService: AuthService) {
        super({
            usernameField: 'email',
            passwordField: 'password',
            session: true,
            passReqToCallback: true
        });
    }

    async validate(
        req: { query: { namespace?: string }; body: { namespace?: string } },
        email: string,
        password: string
    ): Promise<any> {
        let namespace: string | undefined;
        if (typeof req.query.namespace === 'string') {
            namespace = req.query.namespace;
        } else if (typeof req.body.namespace === 'string') {
            namespace = req.body.namespace;
        }
        const user = await this.authService.loadUser({ email, password, namespace });
        return user;
    }
}
