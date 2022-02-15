import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Request } from 'express';
import { Strategy } from 'passport-local';

import { AuthService } from '../service';

@Injectable()
export class EmailPasswordStrategy<User = any> extends PassportStrategy(Strategy, 'emailpassword') {
    constructor(protected readonly authService: AuthService) {
        super({
            usernameField: 'email',
            passwordField: 'password',
            passReqToCallback: true
        });
    }

    protected getNamespace(req: Request) {
        return req.query.namespace ?? req.body.namespace ?? 'default';
    }

    async validate(req: Request, email: string, password: string): Promise<[User, { namespace: string }]> {
        const query: { email: string; password: string; namespace: string } = {
            email,
            password,
            namespace: this.getNamespace(req)
        };
        const user = await this.authService.loadUser(query);
        return [user, { namespace: query.namespace }];
    }
}
