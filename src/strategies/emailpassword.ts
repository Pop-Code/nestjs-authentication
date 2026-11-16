import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Request } from 'express';
import { Strategy } from 'passport-local';

import { DEFAULT_NAMESPACE } from '../constants';
import { AuthService } from '../service';

/**
 * The `emailpassword` passport strategy (passport-local): reads `email` and `password` from the body
 * and loads the user with the auth provider of the namespace.
 *
 * The namespace is read from the `namespace` query parameter or body field, `default` if not set.
 */
@Injectable()
export class EmailPasswordStrategy<User = any> extends PassportStrategy(Strategy, 'emailpassword') {
    constructor(protected readonly authService: AuthService) {
        super({
            usernameField: 'email',
            passwordField: 'password',
            passReqToCallback: true
        });
    }

    protected getNamespace(req: Request): string {
        const namespace = req.query?.namespace ?? req.body?.namespace;
        return typeof namespace === 'string' && namespace !== '' ? namespace : DEFAULT_NAMESPACE;
    }

    /**
     * Called by passport with the credentials.
     * Returns the user (`undefined` fails the authentication) and the auth info.
     */
    async validate(req: Request, email: string, password: string): Promise<[User | undefined, { namespace: string }]> {
        const namespace = this.getNamespace(req);
        const user = await this.authService.loadUser<User>({ email, password, namespace });
        return [user, { namespace }];
    }
}
