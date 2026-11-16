import { Injectable } from '@nestjs/common';

import { DEFAULT_NAMESPACE } from '../constants';
import { AuthService } from '../service';
import { AuthRequest } from '../transports/interfaces';
import { AuthStrategy, AuthStrategyContext, AuthStrategyResult } from './interfaces';

/**
 * The `emailpassword` strategy: reads `email` and `password` from the body (or the query) and loads the user with
 * the auth provider of the namespace, which checks the password.
 *
 * The namespace is read from the `namespace` query parameter or body field, `default` if not set.
 */
@Injectable()
export class EmailPasswordStrategy<User = any> implements AuthStrategy<User> {
    readonly name: string = 'emailpassword';
    protected readonly usernameField: string = 'email';
    protected readonly passwordField: string = 'password';

    constructor(protected readonly authService: AuthService) {}

    protected getNamespace(req: AuthRequest): string {
        const namespace = req.query?.namespace ?? req.body?.namespace;
        return typeof namespace === 'string' && namespace !== '' ? namespace : DEFAULT_NAMESPACE;
    }

    protected getField(req: AuthRequest, field: string): string | undefined {
        const value = req.body?.[field] ?? req.query?.[field];
        return typeof value === 'string' && value !== '' ? value : undefined;
    }

    /**
     * Loads the user of the credentials.
     * Returns the user (`undefined` fails the authentication) and the auth info.
     */
    async validate(
        req: AuthRequest,
        email: string,
        password: string
    ): Promise<[User | undefined, { namespace: string }]> {
        const namespace = this.getNamespace(req);
        const user = await this.authService.loadUser<User>({ email, password, namespace });
        return [user, { namespace }];
    }

    async authenticate({ request }: AuthStrategyContext): Promise<AuthStrategyResult<User> | undefined> {
        const email = this.getField(request, this.usernameField);
        const password = this.getField(request, this.passwordField);
        if (email === undefined || password === undefined) {
            return undefined;
        }
        const [user, info] = await this.validate(request, email, password);
        if (user === undefined || user === null) {
            return undefined;
        }
        return { user, namespace: info.namespace, info };
    }
}
