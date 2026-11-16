import { Inject, Injectable, NotFoundException, Optional } from '@nestjs/common';

import { MODULE_OPTIONS_TOKEN } from '../constants';
import { IAuthModuleOptions } from '../interfaces/options';
import { AuthService } from '../service';
import { DEFAULT_SESSION_KEY, getSessionPayload, removeSessionUser } from '../session/manager';
import { AuthStrategy, AuthStrategyContext, AuthStrategyResult } from './interfaces';

/**
 * The `session` strategy: loads the user stored in the session (`fromSession: true` in a guard).
 *
 * The session holds the payload of the user (`session.passport.user`, the format of passport), loaded back with the
 * auth provider of its namespace. If the user or its provider does not exist anymore, it is removed from the session.
 */
@Injectable()
export class SessionStrategy<User = any> implements AuthStrategy<User> {
    readonly name = 'session';

    constructor(
        protected readonly authService: AuthService,
        @Optional() @Inject(MODULE_OPTIONS_TOKEN) protected readonly moduleOptions?: IAuthModuleOptions
    ) {}

    protected get key(): string {
        return this.moduleOptions?.sessionKey ?? DEFAULT_SESSION_KEY;
    }

    async authenticate({ request }: AuthStrategyContext): Promise<AuthStrategyResult<User> | undefined> {
        if (request.session === undefined || request.session === null) {
            throw new Error(
                'Login sessions require session support. Did you forget to use `express-session` middleware?'
            );
        }
        const payload = getSessionPayload(request, this.key);
        if (payload === undefined) {
            return undefined;
        }
        let user: User | undefined;
        try {
            user = await this.authService.loadUser<User>(payload);
        } catch (e) {
            if (!(e instanceof NotFoundException)) {
                throw e;
            }
        }
        if (user === undefined || user === null) {
            removeSessionUser(request.session, this.key);
            return undefined;
        }
        const namespace = typeof payload.namespace === 'string' ? payload.namespace : undefined;
        return { user, namespace, info: { namespace } };
    }
}
