import { CallHandler, ExecutionContext, Inject, Injectable, NestInterceptor, Optional } from '@nestjs/common';
import { Observable } from 'rxjs';

import { MODULE_OPTIONS_TOKEN } from '../constants';
import { IAuthModuleOptions } from '../interfaces/options';
import { AuthTransports } from '../transports/registry';
import { getRequestAuthContext, runWithAuthContext } from './auth.context';

/**
 * Runs the handlers in the {@link AuthContext} set by the guard, so {@link getAuthContext} and the
 * {@link AuthContextService} return it in everything the handler calls.
 *
 * Registered as a global interceptor by the {@link AuthModule} (disable it with `context: false`).
 */
@Injectable()
export class AuthContextInterceptor implements NestInterceptor {
    constructor(@Optional() @Inject(MODULE_OPTIONS_TOKEN) protected readonly options?: IAuthModuleOptions) {}

    intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
        if (this.options?.context === false) {
            return next.handle();
        }
        const transport = AuthTransports.find(context);
        if (transport === undefined) {
            return next.handle();
        }
        const auth = getRequestAuthContext(transport.getRequest(context));
        // next.handle() binds the handler to the async context it is called in
        return runWithAuthContext(auth, () => next.handle());
    }
}
