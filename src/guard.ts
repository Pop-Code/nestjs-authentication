import { CanActivate, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { GqlExecutionContext } from '@nestjs/graphql';
import passport, { AuthenticateOptions } from 'passport';

export const scopes = new Map();

export interface IAuthGuardOptions extends AuthenticateOptions {
    isAuth?: boolean;
    strategy: string | string[];
}

export class AuthGuard implements CanActivate {
    protected readonly options: IAuthGuardOptions;

    // TODO type options
    constructor(options: any) {
        this.options = { ...options, authInfo: true };
        if (typeof this.options.scope === 'string') {
            this.options.scope = [this.options.scope];
        }
        if (this.options.scope) {
            for (const scope of this.options.scope) {
                scopes.set(scope, scope);
            }
        }
        if (typeof this.options.strategy === 'string') {
            this.options.strategy = [this.options.strategy];
        }
    }

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const httpCtx = context.switchToHttp();
        let [request, response, next] = [httpCtx.getRequest(), httpCtx.getResponse(), httpCtx.getNext()];

        // support graphql context
        const ctx = GqlExecutionContext.create(context);
        if (!request) {
            request = ctx.getContext().request;
            response = request.res;
            next = err => {
                throw err;
            };
        }

        for (const strategy of this.options.strategy) {
            if (strategy === 'local' && request.isAuthenticated()) {
                return true;
            } else {
                await new Promise((ok, fail) =>
                    passport.authenticate(strategy, this.options, async (err, user, info) => {
                        request.authInfo = info;
                        try {
                            if (!user && this.options.isAuth) {
                                throw new Error('User not found');
                            }
                            if (err) {
                                throw err;
                            }
                            if (user) {
                                await this.login(user, request);
                            }
                            ok();
                        } catch (e) {
                            // TO DO we could simply return false here to let the canActivate do the job
                            // And just Log the error
                            fail(new UnauthorizedException(e.message.message || e.message || 'Uncaught error'));
                        }
                    })(request, response, next)
                );
            }
        }

        return true;
    }

    async login<User>(user: any, request: any): Promise<User> {
        request.oauth2Scope = this.options.scope;
        await new Promise((ok, fail) => {
            request.logIn(user, (loginErr: Error) => {
                if (loginErr) {
                    return fail(loginErr);
                }
                ok();
            });
        });
        return user;
    }
}
