import { CanActivate, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import * as passport from 'passport';

export const scopes = new Map();

export interface IAuthGuardOptions extends passport.AuthenticateOptions {
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
        if (Array.isArray(this.options.scope)) {
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
        if (typeof request !== 'object') {
            request = context.getArgByIndex(2).request;
            response = request.res;
            next = (err) => {
                throw err;
            };
        }

        for (const strategy of this.options.strategy) {
            if (strategy === 'local' && request.isAuthenticated() === true) {
                return true;
            } else {
                await new Promise((resolve, reject) =>
                    passport.authenticate(strategy, this.options, async (err: Error, user, info) => {
                        request.authInfo = info;
                        try {
                            if (err !== undefined && err !== null) {
                                throw err;
                            }

                            if (typeof user !== 'object' && this.options.isAuth) {
                                throw new Error('User not found');
                            }

                            if (typeof user === 'object') {
                                await this.login(user, request);
                            }
                            resolve(true);
                        } catch (e) {
                            // TO DO we could simply return false here to let the canActivate do the job
                            // And just Log the error
                            reject(
                                new UnauthorizedException(typeof e?.message === 'string' ? e.message : 'Uncaught error')
                            );
                        }
                    })(request, response, next)
                );
            }
        }

        return true;
    }

    async login<User>(user: any, request: any): Promise<User> {
        request.oauth2Scope = this.options.scope;
        await new Promise((resolve, reject) => {
            request.logIn(user, (loginErr: Error) => {
                if (loginErr instanceof Error) {
                    return reject(loginErr);
                }
                resolve(user);
            });
        });
        return user;
    }
}
