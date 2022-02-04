import { CanActivate, ExecutionContext } from '@nestjs/common';
import { Request } from 'express';
import passport, { AuthenticateOptions } from 'passport';

export class AuthGuard implements CanActivate {
    /**
     * A Memory scopes variable that can be used to get all the scopes used in the application
     */
    static scopes = new Map();
    static registerScopes(_scopes: AuthenticateOptions['scope']) {
        if (_scopes === undefined) {
            return;
        }
        let arrayScopes: string[];
        if (!Array.isArray(_scopes)) {
            arrayScopes = _scopes.split(' ');
        } else {
            arrayScopes = _scopes;
        }
        arrayScopes.forEach((s) => AuthGuard.scopes.set(s, s));
    }

    constructor(
        protected readonly strategies: { [strategyName: string]: AuthenticateOptions },
        protected readonly isAuthRequired?: boolean
    ) {
        for (const strategy in this.strategies) {
            const options = this.strategies[strategy];
            options.authInfo = options?.authInfo ?? true;
            AuthGuard.registerScopes(options?.scope);
        }
    }

    /**
     * Get the request, response and next from context
     * it supports http, graphql(http,ws) context
     */
    getRequestReponse(context: ExecutionContext) {
        let request: any;
        let response: any;
        let next: any;
        // support http, graphql(http,ws) context
        if (context.getType() === 'http') {
            const ctx = context.switchToHttp();
            [request, response, next] = [ctx.getRequest(), ctx.getResponse(), ctx.getNext()];
        } else if (context.getType<'graphql'>() === 'graphql') {
            const ctx = context.getArgByIndex(2);
            request = ctx.req;
            response = ctx.res;
            next = (err: any) => {
                throw err;
            };
        }
        return { request, response, next };
    }

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const { request, response, next } = this.getRequestReponse(context);
        for (const strategy in this.strategies) {
            const options = this.strategies[strategy];
            const success = await new Promise<boolean>((resolve, reject) =>
                passport.authenticate(
                    strategy,
                    options ?? {},
                    async (err: Error, user, authInfo: AuthenticateOptions['authInfo']) => {
                        if (request.authInfo === undefined) {
                            request.authInfo = [];
                        }
                        request.authInfo[strategy] = authInfo;
                        try {
                            if (err !== undefined && err !== null) {
                                return reject(err);
                            }
                            if (typeof user === 'object' && typeof user !== null) {
                                await this.login(user, options, request);
                                return resolve(true);
                            }
                            return resolve(false);
                        } catch (e) {
                            return reject(e);
                        }
                    }
                )(request, response, next)
            );
            if (success === true) {
                return success;
            }
        }
        return this.isAuthRequired ? request.isAuthenticated() : true;
    }

    async login(
        user: Record<string, unknown>,
        options: AuthenticateOptions,
        request: Request
    ): Promise<Record<string, unknown>> {
        return await new Promise((resolve, reject) => {
            request.logIn(user, options, (e: Error) => {
                if (e !== undefined && e !== null) {
                    return reject(e);
                }
                resolve(user);
            });
        });
    }
}
