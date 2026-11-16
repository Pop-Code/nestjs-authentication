import { createParamDecorator, ExecutionContext } from '@nestjs/common';

import { AuthTransports } from '../transports/registry';
import { AuthContext, getAuthContext, getRequestAuthContext } from './auth.context';

/** Returns the {@link AuthContext} of an execution context. */
export function getExecutionAuthContext<User = any>(context: ExecutionContext): AuthContext<User> | undefined {
    const transport = AuthTransports.find(context);
    const fromRequest =
        transport !== undefined ? getRequestAuthContext<User>(transport.getRequest(context)) : undefined;
    return fromRequest ?? getAuthContext<User>();
}

/**
 * Injects the {@link AuthContext} of the request (http, GraphQL, websockets, microservices), `undefined` if it is not
 * authenticated.
 *
 * ```ts
 * @Get('me')
 * me(@CurrentAuth() auth: AuthContext<User>) {}
 * ```
 */
export const CurrentAuth = createParamDecorator((_data: unknown, context: ExecutionContext) =>
    getExecutionAuthContext(context)
);

/**
 * Injects the authenticated user (http, GraphQL, websockets, microservices), `undefined` if the request is not
 * authenticated. Give a property name to inject only this property.
 *
 * ```ts
 * @Get('me')
 * me(@CurrentUser() user: User, @CurrentUser('email') email: string) {}
 * ```
 */
export const CurrentUser = createParamDecorator((property: string | undefined, context: ExecutionContext) => {
    const user = getExecutionAuthContext(context)?.user;
    return property !== undefined && user !== undefined && user !== null ? user[property] : user;
});
