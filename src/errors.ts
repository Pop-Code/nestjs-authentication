import { ExecutionContext, ForbiddenException, HttpException, UnauthorizedException } from '@nestjs/common';

/**
 * Creates the error thrown by the {@link AuthGuard} when a `required` request is not authenticated.
 *
 * @param context the execution context
 * @param transport the name of the transport (`http`, `graphql`, `ws`, `rpc`...)
 */
export type AuthExceptionFactory = (context: ExecutionContext, transport: string) => Error;

function loadOptional(name: string): any {
    try {
        // eslint-disable-next-line @typescript-eslint/no-require-imports
        return require(name);
    } catch {
        return undefined;
    }
}

/**
 * Converts an http exception to the error of the transport: a `WsException` for websockets and an `RpcException`
 * for microservices (if `@nestjs/websockets` / `@nestjs/microservices` are installed), so their exception filters
 * send it to the client. Http and GraphQL keep the http exception (GraphQL drivers format it).
 */
export function toTransportException(exception: HttpException, transport: string): Error {
    const error = { status: exception.getStatus(), message: exception.message };
    if (transport === 'ws') {
        const WsException = loadOptional('@nestjs/websockets')?.WsException;
        return WsException !== undefined ? new WsException(error) : exception;
    }
    if (transport === 'rpc') {
        const RpcException = loadOptional('@nestjs/microservices')?.RpcException;
        return RpcException !== undefined ? new RpcException(error) : exception;
    }
    return exception;
}

/**
 * An {@link AuthExceptionFactory} that throws a 401 Unauthorized, the right status for a request that is not
 * authenticated. With a `challenge`, the http response has a `WWW-Authenticate` header (e.g. `Bearer`).
 *
 * ```ts
 * new AuthGuard({ strategies: { jwt: {} }, required: true, exceptionFactory: unauthorized({ challenge: 'Bearer' }) })
 * ```
 */
export function unauthorized(options: { challenge?: string; message?: string } = {}): AuthExceptionFactory {
    return (context, transport) => {
        if (options.challenge !== undefined && transport === 'http') {
            const response = context.switchToHttp().getResponse();
            // express: setHeader(), fastify: header()
            if (typeof response?.setHeader === 'function') {
                response.setHeader('WWW-Authenticate', options.challenge);
            } else if (typeof response?.header === 'function') {
                response.header('WWW-Authenticate', options.challenge);
            }
        }
        return toTransportException(new UnauthorizedException(options.message), transport);
    };
}

/**
 * The default {@link AuthExceptionFactory}: a 403 Forbidden (the error NestJS throws when a guard returns `false`),
 * converted to the error of the transport.
 */
export const forbidden: AuthExceptionFactory = (_context, transport) =>
    toTransportException(new ForbiddenException('Forbidden resource'), transport);
