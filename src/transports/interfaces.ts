import { ExecutionContext } from '@nestjs/common';

/**
 * The request given to the passport strategies: what they read (`headers`, `query`, `body`, `session`)
 * and where passport sets the user (`user`, `logIn()`, `isAuthenticated()`...).
 *
 * For http it is the request of the framework (express, fastify). For the other transports it is built
 * from the context (GraphQL context, socket handshake, message metadata) and cached, so all the guards and
 * decorators of the same request, operation or connection share it.
 */
export interface AuthRequest {
    headers: Record<string, string | string[] | undefined>;
    query?: Record<string, unknown>;
    body?: any;
    session?: any;
    user?: any;
    [key: string]: any;
}

/**
 * Reads the request of a type of execution context (http, GraphQL, websockets, microservices...).
 *
 * Built-in: {@link HttpAuthTransport}, {@link GraphqlAuthTransport}, {@link WsAuthTransport}, {@link RpcAuthTransport}.
 * Add yours with the `transports` option of the {@link AuthModule}, or of the {@link AuthGuard}.
 */
export interface AuthTransport {
    /** The name of the transport, given to the exception factories (`http`, `graphql`, `ws`, `rpc`...). */
    readonly name: string;
    /** Returns `true` if this transport handles the context. The first transport that does is used. */
    supports(context: ExecutionContext): boolean;
    /** Returns the request given to passport. Must return the same object for the same request. */
    getRequest(context: ExecutionContext): AuthRequest;
    /** Returns the response given to passport, if the transport has one. */
    getResponse?(context: ExecutionContext): any;
    /** Returns the `next` function given to passport. Defaults to a function that throws the error it receives. */
    getNext?(context: ExecutionContext): (err?: any) => void;
}
