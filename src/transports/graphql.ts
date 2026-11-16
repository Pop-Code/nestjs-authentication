import { ExecutionContext } from '@nestjs/common';

import { AuthRequest, AuthTransport } from './interfaces';
import { createRequest, normalizeHeaders, RequestCache, toAuthorization } from './utils';

/**
 * The GraphQL transport (queries, mutations and subscriptions), for Apollo, Mercurius, Yoga...
 *
 * The request is found in the GraphQL context (third resolver argument), in this order:
 *
 * - `context.req` (Apollo with express, the default context of `@nestjs/apollo`)
 * - `context.request`, `context.reply.request` (fastify, Mercurius)
 * - subscriptions (graphql-ws): a request built from `context.extra.request` (the upgrade request: headers,
 *   cookies, session) and `context.connectionParams`
 *
 * For subscriptions, `connectionParams.authorization` (or `Authorization`, `authToken`, `token`) is set as the
 * `authorization` header (`Bearer <token>` if it has no scheme), and `connectionParams.headers` are added to the headers.
 * Return `connectionParams` and `extra` from your context factory for subscriptions:
 * `context: ({ req, res, connectionParams, extra }) => ({ req, res, connectionParams, extra })`.
 */
export class GraphqlAuthTransport implements AuthTransport {
    readonly name = 'graphql';
    protected readonly requests = new RequestCache();

    supports(context: ExecutionContext): boolean {
        return context.getType<string>() === 'graphql';
    }

    protected getContext(context: ExecutionContext): any {
        return context.getArgByIndex(2) ?? {};
    }

    getRequest(context: ExecutionContext): AuthRequest {
        const ctx = this.getContext(context);
        const request = ctx.req ?? ctx.request ?? ctx.reply?.request;
        if (request !== undefined && request !== null && ctx.connectionParams === undefined) {
            return request;
        }
        return this.requests.get(ctx, () => this.createSubscriptionRequest(ctx, request));
    }

    getResponse(context: ExecutionContext): any {
        const ctx = this.getContext(context);
        return ctx.res ?? ctx.reply;
    }

    protected createSubscriptionRequest(ctx: any, request?: any): AuthRequest {
        const upgrade = request ?? ctx.extra?.request;
        const params = ctx.connectionParams ?? {};
        const headers = { ...normalizeHeaders(upgrade?.headers), ...normalizeHeaders(params.headers) };
        const authorization = toAuthorization(
            params.authorization ?? params.Authorization ?? params.authToken ?? params.token
        );
        if (authorization !== undefined) {
            headers.authorization = authorization;
        }
        return createRequest(upgrade, { headers, query: {}, body: {} });
    }
}
