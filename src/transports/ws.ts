import { ExecutionContext } from '@nestjs/common';

import { AuthRequest, AuthTransport } from './interfaces';
import { createRequest, normalizeHeaders, RequestCache, toAuthorization } from './utils';

/**
 * The websockets transport (gateways), for socket.io and ws.
 *
 * The request is built once per connection:
 *
 * - socket.io: from the handshake (`client.request`: headers, cookies and the session if you share the session
 *   middleware with `io.engine.use(session)`), `handshake.query`, and `handshake.auth.token`
 *   (or `auth.authorization`), set as the `authorization` header (`Bearer <token>` if it has no scheme)
 * - ws: from the upgrade request. The ws adapter does not keep it: give it in `handleConnection(client, request)`
 *   with {@link WsAuthTransport.setRequest}, or set `client.request`
 */
export class WsAuthTransport implements AuthTransport {
    readonly name = 'ws';
    protected static readonly requests = new RequestCache();

    /** Sets the upgrade request of a ws client (`handleConnection(client, request)`). */
    static setRequest(client: object, request: { headers?: any; url?: string; session?: any }): void {
        WsAuthTransport.requests.set(client, WsAuthTransport.createRequest(request, {}, undefined));
    }

    supports(context: ExecutionContext): boolean {
        return context.getType() === 'ws';
    }

    getRequest(context: ExecutionContext): AuthRequest {
        const client = context.switchToWs().getClient();
        return WsAuthTransport.requests.get(client, () => {
            const handshake = client?.handshake;
            const upgrade = client?.request ?? client?.upgradeReq;
            return WsAuthTransport.createRequest(
                upgrade ?? (handshake !== undefined ? { headers: handshake.headers } : undefined),
                handshake?.query ?? {},
                handshake?.auth
            );
        });
    }

    protected static createRequest(
        upgrade: { headers?: any; url?: string } | undefined,
        query: Record<string, unknown>,
        auth: Record<string, unknown> | undefined
    ): AuthRequest {
        const headers = normalizeHeaders(upgrade?.headers);
        const authorization = toAuthorization(auth?.authorization ?? auth?.token);
        if (authorization !== undefined && headers.authorization === undefined) {
            headers.authorization = authorization;
        }
        let requestQuery = query;
        if (Object.keys(query).length === 0 && typeof upgrade?.url === 'string') {
            requestQuery = Object.fromEntries(new URL(upgrade.url, 'http://localhost').searchParams);
        }
        return createRequest(upgrade, { headers, query: requestQuery, body: {} });
    }
}
