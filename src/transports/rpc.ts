import { ExecutionContext } from '@nestjs/common';

import { AuthRequest, AuthTransport } from './interfaces';
import { createRequest, normalizeHeaders, RequestCache } from './utils';

/**
 * The microservices transport (message and event patterns).
 *
 * The headers are read from the message metadata of the transporter:
 *
 * - gRPC: the `Metadata`
 * - NATS: `NatsContext.getHeaders()`
 * - Kafka: the message headers; RabbitMQ: the message properties headers
 * - the other transporters (TCP, Redis, MQTT): the `headers` property of the data
 *
 * The data is the `body`.
 */
export class RpcAuthTransport implements AuthTransport {
    readonly name = 'rpc';
    protected readonly requests = new RequestCache();

    supports(context: ExecutionContext): boolean {
        return context.getType() === 'rpc';
    }

    getRequest(context: ExecutionContext): AuthRequest {
        const rpc = context.switchToRpc();
        const ctx = rpc.getContext();
        const data = rpc.getData();
        return this.requests.get(ctx ?? data, () =>
            createRequest(undefined, { headers: this.getHeaders(ctx, data), query: {}, body: data })
        );
    }

    protected getHeaders(ctx: any, data: any): Record<string, string | string[]> {
        // gRPC Metadata
        if (typeof ctx?.getMap === 'function') {
            return normalizeHeaders(ctx.getMap());
        }
        // NATS
        if (typeof ctx?.getHeaders === 'function') {
            const headers = ctx.getHeaders();
            if (headers !== undefined && typeof headers.keys === 'function' && typeof headers.get === 'function') {
                return normalizeHeaders(
                    Object.fromEntries(Array.from(headers.keys() as string[], (k) => [k, headers.get(k)]))
                );
            }
            return normalizeHeaders(headers);
        }
        // Kafka, RabbitMQ
        if (typeof ctx?.getMessage === 'function') {
            const message = ctx.getMessage();
            return normalizeHeaders(message?.headers ?? message?.properties?.headers);
        }
        return normalizeHeaders(data?.headers);
    }
}
