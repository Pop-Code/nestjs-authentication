import { ExecutionContext, NotImplementedException } from '@nestjs/common';

import { GraphqlAuthTransport } from './graphql';
import { HttpAuthTransport } from './http';
import { AuthTransport } from './interfaces';
import { RpcAuthTransport } from './rpc';
import { WsAuthTransport } from './ws';

/**
 * The transports used by the guards and the decorators: the built-in ones, and the ones added with
 * `AuthModule.forRoot({ transports })` or {@link AuthTransports.register}.
 */
export class AuthTransports {
    private static custom: AuthTransport[] = [];
    private static readonly builtIn: AuthTransport[] = [
        new HttpAuthTransport(),
        new GraphqlAuthTransport(),
        new WsAuthTransport(),
        new RpcAuthTransport()
    ];

    /** Adds transports. They are tried before the built-in ones, in the order they are added. */
    static register(...transports: AuthTransport[]): void {
        for (const transport of transports) {
            if (!AuthTransports.custom.includes(transport)) {
                AuthTransports.custom.push(transport);
            }
        }
    }

    /** Removes the transports added with {@link register} (for tests). */
    static reset(): void {
        AuthTransports.custom = [];
    }

    /** Returns the transports: the given ones first, then the registered ones, then the built-in ones. */
    static all(extra: AuthTransport[] = []): AuthTransport[] {
        return [...extra, ...AuthTransports.custom, ...AuthTransports.builtIn];
    }

    /** Returns the first transport that supports the context, or `undefined`. */
    static find(context: ExecutionContext, extra: AuthTransport[] = []): AuthTransport | undefined {
        return AuthTransports.all(extra).find((t) => t.supports(context));
    }

    /**
     * Returns the first transport that supports the context.
     *
     * @throws NotImplementedException if none does
     */
    static get(context: ExecutionContext, extra: AuthTransport[] = []): AuthTransport {
        const transport = AuthTransports.find(context, extra);
        if (transport === undefined) {
            throw new NotImplementedException(`Auth Context ${context.getType()} not implemented`);
        }
        return transport;
    }
}
