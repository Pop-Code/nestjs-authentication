import { ExecutionContext } from '@nestjs/common';

import { AuthRequest, AuthTransport } from './interfaces';

/**
 * The http transport: the request and the response of the http adapter (express or fastify).
 */
export class HttpAuthTransport implements AuthTransport {
    readonly name = 'http';

    supports(context: ExecutionContext): boolean {
        return context.getType() === 'http';
    }

    getRequest(context: ExecutionContext): AuthRequest {
        return context.switchToHttp().getRequest();
    }

    getResponse(context: ExecutionContext): any {
        return context.switchToHttp().getResponse();
    }

    getNext(context: ExecutionContext): (err?: any) => void {
        const next = context.switchToHttp().getNext();
        return typeof next === 'function' ? next : throwError;
    }
}

function throwError(err?: any): void {
    if (err !== undefined && err !== null) {
        throw err;
    }
}
