import { AuthRequest } from './interfaces';

/** Lower cases the header names and converts the values (Buffer, number...) to strings. */
export function normalizeHeaders(headers: unknown): Record<string, string | string[]> {
    const result: Record<string, string | string[]> = {};
    if (headers === undefined || headers === null || typeof headers !== 'object') {
        return result;
    }
    const entries: [string, unknown][] =
        typeof (headers as any).entries === 'function' && !(headers instanceof Array)
            ? Array.from((headers as any).entries() as Iterable<[string, unknown]>)
            : Object.entries(headers);
    for (const [key, value] of entries) {
        if (value === undefined || value === null) {
            continue;
        }
        const name = key.toLowerCase();
        if (Array.isArray(value)) {
            const values = value.map((v) => toHeaderValue(v)).filter((v): v is string => v !== undefined);
            result[name] = values.length === 1 ? values[0] : values;
        } else {
            const v = toHeaderValue(value);
            if (v !== undefined) {
                result[name] = v;
            }
        }
    }
    return result;
}

function toHeaderValue(value: unknown): string | undefined {
    if (typeof value === 'string') {
        return value;
    }
    if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
        return Buffer.from(value).toString('utf8');
    }
    if (typeof value === 'number' || typeof value === 'boolean') {
        return String(value);
    }
    return undefined;
}

/** Returns `Bearer <token>`, or the value if it already has a scheme. */
export function toAuthorization(token: unknown): string | undefined {
    if (typeof token !== 'string' || token === '') {
        return undefined;
    }
    return /^[A-Za-z][A-Za-z0-9-]*\s/.test(token) ? token : `Bearer ${token}`;
}

/**
 * Returns a request that reads what is not set on it from `base` (e.g. the session of the upgrade request),
 * with its own `headers`, `query` and `body`, so `base` is never modified.
 */
export function createRequest(
    base: object | undefined,
    parts: { headers: Record<string, string | string[]>; query?: Record<string, unknown>; body?: any }
): AuthRequest {
    const request = Object.create(base ?? null) as AuthRequest;
    request.headers = parts.headers;
    request.query = parts.query ?? {};
    request.body = parts.body ?? {};
    return request;
}

/** Caches the requests built for an object (a GraphQL context, a socket, a message context). */
export class RequestCache {
    private readonly cache = new WeakMap<object, AuthRequest>();

    get(key: unknown, create: () => AuthRequest): AuthRequest {
        if (key === null || (typeof key !== 'object' && typeof key !== 'function')) {
            return create();
        }
        let request = this.cache.get(key);
        if (request === undefined) {
            request = create();
            this.cache.set(key, request);
        }
        return request;
    }

    set(key: object, request: AuthRequest): void {
        this.cache.set(key, request);
    }
}
