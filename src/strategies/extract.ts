import { AuthRequest } from '../transports/interfaces';

/** Returns the token of a request, `null` or `undefined` if there is none. */
export type JwtFromRequestFunction = (request: AuthRequest) => string | null | undefined;

const header = (request: AuthRequest, name: string): string | undefined => {
    const value = request.headers?.[name.toLowerCase()];
    return Array.isArray(value) ? value[0] : value;
};

/**
 * Token extractors, with the API of passport-jwt's `ExtractJwt` (its extractors work too).
 */
export const ExtractJwt = {
    /** The value of a header. */
    fromHeader:
        (name: string): JwtFromRequestFunction =>
        (request) =>
            header(request, name) ?? null,

    /** A field of the body. */
    fromBodyField:
        (field: string): JwtFromRequestFunction =>
        (request) => {
            const value = request.body?.[field];
            return typeof value === 'string' ? value : null;
        },

    /** A query parameter. */
    fromUrlQueryParameter:
        (name: string): JwtFromRequestFunction =>
        (request) => {
            const value = request.query?.[name];
            return typeof value === 'string' ? value : null;
        },

    /** A cookie (needs a cookie parser, e.g. cookie-parser, or reads the `cookie` header). */
    fromCookie:
        (name: string): JwtFromRequestFunction =>
        (request) => {
            const parsed = request.cookies?.[name];
            if (typeof parsed === 'string') {
                return parsed;
            }
            const cookies = header(request, 'cookie');
            const match = cookies
                ?.split(';')
                .map((c) => c.trim())
                .find((c) => c.startsWith(`${name}=`));
            return match !== undefined ? decodeURIComponent(match.slice(name.length + 1)) : null;
        },

    /** The `authorization` header with a scheme (case insensitive): `<scheme> <token>`. */
    fromAuthHeaderWithScheme:
        (scheme: string): JwtFromRequestFunction =>
        (request) => {
            const match = /^(\S+)\s+(\S+)$/.exec(header(request, 'authorization') ?? '');
            return match !== null && match[1].toLowerCase() === scheme.toLowerCase() ? match[2] : null;
        },

    /** The `authorization` header: `Bearer <token>`. */
    fromAuthHeaderAsBearerToken: (): JwtFromRequestFunction => ExtractJwt.fromAuthHeaderWithScheme('bearer'),

    /** The first token found by the extractors. */
    fromExtractors:
        (extractors: JwtFromRequestFunction[]): JwtFromRequestFunction =>
        (request) => {
            for (const extractor of extractors) {
                const token = extractor(request);
                if (typeof token === 'string' && token !== '') {
                    return token;
                }
            }
            return null;
        }
};
