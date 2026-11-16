import { ExecutionContext, NotImplementedException } from '@nestjs/common';

import {
    AuthTransport,
    AuthTransports,
    GraphqlAuthTransport,
    HttpAuthTransport,
    normalizeHeaders,
    RpcAuthTransport,
    toAuthorization,
    WsAuthTransport
} from '../src';

const context = (type: string, args: any[]): ExecutionContext =>
    ({
        getType: () => type,
        getArgByIndex: (i: number) => args[i],
        switchToHttp: () => ({ getRequest: () => args[0], getResponse: () => args[1], getNext: () => args[2] }),
        switchToWs: () => ({ getClient: () => args[0], getData: () => args[1] }),
        switchToRpc: () => ({ getData: () => args[0], getContext: () => args[1] })
    }) as unknown as ExecutionContext;

describe('utils', () => {
    test('normalizeHeaders() lower cases the names and converts the values', () => {
        expect(
            normalizeHeaders({
                Authorization: 'Bearer a',
                'X-Num': 1,
                'X-Buf': Buffer.from('b'),
                'X-Arr': ['c', Buffer.from('d')],
                'X-Null': null
            })
        ).toEqual({ authorization: 'Bearer a', 'x-num': '1', 'x-buf': 'b', 'x-arr': ['c', 'd'] });
        expect(normalizeHeaders(new Map([['A', 'b']]))).toEqual({ a: 'b' });
        expect(normalizeHeaders({ a: ['one'] })).toEqual({ a: 'one' });
        expect(normalizeHeaders({ a: { nested: true } })).toEqual({});
        expect(normalizeHeaders(undefined)).toEqual({});
        expect(normalizeHeaders('x')).toEqual({});
    });

    test('toAuthorization() adds the Bearer scheme', () => {
        expect(toAuthorization('abc')).toBe('Bearer abc');
        expect(toAuthorization('Bearer abc')).toBe('Bearer abc');
        expect(toAuthorization('Basic dXNlcg==')).toBe('Basic dXNlcg==');
        expect(toAuthorization('')).toBeUndefined();
        expect(toAuthorization(42)).toBeUndefined();
    });
});

describe('HttpAuthTransport', () => {
    const transport = new HttpAuthTransport();

    test('returns the request, the response and next', () => {
        const [req, res, next] = [{ headers: {} }, {}, () => undefined];
        const ctx = context('http', [req, res, next]);
        expect(transport.supports(ctx)).toBe(true);
        expect(transport.supports(context('ws', []))).toBe(false);
        expect(transport.getRequest(ctx)).toBe(req);
        expect(transport.getResponse(ctx)).toBe(res);
        expect(transport.getNext(ctx)).toBe(next);
    });

    test('next throws when the adapter has none (fastify)', () => {
        const next = transport.getNext(context('http', [{}, {}, undefined]));
        expect(() => next()).not.toThrow();
        expect(() => next(new Error('boom'))).toThrow('boom');
    });
});

describe('GraphqlAuthTransport', () => {
    const transport = new GraphqlAuthTransport();
    const gql = (ctx: any) => context('graphql', [{}, {}, ctx, {}]);

    test('uses context.req (apollo express)', () => {
        const req = { headers: {} };
        const res = {};
        expect(transport.supports(gql({}))).toBe(true);
        expect(transport.getRequest(gql({ req, res }))).toBe(req);
        expect(transport.getResponse(gql({ req, res }))).toBe(res);
    });

    test('uses context.request and context.reply.request (fastify, mercurius)', () => {
        const request = { headers: {} };
        expect(transport.getRequest(gql({ request }))).toBe(request);
        const reply = { request };
        expect(transport.getRequest(gql({ reply }))).toBe(request);
        expect(transport.getResponse(gql({ reply }))).toBe(reply);
    });

    test('builds the request of a subscription from the upgrade request and the connection params', () => {
        const upgrade = { headers: { Cookie: 'sid=1', 'X-Client': 'web' }, session: { id: 's' } };
        const ctx = {
            connectionParams: { authorization: 'token', headers: { 'X-Tenant': 't1' } },
            extra: { request: upgrade }
        };
        const request = transport.getRequest(gql(ctx));
        expect(request.headers).toEqual({
            cookie: 'sid=1',
            'x-client': 'web',
            'x-tenant': 't1',
            authorization: 'Bearer token'
        });
        expect(request.session).toBe(upgrade.session);
        expect(request.query).toEqual({});
        // the upgrade request is not modified
        expect(upgrade.headers).toEqual({ Cookie: 'sid=1', 'X-Client': 'web' });
        // the same request for all the resolvers of the operation
        expect(transport.getRequest(gql(ctx))).toBe(request);
    });

    test.each([['Authorization'], ['authToken'], ['token']])('reads the token from connectionParams.%s', (name) => {
        const request = transport.getRequest(gql({ connectionParams: { [name]: 'Bearer abc' } }));
        expect(request.headers.authorization).toBe('Bearer abc');
    });

    test('a subscription with context.req uses it as the base request', () => {
        const req = { headers: { cookie: 'a' } };
        const request = transport.getRequest(gql({ req, connectionParams: { token: 'abc' } }));
        expect(request).not.toBe(req);
        expect(request.headers).toEqual({ cookie: 'a', authorization: 'Bearer abc' });
    });

    test('works without a context', () => {
        const request = transport.getRequest(context('graphql', [{}, {}, undefined]));
        expect(request.headers).toEqual({});
    });
});

describe('WsAuthTransport', () => {
    const transport = new WsAuthTransport();
    const ws = (client: any) => context('ws', [client, {}]);

    test('socket.io: uses the handshake request, query and auth token', () => {
        const upgrade = { headers: { Cookie: 'sid=1' }, session: { id: 's' } };
        const client = {
            request: upgrade,
            handshake: { headers: upgrade.headers, query: { namespace: 'admin' }, auth: { token: 'abc' } }
        };
        expect(transport.supports(ws(client))).toBe(true);
        const request = transport.getRequest(ws(client));
        expect(request.headers).toEqual({ cookie: 'sid=1', authorization: 'Bearer abc' });
        expect(request.query).toEqual({ namespace: 'admin' });
        expect(request.session).toBe(upgrade.session);
        expect(transport.getRequest(ws(client))).toBe(request);
    });

    test('socket.io: the authorization header wins over the auth token', () => {
        const client = {
            handshake: { headers: { authorization: 'Bearer header' }, query: {}, auth: { token: 'auth' } }
        };
        expect(transport.getRequest(ws(client)).headers.authorization).toBe('Bearer header');
    });

    test('ws: uses the request given with setRequest(), and its url query', () => {
        const client = {};
        WsAuthTransport.setRequest(client, { headers: { authorization: 'Bearer a' }, url: '/socket?namespace=admin' });
        const request = transport.getRequest(ws(client));
        expect(request.headers.authorization).toBe('Bearer a');
        expect(request.query).toEqual({ namespace: 'admin' });
    });

    test('ws: uses client.request or client.upgradeReq', () => {
        expect(transport.getRequest(ws({ upgradeReq: { headers: { a: 'b' } } })).headers).toEqual({ a: 'b' });
        expect(transport.getRequest(ws({})).headers).toEqual({});
    });
});

describe('RpcAuthTransport', () => {
    const transport = new RpcAuthTransport();
    const rpc = (data: any, ctx: any) => context('rpc', [data, ctx]);

    test('gRPC: reads the Metadata', () => {
        const metadata = { getMap: () => ({ authorization: 'Bearer a' }) };
        const request = transport.getRequest(rpc({ id: 1 }, metadata));
        expect(transport.supports(rpc({}, metadata))).toBe(true);
        expect(request.headers).toEqual({ authorization: 'Bearer a' });
        expect(request.body).toEqual({ id: 1 });
        expect(transport.getRequest(rpc({ id: 1 }, metadata))).toBe(request);
    });

    test('NATS: reads the headers (MsgHdrs or object)', () => {
        const hdrs = new Map([['Authorization', 'Bearer n']]);
        const msgHdrs = { keys: () => hdrs.keys(), get: (k: string) => hdrs.get(k) };
        expect(transport.getRequest(rpc({}, { getHeaders: () => msgHdrs })).headers).toEqual({
            authorization: 'Bearer n'
        });
        expect(transport.getRequest(rpc({}, { getHeaders: () => ({ authorization: 'Bearer o' }) })).headers).toEqual({
            authorization: 'Bearer o'
        });
    });

    test('Kafka and RabbitMQ: read the message headers', () => {
        const kafka = { getMessage: () => ({ headers: { authorization: Buffer.from('Bearer k') } }) };
        expect(transport.getRequest(rpc({}, kafka)).headers).toEqual({ authorization: 'Bearer k' });
        const rmq = { getMessage: () => ({ properties: { headers: { authorization: 'Bearer r' } } }) };
        expect(transport.getRequest(rpc({}, rmq)).headers).toEqual({ authorization: 'Bearer r' });
    });

    test('TCP, Redis, MQTT: read data.headers', () => {
        const data = { headers: { authorization: 'Bearer t' } };
        expect(transport.getRequest(rpc(data, undefined)).headers).toEqual({ authorization: 'Bearer t' });
        expect(transport.getRequest(rpc('primitive', undefined)).headers).toEqual({});
    });
});

describe('AuthTransports', () => {
    afterEach(() => AuthTransports.reset());

    const custom: AuthTransport = {
        name: 'custom',
        supports: (ctx) => ctx.getType<string>() === 'custom' || ctx.getType() === 'http',
        getRequest: () => ({ headers: { custom: 'yes' } })
    };

    test('finds the built-in transports', () => {
        expect(AuthTransports.get(context('http', [{}]))).toBeInstanceOf(HttpAuthTransport);
        expect(AuthTransports.get(context('graphql', []))).toBeInstanceOf(GraphqlAuthTransport);
        expect(AuthTransports.get(context('ws', []))).toBeInstanceOf(WsAuthTransport);
        expect(AuthTransports.get(context('rpc', []))).toBeInstanceOf(RpcAuthTransport);
        expect(AuthTransports.find(context('other', []))).toBeUndefined();
        expect(() => AuthTransports.get(context('other', []))).toThrow(NotImplementedException);
    });

    test('registered and extra transports are tried first', () => {
        AuthTransports.register(custom, custom);
        expect(AuthTransports.all().filter((t) => t === custom)).toHaveLength(1);
        expect(AuthTransports.get(context('http', [{}]))).toBe(custom);
        const extra: AuthTransport = { ...custom, name: 'extra' };
        expect(AuthTransports.get(context('http', [{}]), [extra])).toBe(extra);
        AuthTransports.reset();
        expect(AuthTransports.get(context('http', [{}]))).toBeInstanceOf(HttpAuthTransport);
    });
});
