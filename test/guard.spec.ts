import { ExecutionContext, NotImplementedException } from '@nestjs/common';

import { AuthGuard } from '../src';

const context = (type: string, args: any[] = []): ExecutionContext =>
    ({
        getType: () => type,
        getArgByIndex: (i: number) => args[i],
        switchToHttp: () => ({
            getRequest: () => args[0],
            getResponse: () => args[1],
            getNext: () => args[2]
        })
    }) as unknown as ExecutionContext;

describe('AuthGuard', () => {
    beforeEach(() => AuthGuard.scopes.clear());

    test('sets the default strategy options', () => {
        const options = { strategies: { jwt: {}, local: { session: true, authInfo: false } } };
        new AuthGuard(options);
        expect(options.strategies.jwt).toEqual({ authInfo: true, session: false });
        expect(options.strategies.local).toEqual({ authInfo: false, session: true });
    });

    test('registers the scopes of the strategies', () => {
        new AuthGuard({ strategies: { a: { scope: 'read write' }, b: { scope: ['admin', 'read'] }, c: {} } });
        expect([...AuthGuard.scopes.keys()]).toEqual(['read', 'write', 'admin']);
        AuthGuard.registerScopes(undefined);
        AuthGuard.registerScopes('');
        expect(AuthGuard.scopes.size).toBe(3);
    });

    test('getRequestResponse() supports http', () => {
        const guard = new AuthGuard({ strategies: {} });
        const [req, res, next] = [{}, {}, () => undefined];
        expect(guard.getRequestResponse(context('http', [req, res, next]))).toEqual({
            request: req,
            response: res,
            next
        });
        // deprecated alias
        expect(guard.getRequestReponse(context('http', [req, res, next])).request).toBe(req);
    });

    test('getRequestResponse() supports graphql', () => {
        const guard = new AuthGuard({ strategies: {} });
        const [req, res] = [{}, {}];
        const result = guard.getRequestResponse(context('graphql', [{}, {}, { req, res }]));
        expect(result.request).toBe(req);
        expect(result.response).toBe(res);
        expect(() => result.next()).not.toThrow();
        expect(() => result.next(new Error('failed'))).toThrow('failed');
    });

    test('getRequestResponse() throws for other contexts', () => {
        const guard = new AuthGuard({ strategies: {} });
        expect(() => guard.getRequestResponse(context('unknown'))).toThrow(NotImplementedException);
    });

    test('authenticateFromSession() fails without a session middleware', async () => {
        const guard = new AuthGuard({ strategies: {}, fromSession: true });
        await expect(guard.authenticateFromSession({} as any, {} as any)).rejects.toThrow(
            'Login sessions require session support'
        );
    });

    test('a required guard without strategy rejects a request that passport never saw', async () => {
        const guard = new AuthGuard({ strategies: {}, required: true });
        const request: any = { headers: {} };
        await expect(guard.canActivate(context('http', [request, {}, () => undefined]))).resolves.toBe(false);
        expect(typeof request.isAuthenticated).toBe('function');
        await expect(
            new AuthGuard({ strategies: {} }).canActivate(context('http', [{ headers: {} }, {}]))
        ).resolves.toBe(true);
    });
});
