import { ExecutionContext, NotImplementedException } from '@nestjs/common';

import { AuthGuard, AuthService, AuthStrategyRegistry, SessionStrategy } from '../src';

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
    test('sets the default strategy options', () => {
        const options = { strategies: { jwt: {}, local: { authInfo: false } } };
        new AuthGuard(options);
        expect(options.strategies.jwt).toEqual({ authInfo: true });
        expect(options.strategies.local).toEqual({ authInfo: false });
    });

    test('the session options of a strategy are rejected: they are options of the guard', () => {
        expect(() => new AuthGuard({ strategies: { emailpassword: { session: true } } })).toThrow(
            'set "saveSession" on the guard'
        );
        expect(() => new AuthGuard({ strategies: { emailpassword: { keepSessionInfo: true } } })).toThrow(
            'set "keepSessionInfo" on the guard'
        );
    });

    test('getRequestResponse() supports http', () => {
        const guard = new AuthGuard({ strategies: {} });
        const [req, res, next] = [{}, {}, () => undefined];
        expect(guard.getRequestResponse(context('http', [req, res, next]))).toEqual({
            request: req,
            response: res,
            next
        });
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
        const registry = new AuthStrategyRegistry().register(new SessionStrategy(new AuthService()));
        const guard = new AuthGuard({ strategies: {}, fromSession: true }, registry);
        await expect(guard.authenticateFromSession({ headers: {} }, {})).rejects.toThrow(
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

    test('a guard without AuthModule fails with a clear error', async () => {
        const current = AuthStrategyRegistry.current;
        AuthStrategyRegistry.current = undefined;
        try {
            const guard = new AuthGuard({ strategies: { jwt: {} } });
            await expect(guard.canActivate(context('http', [{ headers: {} }, {}]))).rejects.toThrow(
                'the AuthModule is not initialized'
            );
        } finally {
            AuthStrategyRegistry.current = current;
        }
    });
});
