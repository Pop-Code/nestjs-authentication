import { UnauthorizedException } from '@nestjs/common';

import {
    AUTH_CONTEXT,
    AuthContextService,
    getAuthContext,
    getRequestAuthContext,
    runWithAuthContext,
    setRequestAuthContext
} from '../src';

describe('AuthContext', () => {
    const auth = { user: { id: 1 }, strategy: 'jwt', transport: 'http' };

    test('runWithAuthContext() sets the context of the async calls', async () => {
        expect(getAuthContext()).toBeUndefined();
        await runWithAuthContext(auth, async () => {
            await new Promise((r) => setTimeout(r, 1));
            expect(getAuthContext()).toBe(auth);
            runWithAuthContext(undefined, () => expect(getAuthContext()).toBeUndefined());
            expect(getAuthContext()).toBe(auth);
        });
        expect(getAuthContext()).toBeUndefined();
    });

    test('AuthContextService', () => {
        const service = new AuthContextService();
        expect(service.get()).toBeUndefined();
        expect(service.getUser()).toBeUndefined();
        expect(service.isAuthenticated()).toBe(false);
        expect(() => service.getUserOrFail()).toThrow(UnauthorizedException);
        runWithAuthContext(auth, () => {
            expect(service.get()).toBe(auth);
            expect(service.getUser()).toEqual({ id: 1 });
            expect(service.getUserOrFail()).toEqual({ id: 1 });
            expect(service.isAuthenticated()).toBe(true);
        });
    });

    test('the context of a request', () => {
        const request = {};
        expect(getRequestAuthContext(request)).toBeUndefined();
        expect(getRequestAuthContext(undefined)).toBeUndefined();
        setRequestAuthContext(request, auth);
        expect(getRequestAuthContext(request)).toBe(auth);
        expect((request as any)[AUTH_CONTEXT]).toBe(auth);
    });
});
