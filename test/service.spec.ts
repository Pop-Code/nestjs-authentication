import { NotFoundException } from '@nestjs/common';

import { AuthService, IAuthProvider } from '../src';

const provider = (name: string, user?: any): IAuthProvider => ({
    getName: () => name,
    loadUser: jest.fn(async () => user)
});

describe('AuthService', () => {
    test('registers the providers by name', () => {
        const service = new AuthService();
        const a = provider('default');
        const b = provider('admin');
        expect(service.registerAuthProvider(a).registerAuthProvider(b)).toBe(service);
        expect(service.getAuthProvider('default')).toBe(a);
        expect(service.getAuthProvider('admin')).toBe(b);
        expect(service.getAuthProvider('none')).toBeUndefined();
        expect([...service.getAuthProviders().keys()]).toEqual(['default', 'admin']);
    });

    test('a provider replaces the provider with the same name', () => {
        const service = new AuthService();
        const b = provider('default');
        service.registerAuthProvider(provider('default')).registerAuthProvider(b);
        expect(service.getAuthProvider('default')).toBe(b);
    });

    test('loadUser() uses the provider of the namespace, default if not set', async () => {
        const service = new AuthService();
        const a = provider('default', { id: 'a' });
        const b = provider('admin', { id: 'b' });
        service.registerAuthProvider(a).registerAuthProvider(b);

        await expect(service.loadUser({ _id: 1 })).resolves.toEqual({ id: 'a' });
        await expect(service.loadUser({ _id: 1, namespace: 'admin' })).resolves.toEqual({ id: 'b' });
        expect(b.loadUser).toHaveBeenCalledWith({ _id: 1, namespace: 'admin' });
        // a namespace that is not a string is ignored
        await expect(service.loadUser({ _id: 1, namespace: 42 as any })).resolves.toEqual({ id: 'a' });
    });

    test('loadUser() returns undefined if the provider does not find the user', async () => {
        const service = new AuthService().registerAuthProvider(provider('default'));
        await expect(service.loadUser({ _id: 1 })).resolves.toBeUndefined();
    });

    test('loadUser() throws a NotFoundException if there is no provider for the namespace', async () => {
        const service = new AuthService();
        await expect(service.loadUser({ namespace: 'unknown' })).rejects.toThrow(NotFoundException);
        await expect(service.loadUser({ namespace: 'unknown' })).rejects.toThrow('Provider unknown not found');
    });
});
