import { NotFoundException } from '@nestjs/common';

import { AuthService, UserSerializer } from '../src';

const run = (fn: (done: (...args: any[]) => void) => unknown) =>
    new Promise<any[]>((resolve) => {
        void fn((...args) => resolve(args));
    });

describe('UserSerializer', () => {
    const authService = new AuthService();
    const serializer = new UserSerializer(authService);

    afterEach(() => jest.restoreAllMocks());

    test('serializeUser() stores authSerialize()', async () => {
        const user = { authSerialize: () => ({ _id: '1', namespace: 'admin' }) };
        await expect(run((done) => serializer.serializeUser(user, done))).resolves.toEqual([
            null,
            { _id: '1', namespace: 'admin' }
        ]);
    });

    test('serializeUser() stores nothing without a user', async () => {
        await expect(run((done) => serializer.serializeUser(undefined, done))).resolves.toEqual([null]);
        await expect(run((done) => serializer.serializeUser(null, done))).resolves.toEqual([null]);
    });

    test('deserializeUser() loads the user', async () => {
        const user = { id: '1' };
        jest.spyOn(authService, 'loadUser').mockResolvedValue(user);
        await expect(run((done) => serializer.deserializeUser({ _id: '1' }, done))).resolves.toEqual([null, user]);
    });

    test('deserializeUser() returns false if the user does not exist anymore', async () => {
        jest.spyOn(authService, 'loadUser').mockResolvedValue(undefined);
        await expect(run((done) => serializer.deserializeUser({ _id: '1' }, done))).resolves.toEqual([null, false]);
    });

    test('deserializeUser() returns false if the provider does not exist anymore', async () => {
        jest.spyOn(authService, 'loadUser').mockRejectedValue(new NotFoundException());
        await expect(run((done) => serializer.deserializeUser({ _id: '1' }, done))).resolves.toEqual([null, false]);
    });

    test('deserializeUser() passes the other errors', async () => {
        const error = new Error('database down');
        jest.spyOn(authService, 'loadUser').mockRejectedValue(error);
        await expect(run((done) => serializer.deserializeUser({ _id: '1' }, done))).resolves.toEqual([error]);
    });
});
