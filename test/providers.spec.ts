import { EmailPasswordAuthProvider, EmailPasswordUser, Encryptor, IEncryptor, MemoryUserProvider } from '../src';
import { memoryAuthProvider } from './fixtures';

class User implements EmailPasswordUser {
    constructor(
        public _id: any,
        public email: string,
        public passwordEncrypted: string
    ) {}
    authSerialize() {
        return { _id: this._id };
    }
}

const encryptor = new Encryptor({
    key: '77c0c891a5a062694a5ef1fdcf3719fe460d9c6e7ad5bda8715e44fdb2c8ae85',
    iv: 'f62456b5e1604435e3a548002d8b8944'
});

describe('MemoryUserProvider', () => {
    const users = new MemoryUserProvider<User>();
    const user = new User(1, 'john@example.com', 'x');
    users.registerUser(user).registerUser(new User(2, 'jane@example.com', 'y'));

    test('findOne() finds a user by _id (as string)', async () => {
        await expect(users.findOne({ _id: 1 })).resolves.toBe(user);
        await expect(users.findOne({ _id: '1' })).resolves.toBe(user);
        await expect(users.findOne({ _id: 3 })).resolves.toBeUndefined();
    });

    test('findOne() finds a user by email', async () => {
        await expect(users.findOne({ email: 'john@example.com' })).resolves.toBe(user);
        await expect(users.findOne({ email: 'nobody@example.com' })).resolves.toBeUndefined();
        await expect(users.findOne({})).resolves.toBeUndefined();
    });

    test('removeUser() removes a user', async () => {
        const provider = new MemoryUserProvider<User>().registerUser(new User(5, 'a@b.c', 'z'));
        expect(provider.removeUser({ _id: 5 })).toBe(true);
        expect(provider.removeUser({ _id: 5 })).toBe(false);
        await expect(provider.findOne({ _id: 5 })).resolves.toBeUndefined();
    });
});

describe('EmailPasswordAuthProvider', () => {
    const users = new MemoryUserProvider<User>();
    const user = new User(1, 'john@example.com', encryptor.encrypt('secret'));
    users.registerUser(user);

    test('getName()', () => {
        expect(memoryAuthProvider('default', users, encryptor).getName()).toBe('default');
    });

    test('loadUser() checks the password', async () => {
        const provider = memoryAuthProvider('default', users, encryptor);
        await expect(provider.loadUser({ email: user.email, password: 'secret' })).resolves.toBe(user);
        await expect(provider.loadUser({ email: user.email, password: 'wrong' })).resolves.toBeUndefined();
        await expect(provider.loadUser({ email: 'nobody@example.com', password: 'secret' })).resolves.toBeUndefined();
    });

    test('loadUser() loads by _id without password (session / token payload)', async () => {
        const provider = memoryAuthProvider('default', users, encryptor);
        await expect(provider.loadUser({ _id: 1 })).resolves.toBe(user);
        await expect(provider.loadUser({ _id: 1, password: 'wrong' })).resolves.toBeUndefined();
    });

    test('loadUser() uses the compare() method of a custom encryptor', async () => {
        const custom: IEncryptor = {
            encrypt: jest.fn(async (v: string) => `hash:${v}`),
            compare: jest.fn(async (v: string, hash: string) => hash === `hash:${v}`)
        };
        const hashed = new MemoryUserProvider<User>().registerUser(new User(1, 'a@b.c', 'hash:secret'));
        const provider = memoryAuthProvider('default', hashed, custom);
        await expect(provider.loadUser({ email: 'a@b.c', password: 'secret' })).resolves.toBeInstanceOf(User);
        await expect(provider.loadUser({ email: 'a@b.c', password: 'wrong' })).resolves.toBeUndefined();
        expect(custom.compare).toHaveBeenCalledWith('secret', 'hash:secret');
        expect(custom.encrypt).not.toHaveBeenCalled();
    });

    test('loadUser() encrypts and compares with a custom encryptor without compare()', async () => {
        const custom: IEncryptor = { encrypt: async (v: string) => v.toUpperCase() };
        const plain = new MemoryUserProvider<User>().registerUser(new User(1, 'a@b.c', 'SECRET'));
        const provider = memoryAuthProvider('default', plain, custom);
        await expect(provider.loadUser({ email: 'a@b.c', password: 'secret' })).resolves.toBeInstanceOf(User);
        await expect(provider.loadUser({ email: 'a@b.c', password: 'other' })).resolves.toBeUndefined();
    });

    test('loadUser() fails if the user has no stored password', async () => {
        const noPassword = new MemoryUserProvider<User>().registerUser(new User(1, 'a@b.c', undefined as any));
        const provider = memoryAuthProvider('default', noPassword, encryptor);
        await expect(provider.loadUser({ email: 'a@b.c', password: 'secret' })).resolves.toBeUndefined();
    });
});

describe('EmailPasswordAuthProvider calls', () => {
    const user = new User(1, 'john@example.com', encryptor.encrypt('secret'));

    test('findByEmail() on login and findById() with a payload: never the password nor the claims', async () => {
        const findById = jest.fn(async () => user);
        const findByEmail = jest.fn(async () => user);
        const provider = new EmailPasswordAuthProvider<User>({ encryptor, findById, findByEmail });
        await provider.loadUser({ email: user.email, password: 'secret' });
        expect(findByEmail).toHaveBeenLastCalledWith(user.email);
        await provider.loadUser({ sub: 1, namespace: 'default', iat: 1, exp: 2, scope: 'a' });
        expect(findById).toHaveBeenLastCalledWith(1);
    });
});
