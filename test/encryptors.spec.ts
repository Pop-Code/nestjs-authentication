import { EmailPasswordAuthProvider, Encryptor, MemoryUserProvider, MigratingEncryptor, ScryptEncryptor } from '../src';
import { iv, key, memoryAuthProvider, User } from './fixtures';

// a low cost keeps the tests fast
const scrypt = new ScryptEncryptor({ cost: 2 ** 10 });
const aes = new Encryptor({ key, iv });

describe('ScryptEncryptor', () => {
    test('hashes with a random salt and the parameters', async () => {
        const a = await scrypt.encrypt('secret');
        const b = await scrypt.encrypt('secret');
        expect(a).toMatch(/^\$scrypt\$ln=10,r=8,p=1\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$/);
        expect(a).not.toBe(b);
        await expect(scrypt.compare('secret', a)).resolves.toBe(true);
        await expect(scrypt.compare('secret', b)).resolves.toBe(true);
        await expect(scrypt.compare('wrong', a)).resolves.toBe(false);
    });

    test('rejects values that are not scrypt hashes', async () => {
        await expect(scrypt.compare('secret', aes.encrypt('secret'))).resolves.toBe(false);
        await expect(scrypt.compare('secret', '$scrypt$ln=10,r=8,p=1$abc$')).resolves.toBe(false);
        await expect(scrypt.compare('secret', undefined as any)).resolves.toBe(false);
        expect(scrypt.canVerify(aes.encrypt('secret'))).toBe(false);
        expect(scrypt.canVerify(undefined as any)).toBe(false);
    });

    test('verifies the hashes of other parameters, and says they need a rehash', async () => {
        const old = await new ScryptEncryptor({ cost: 2 ** 9, keyLength: 16 }).encrypt('secret');
        expect(scrypt.canVerify(old)).toBe(true);
        await expect(scrypt.compare('secret', old)).resolves.toBe(true);
        expect(scrypt.needsRehash(old)).toBe(true);
        expect(scrypt.needsRehash(await scrypt.encrypt('secret'))).toBe(false);
        expect(scrypt.needsRehash('not a hash')).toBe(true);
    });

    test('uses more than the default maxmem with the default cost', async () => {
        const strong = new ScryptEncryptor();
        await expect(strong.compare('secret', await strong.encrypt('secret'))).resolves.toBe(true);
    });

    test('rejects a cost that is not a power of 2', () => {
        expect(() => new ScryptEncryptor({ cost: 1000 })).toThrow('power of 2');
        expect(() => new ScryptEncryptor({ cost: 1 })).toThrow('power of 2');
    });
});

describe('MigratingEncryptor', () => {
    const migrating = new MigratingEncryptor(scrypt, [aes]);

    test('encrypts with the current encryptor', async () => {
        expect(scrypt.canVerify(await migrating.encrypt('secret'))).toBe(true);
    });

    test('verifies the legacy values, and says they need a rehash', async () => {
        const legacy = aes.encrypt('secret');
        expect(migrating.canVerify(legacy)).toBe(true);
        await expect(migrating.compare('secret', legacy)).resolves.toBe(true);
        await expect(migrating.compare('wrong', legacy)).resolves.toBe(false);
        expect(migrating.needsRehash(legacy)).toBe(true);

        const current = await scrypt.encrypt('secret');
        await expect(migrating.compare('secret', current)).resolves.toBe(true);
        expect(migrating.needsRehash(current)).toBe(false);
    });

    test('rejects the values no encryptor can verify', async () => {
        expect(migrating.canVerify('not hex nor scrypt')).toBe(false);
        await expect(migrating.compare('secret', 'not hex nor scrypt')).resolves.toBe(false);
        expect(migrating.needsRehash('not hex nor scrypt')).toBe(true);
    });

    test('legacy encryptors without compare() nor canVerify()', async () => {
        const upper = { encrypt: (v: string) => v.toUpperCase() };
        // current without canVerify is used for everything
        const m = new MigratingEncryptor(upper, []);
        await expect(m.compare('secret', 'SECRET')).resolves.toBe(true);
        await expect(m.compare('secret', 'OTHER')).resolves.toBe(false);
        expect(m.needsRehash('SECRET')).toBe(false);
    });
});

describe('EmailPasswordAuthProvider rehash', () => {
    test('stores the password with the current encryptor after a login with a legacy value', async () => {
        const user = new User('1', 'a@b.c', aes.encrypt('secret'));
        const users = new MemoryUserProvider<User>().registerUser(user);
        const update = jest.spyOn(users, 'updatePassword');
        const provider = memoryAuthProvider('default', users, new MigratingEncryptor(scrypt, [aes]));

        await expect(provider.loadUser({ email: 'a@b.c', password: 'wrong' })).resolves.toBeUndefined();
        expect(update).not.toHaveBeenCalled();

        await expect(provider.loadUser({ email: 'a@b.c', password: 'secret' })).resolves.toBe(user);
        expect(update).toHaveBeenCalledTimes(1);
        expect(scrypt.canVerify(user.passwordEncrypted)).toBe(true);

        // the next login uses the new hash, no rehash
        await expect(provider.loadUser({ email: 'a@b.c', password: 'secret' })).resolves.toBe(user);
        expect(update).toHaveBeenCalledTimes(1);
    });

    test('does nothing if the user provider cannot update the password', async () => {
        const user = new User('1', 'a@b.c', aes.encrypt('secret'));
        const provider = new EmailPasswordAuthProvider<User>({
            encryptor: new MigratingEncryptor(scrypt, [aes]),
            findById: async () => user,
            findByEmail: async () => user
        });
        await expect(provider.loadUser({ email: 'a@b.c', password: 'secret' })).resolves.toBe(user);
        expect(user.passwordEncrypted).toBe(aes.encrypt('secret'));
    });
});
