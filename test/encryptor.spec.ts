import { Encryptor } from '../src';

const key = '77c0c891a5a062694a5ef1fdcf3719fe460d9c6e7ad5bda8715e44fdb2c8ae85';
const iv = 'f62456b5e1604435e3a548002d8b8944';
const encryptor = new Encryptor({ key, iv });

describe('Encryptor', () => {
    test('The Encryptor must encrypt a value and give same result multiple times', async () => {
        const password = 'Hello, I am a strong * password * encrypted';
        const encrypted = 'b28d5453627e7f65fa1e0830c5e7d81d449d7f55a2e7266330148587fdeb623e28a6f135b6d1c411f35975';
        for (let i = 0; i < 1000; i++) {
            expect(encryptor.encrypt(password)).toEqual(encrypted);
        }
    });

    test('The Encryptor must encrypt two different value and give different results', async () => {
        const password1 = 'firstpassword';
        const password2 = 'differentpassword';
        expect(encryptor.encrypt(password1)).not.toEqual(encryptor.encrypt(password2));
    });

    test('compare() checks a value against an encrypted value', () => {
        const encrypted = encryptor.encrypt('password');
        expect(encryptor.compare('password', encrypted)).toBe(true);
        expect(encryptor.compare('passwork', encrypted)).toBe(false);
        expect(encryptor.compare('password', encrypted.slice(2))).toBe(false);
        expect(encryptor.compare('password', '')).toBe(false);
    });

    test('The Encryptor rejects a key or an iv of the wrong size', () => {
        expect(() => new Encryptor({ key: 'abcd', iv })).toThrow('the key must be 32 bytes');
        expect(() => new Encryptor({ key, iv: 'abcd' })).toThrow('the iv must be 16 bytes');
    });
});
