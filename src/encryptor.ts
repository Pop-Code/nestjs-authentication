import { Injectable } from '@nestjs/common';
import { createCipheriv, timingSafeEqual } from 'crypto';

import { IEncryptor, IEncryptorOptions } from './interfaces/encrypt';

/**
 * Encrypts values with aes-256-ctr and a fixed key and iv: the same value always gives the same result,
 * so an encrypted password can be compared with the stored one.
 *
 * Not recommended for new applications: a fixed key and iv leak the length and the common prefixes of the passwords,
 * and anyone with the key can decrypt them. Use {@link ScryptEncryptor}, and {@link MigratingEncryptor} to migrate.
 *
 * This is the default {@link IEncryptor}: provided by the {@link AuthModule} when the `encrypt` option is set,
 * with the `Encryptor` class and, unless the `encryptor` option is set, the {@link ENCRYPTOR} token.
 */
@Injectable()
export class Encryptor implements IEncryptor {
    protected readonly key: Buffer;
    protected readonly iv: Buffer;

    /**
     * @throws Error if the key is not 32 bytes or the iv is not 16 bytes (hex strings)
     */
    constructor(protected options: IEncryptorOptions) {
        this.key = Buffer.from(options.key, 'hex');
        this.iv = Buffer.from(options.iv, 'hex');
        if (this.key.length !== 32) {
            throw new Error('Encryptor: the key must be 32 bytes, as a hex string of 64 characters');
        }
        if (this.iv.length !== 16) {
            throw new Error('Encryptor: the iv must be 16 bytes, as a hex string of 32 characters');
        }
    }

    /** Returns the encrypted value as a hex string. */
    encrypt(value: string): string {
        const cipher = createCipheriv('aes-256-ctr', this.key, this.iv);
        return cipher.update(value, 'utf8', 'hex') + cipher.final('hex');
    }

    /** Returns `true` if the value is a hex string (the format of the values encrypted by this encryptor). */
    canVerify(encrypted: string): boolean {
        return typeof encrypted === 'string' && /^(?:[0-9a-f]{2})*$/.test(encrypted);
    }

    /** Returns `true` if the value encrypted matches `encrypted` (constant time comparison). */
    compare(value: string, encrypted: string): boolean {
        const actual = Buffer.from(this.encrypt(value));
        const expected = Buffer.from(encrypted);
        return actual.length === expected.length && timingSafeEqual(actual, expected);
    }
}
