import { randomBytes, scrypt, ScryptOptions, timingSafeEqual } from 'crypto';

import { IEncryptor } from '../interfaces/encrypt';

/** Options of the {@link ScryptEncryptor}. */
export interface ScryptEncryptorOptions {
    /** CPU / memory cost, a power of 2. Default `2 ** 16` (64 MiB with `r = 8`). */
    cost?: number;
    /** Block size. Default `8`. */
    blockSize?: number;
    /** Parallelization. Default `1`. */
    parallelization?: number;
    /** Salt length in bytes. Default `16`. */
    saltLength?: number;
    /** Hash length in bytes. Default `32`. */
    keyLength?: number;
}

const PREFIX = '$scrypt$';

function scryptAsync(password: string, salt: Buffer, keyLength: number, options: ScryptOptions): Promise<Buffer> {
    return new Promise((resolve, reject) =>
        scrypt(password, salt, keyLength, options, (err, key) => (err ? reject(err) : resolve(key)))
    );
}

/**
 * Hashes the passwords with scrypt (built in Node.js, no dependency), with a random salt per password.
 *
 * The stored value has the parameters, so they can be raised later (old hashes are still verified, and
 * {@link needsRehash} tells which ones to update): `$scrypt$ln=16,r=8,p=1$<salt>$<hash>` (base64).
 */
export class ScryptEncryptor implements IEncryptor {
    protected readonly cost: number;
    protected readonly blockSize: number;
    protected readonly parallelization: number;
    protected readonly saltLength: number;
    protected readonly keyLength: number;

    constructor(options: ScryptEncryptorOptions = {}) {
        this.cost = options.cost ?? 2 ** 16;
        this.blockSize = options.blockSize ?? 8;
        this.parallelization = options.parallelization ?? 1;
        this.saltLength = options.saltLength ?? 16;
        this.keyLength = options.keyLength ?? 32;
        if (!Number.isInteger(Math.log2(this.cost)) || this.cost < 2) {
            throw new Error('ScryptEncryptor: the cost must be a power of 2');
        }
    }

    protected scryptOptions(cost: number, blockSize: number, parallelization: number): ScryptOptions {
        // scrypt needs 128 * N * r bytes, more than the default maxmem (32 MiB) from N = 2 ** 15
        return { N: cost, r: blockSize, p: parallelization, maxmem: 256 * cost * blockSize + 1024 * 1024 };
    }

    async encrypt(value: string): Promise<string> {
        const salt = randomBytes(this.saltLength);
        const hash = await scryptAsync(
            value,
            salt,
            this.keyLength,
            this.scryptOptions(this.cost, this.blockSize, this.parallelization)
        );
        const params = `ln=${Math.log2(this.cost)},r=${this.blockSize},p=${this.parallelization}`;
        return `${PREFIX}${params}$${salt.toString('base64')}$${hash.toString('base64')}`;
    }

    protected parse(encrypted: string) {
        const match = /^\$scrypt\$ln=(\d+),r=(\d+),p=(\d+)\$([A-Za-z0-9+/=]+)\$([A-Za-z0-9+/=]+)$/.exec(encrypted);
        if (match === null) {
            return undefined;
        }
        const [, ln, r, p, salt, hash] = match;
        return {
            cost: 2 ** Number(ln),
            blockSize: Number(r),
            parallelization: Number(p),
            salt: Buffer.from(salt, 'base64'),
            hash: Buffer.from(hash, 'base64')
        };
    }

    canVerify(encrypted: string): boolean {
        return typeof encrypted === 'string' && this.parse(encrypted) !== undefined;
    }

    async compare(value: string, encrypted: string): Promise<boolean> {
        const parsed = typeof encrypted === 'string' ? this.parse(encrypted) : undefined;
        if (parsed === undefined || parsed.hash.length === 0) {
            return false;
        }
        const hash = await scryptAsync(
            value,
            parsed.salt,
            parsed.hash.length,
            this.scryptOptions(parsed.cost, parsed.blockSize, parsed.parallelization)
        );
        return timingSafeEqual(hash, parsed.hash);
    }

    needsRehash(encrypted: string): boolean {
        const parsed = this.parse(encrypted);
        return (
            parsed === undefined ||
            parsed.cost !== this.cost ||
            parsed.blockSize !== this.blockSize ||
            parsed.parallelization !== this.parallelization ||
            parsed.hash.length !== this.keyLength
        );
    }
}
