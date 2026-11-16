import { timingSafeEqual } from 'crypto';

import { IEncryptor } from '../interfaces/encrypt';

/**
 * Migrates the stored passwords to a new encryptor, one user at a time, on login:
 *
 * - new passwords are encrypted with `current`
 * - a stored value is checked with the first encryptor that can verify it (`canVerify()`), `current` first
 * - `needsRehash()` is `true` for the values of the previous encryptors (and the ones `current` wants to rehash),
 *   so {@link EmailPasswordAuthProvider} stores the password again with `current` after a successful login
 *   (with its `updatePasswordHash` option)
 *
 * ```ts
 * AuthModule.forRoot({
 *     encryptor: new MigratingEncryptor(new ScryptEncryptor(), [new Encryptor({ key, iv })])
 * });
 * ```
 */
export class MigratingEncryptor implements IEncryptor {
    constructor(
        protected readonly current: IEncryptor,
        protected readonly legacy: IEncryptor[]
    ) {}

    encrypt(value: string): string | Promise<string> {
        return this.current.encrypt(value);
    }

    /** Returns the encryptor of a stored value: the first one that can verify it, `current` if none says so. */
    protected getEncryptor(encrypted: string): IEncryptor | undefined {
        if (this.current.canVerify?.(encrypted) ?? false) {
            return this.current;
        }
        return (
            this.legacy.find((e) => e.canVerify?.(encrypted) ?? false) ??
            (this.current.canVerify ? undefined : this.current)
        );
    }

    canVerify(encrypted: string): boolean {
        return this.getEncryptor(encrypted) !== undefined;
    }

    async compare(value: string, encrypted: string): Promise<boolean> {
        const encryptor = this.getEncryptor(encrypted);
        if (encryptor === undefined) {
            return false;
        }
        if (typeof encryptor.compare === 'function') {
            return await encryptor.compare(value, encrypted);
        }
        const actual = Buffer.from(await encryptor.encrypt(value));
        const expected = Buffer.from(encrypted);
        return actual.length === expected.length && timingSafeEqual(actual, expected);
    }

    needsRehash(encrypted: string): boolean {
        const encryptor = this.getEncryptor(encrypted);
        if (encryptor !== this.current) {
            return true;
        }
        return this.current.needsRehash?.(encrypted) ?? false;
    }
}
