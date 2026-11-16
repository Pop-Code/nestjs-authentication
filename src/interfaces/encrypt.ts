/**
 * Encrypts (or hashes) the passwords, and checks a password against the stored value.
 *
 * The default implementation is {@link Encryptor} (aes-256-ctr). Give your own with the `encryptor` option
 * of the {@link AuthModule} (e.g. bcrypt or argon2), and inject it with {@link InjectEncryptor}.
 */
export interface IEncryptor {
    /** Returns the value to store for a password. */
    encrypt: (value: string) => string | Promise<string>;
    /**
     * Returns `true` if the password matches the stored value.
     * Required for salted hashes (bcrypt, argon2...). If not implemented, the password is encrypted
     * and compared with the stored value in constant time.
     */
    compare?: (value: string, encrypted: string) => boolean | Promise<boolean>;
    /**
     * Returns `true` if this encryptor can check the stored value (e.g. it has its format).
     * Used by {@link MigratingEncryptor} to pick the encryptor of a stored value.
     */
    canVerify?: (encrypted: string) => boolean;
    /**
     * Returns `true` if the stored value should be encrypted again (older algorithm or parameters).
     * After a successful login, {@link EmailPasswordAuthProvider} then calls its `updatePasswordHash` option.
     */
    needsRehash?: (encrypted: string) => boolean;
}

/**
 * Options of the {@link Encryptor} (aes-256-ctr).
 */
export interface IEncryptorOptions {
    /** The initialization vector, 16 bytes as a hex string (32 characters). */
    iv: string;
    /** The key, 32 bytes as a hex string (64 characters). */
    key: string;
}
