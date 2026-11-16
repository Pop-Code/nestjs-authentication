import { timingSafeEqual } from 'crypto';

import { DEFAULT_NAMESPACE } from '../constants';
import { AuthUserPayload, getPayloadUserId } from '../interfaces/auth.user';
import { IEncryptor } from '../interfaces/encrypt';
import { IAuthProvider } from '../interfaces/provider';

/** A value, or a promise of it. */
export type MaybePromise<T> = T | Promise<T>;

/** The data given to {@link EmailPasswordAuthProvider.loadUser}: credentials, or a session / token payload. */
export interface EmailPasswordCredentials {
    email?: string;
    password?: string;
    /** The id of the user (a payload): `sub`, `_id` or `id`. */
    sub?: unknown;
    _id?: unknown;
    id?: unknown;
    namespace?: string;
    [key: string]: unknown;
}

/**
 * Options of the {@link EmailPasswordAuthProvider}: how to find and read your users, whatever their shape.
 *
 * @typeParam User your user type
 */
export interface EmailPasswordAuthProviderOptions<User> {
    /** The namespace of the provider. Default `default`. */
    namespace?: string;
    /** Checks the passwords: the {@link ENCRYPTOR} (inject it), e.g. a {@link ScryptEncryptor}. */
    encryptor: IEncryptor;
    /** Returns the user of an id (from a session or a token), or `undefined`. */
    findById: (id: any) => MaybePromise<User | undefined | null>;
    /** Returns the user of an email (login), or `undefined`. */
    findByEmail: (email: string) => MaybePromise<User | undefined | null>;
    /** Returns the id of a user, stored in the sessions and the tokens. Default: `user._id ?? user.id`. */
    getId?: (user: User) => unknown;
    /** Returns the stored password hash of a user. Default: `user.passwordEncrypted ?? user.passwordHash`. */
    getPasswordHash?: (user: User) => string | undefined | null;
    /**
     * Stores a new password hash, after a successful login when the encryptor says the stored one needs a rehash
     * (see {@link MigratingEncryptor}). Optional.
     */
    updatePasswordHash?: (user: User, passwordHash: string) => MaybePromise<void>;
}

const defaultGetId = (user: any) => user?._id ?? user?.id;
const defaultGetPasswordHash = (user: any) => user?.passwordEncrypted ?? user?.passwordHash;

/**
 * The auth provider of the users who log in with an email and a password. Your users keep their shape: give the
 * functions that find and read them.
 *
 * ```ts
 * new EmailPasswordAuthProvider<UserEntity>({
 *     encryptor,
 *     findById: (id) => users.findOneBy({ id }),
 *     findByEmail: (email) => users.findOneBy({ email }),
 *     getId: (user) => user.id,
 *     getPasswordHash: (user) => user.passwordHash
 * });
 * ```
 *
 * - login (`{ email, password }`): `findByEmail()`, then checks the password against the hash with the encryptor
 *   (and stores a new hash with `updatePasswordHash()` if the encryptor says it needs a rehash)
 * - session or token payload (`{ sub, namespace }`): `findById()`
 * - the payload of a user is `{ sub: getId(user), namespace }`
 *
 * @typeParam User your user type
 */
export class EmailPasswordAuthProvider<User = any> implements IAuthProvider<User, EmailPasswordCredentials> {
    protected readonly options: Required<Omit<EmailPasswordAuthProviderOptions<User>, 'updatePasswordHash'>> &
        Pick<EmailPasswordAuthProviderOptions<User>, 'updatePasswordHash'>;

    constructor(options: EmailPasswordAuthProviderOptions<User>) {
        if (options.encryptor === undefined || options.encryptor === null) {
            throw new Error('EmailPasswordAuthProvider requires an encryptor');
        }
        // `??` and not a spread: an option set to `undefined` keeps its default
        this.options = {
            ...options,
            namespace: options.namespace ?? DEFAULT_NAMESPACE,
            getId: options.getId ?? defaultGetId,
            getPasswordHash: options.getPasswordHash ?? defaultGetPasswordHash
        };
    }

    getName(): string {
        return this.options.namespace;
    }

    /** Returns `{ sub: getId(user), namespace }`. */
    serializeUser(user: User): AuthUserPayload {
        const id = this.options.getId(user);
        if (id === undefined || id === null) {
            throw new Error(`EmailPasswordAuthProvider "${this.getName()}": the user has no id (set the getId option)`);
        }
        return { sub: id, namespace: this.getName() };
    }

    async loadUser(data: EmailPasswordCredentials): Promise<User | undefined> {
        if (typeof data.password === 'string') {
            const user =
                typeof data.email === 'string'
                    ? await this.options.findByEmail(data.email)
                    : await this.findById(getPayloadUserId(data));
            if (user === undefined || user === null || !(await this.checkPassword(user, data.password))) {
                return undefined;
            }
            await this.rehashPassword(user, data.password);
            return user;
        }
        const id = getPayloadUserId(data);
        if (id !== undefined && id !== null) {
            return await this.findById(id);
        }
        return typeof data.email === 'string' ? ((await this.options.findByEmail(data.email)) ?? undefined) : undefined;
    }

    protected async findById(id: unknown): Promise<User | undefined> {
        if (id === undefined || id === null) {
            return undefined;
        }
        return (await this.options.findById(id)) ?? undefined;
    }

    /** Uses `encryptor.compare()` if implemented, else encrypts the password and compares in constant time. */
    protected async checkPassword(user: User, password: string): Promise<boolean> {
        const hash = this.options.getPasswordHash(user);
        if (typeof hash !== 'string' || hash === '') {
            return false;
        }
        const { encryptor } = this.options;
        if (typeof encryptor.compare === 'function') {
            return await encryptor.compare(password, hash);
        }
        const actual = Buffer.from(await encryptor.encrypt(password));
        const expected = Buffer.from(hash);
        return actual.length === expected.length && timingSafeEqual(actual, expected);
    }

    /** Stores a new hash if the encryptor says the stored one needs a rehash and `updatePasswordHash` is set. */
    protected async rehashPassword(user: User, password: string): Promise<void> {
        const { encryptor, updatePasswordHash, getPasswordHash } = this.options;
        const hash = getPasswordHash(user);
        if (
            typeof encryptor.needsRehash === 'function' &&
            updatePasswordHash !== undefined &&
            typeof hash === 'string'
        ) {
            if (encryptor.needsRehash(hash)) {
                await updatePasswordHash(user, await encryptor.encrypt(password));
            }
        }
    }
}
