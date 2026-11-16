import { Inject, Injectable, Optional } from '@nestjs/common';

import { IUserProvider } from '../interfaces/provider';

/** Options of the {@link MemoryUserProvider}: how to read your users. */
export interface MemoryUserProviderOptions<User> {
    /** Default: `user._id ?? user.id`. */
    getId?: (user: User) => unknown;
    /** Default: `user.email`. */
    getEmail?: (user: User) => string | undefined;
    /** Default: sets `passwordEncrypted` if the user has it, else `passwordHash`. */
    setPasswordHash?: (user: User, passwordHash: string) => void;
}

/** Injection token of the options of a {@link MemoryUserProvider} created by dependency injection. */
export const MEMORY_USER_PROVIDER_OPTIONS = 'nestjs-authentication:memory-user-provider.options';

/**
 * Keeps users in memory: for tests, prototypes and a few static users. Your users keep their shape.
 *
 * ```ts
 * const users = new MemoryUserProvider<User>({ getId: (u) => u.id }).registerUser(john);
 * new EmailPasswordAuthProvider<User>({
 *     encryptor,
 *     findById: (id) => users.findById(id),
 *     findByEmail: (email) => users.findByEmail(email),
 *     updatePasswordHash: (user, hash) => users.updatePassword(user, hash)
 * });
 * ```
 */
@Injectable()
export class MemoryUserProvider<User = any> implements IUserProvider<User> {
    private readonly users: Map<string, User> = new Map();
    protected readonly getId: (user: User) => unknown;
    protected readonly getEmail: (user: User) => string | undefined;
    protected readonly setPasswordHash: (user: User, passwordHash: string) => void;

    constructor(@Optional() @Inject(MEMORY_USER_PROVIDER_OPTIONS) options: MemoryUserProviderOptions<User> = {}) {
        this.getId = options?.getId ?? ((user: any) => user?._id ?? user?.id);
        this.getEmail = options?.getEmail ?? ((user: any) => user?.email);
        this.setPasswordHash =
            options?.setPasswordHash ??
            ((user: any, hash: string) => {
                if ('passwordHash' in user && !('passwordEncrypted' in user)) {
                    user.passwordHash = hash;
                } else {
                    user.passwordEncrypted = hash;
                }
            });
    }

    async findById(id: unknown): Promise<User | undefined> {
        return id === undefined || id === null ? undefined : this.users.get(String(id));
    }

    async findByEmail(email: string): Promise<User | undefined> {
        for (const user of this.users.values()) {
            if (this.getEmail(user) === email) {
                return user;
            }
        }
        return undefined;
    }

    /** Finds a user by `_id`, or by `email` if the query has no `_id` (the {@link IUserProvider} of 0.4). */
    async findOne(query: Record<string, unknown>): Promise<User | undefined> {
        if (query._id !== undefined && query._id !== null) {
            return await this.findById(query._id);
        }
        return typeof query.email === 'string' ? await this.findByEmail(query.email) : undefined;
    }

    /** Adds a user, or replaces the user with the same id. */
    registerUser(user: User): this {
        this.users.set(String(this.getId(user)), user);
        return this;
    }

    /** Sets the password hash of a user. */
    updatePassword(user: User, passwordHash: string): void {
        this.setPasswordHash(user, passwordHash);
    }

    /** Removes a user. Returns `true` if it existed. */
    removeUser(user: Partial<User>): boolean {
        return this.users.delete(String(this.getId(user as User)));
    }
}
