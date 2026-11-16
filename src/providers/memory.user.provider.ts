import { Injectable } from '@nestjs/common';

import { MemoryUser } from '../classes/memory.user';
import { IUserProvider } from '../interfaces/provider';

/**
 * Stores {@link MemoryUser} users in memory. Useful for tests, prototypes and a few static users.
 */
@Injectable()
export class MemoryUserProvider<U extends MemoryUser> implements IUserProvider<U> {
    private readonly users: Map<string, U> = new Map();

    /** Finds a user by `_id`, or by `email` if the query has no `_id`. */
    async findOne(query: Record<string, unknown>): Promise<U | undefined> {
        if (query._id !== undefined && query._id !== null) {
            return this.users.get(String(query._id));
        }
        if (typeof query.email !== 'string') {
            return;
        }
        for (const user of this.users.values()) {
            if (user.email === query.email) {
                return user;
            }
        }
    }

    /** Adds a user, or replaces the user with the same `_id`. */
    registerUser(user: U): this {
        this.users.set(String(user._id), user);
        return this;
    }

    /** Sets the encrypted password of a user. */
    updatePassword(user: U, passwordEncrypted: string): void {
        user.passwordEncrypted = passwordEncrypted;
    }

    /** Removes a user. Returns `true` if it existed. */
    removeUser(user: Pick<U, '_id'>): boolean {
        return this.users.delete(String(user._id));
    }
}
