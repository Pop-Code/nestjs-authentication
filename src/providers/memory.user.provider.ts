import { Injectable } from '@nestjs/common';

import { MemoryUser } from '../classes/memory.user';
import { IUserProvider } from '../interfaces/provider';

@Injectable()
export class MemoryUserProvider<U extends MemoryUser> implements IUserProvider<U> {
    private readonly users: Map<string, U> = new Map();

    async findOne<S extends { [key in keyof U]: any }>(data: S): Promise<U | undefined> {
        if (data._id !== undefined) {
            return this.users.get(data._id.toString());
        } else {
            if (typeof data.email !== 'string') {
                return;
            }
            const users = Array.from(this.users.values());
            return users.find((u) => u.email === data.email);
        }
    }

    registerUser(user: U): MemoryUserProvider<U> {
        this.users.set(user._id.toString(), user);
        return this;
    }
}
