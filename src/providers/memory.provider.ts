import { Injectable } from '@nestjs/common';

import { MemoryUser } from '../classes/memory.user';
import { IUserProvider } from '../interfaces/provider';

@Injectable()
export class MemoryUserProvider<U extends MemoryUser> implements IUserProvider<U> {
    private readonly users: Map<string, U> = new Map();

    findOne<S extends { [key in keyof U]: any }>(data: S): Promise<U> {
        if (data._id) {
            return Promise.resolve(this.users.get(data._id.toString()));
        } else {
            if (!data.email) {
                return;
            }
            const users = Array.from(this.users.values());
            return Promise.resolve(users.find((u) => u.email === data.email));
        }
    }

    registerUser(user: U): MemoryUserProvider<U> {
        this.users.set(user._id.toString(), user);
        return this;
    }
}
