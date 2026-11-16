// users/users.service.ts
import { Injectable } from '@nestjs/common';
import { randomUUID } from 'crypto';

import { IEncryptor, InjectEncryptor } from '../../../src';
import { User } from './user';

@Injectable()
export class UsersService {
    private readonly users = new Map<string, User>();

    constructor(@InjectEncryptor() private readonly encryptor: IEncryptor) {}

    async register(email: string, password: string, roles: string[] = []): Promise<User> {
        const user = new User(randomUUID(), email, await this.encryptor.encrypt(password), roles);
        this.users.set(user.id, user);
        return user;
    }

    async findById(id: string): Promise<User | undefined> {
        return this.users.get(id);
    }

    async findByEmail(email: string): Promise<User | undefined> {
        return [...this.users.values()].find((user) => user.email === email);
    }

    async updatePasswordHash(user: User, passwordHash: string): Promise<void> {
        user.passwordHash = passwordHash;
    }
}
