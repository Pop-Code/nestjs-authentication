import { Injectable } from '@nestjs/common';

import { IEmailPassword } from '../interfaces/emailpassword';
import { IEncrypt } from '../interfaces/encrypt';
import { IAuthProvider, IUserProvider } from '../interfaces/provider';

@Injectable()
export class AuthUserProvider<T extends IEmailPassword> implements IAuthProvider<T> {
    constructor(
        private readonly providerName: string,
        private readonly userProvider: IUserProvider<T>,
        private readonly encryptor: IEncrypt
    ) {}

    async loadUser(data: { password: string; [key: string]: any }): Promise<T> {
        const query = { ...data };
        delete query.password;
        const entity = await this.userProvider.findOne(query);
        if (entity && data.password) {
            const encrypted = this.encryptor.encrypt(data.password);
            if (encrypted === entity.passwordEncrypted) {
                return entity;
            }
        }
        if (!entity) {
            return;
        }
        return entity;
    }

    getName(): string {
        return this.providerName;
    }
}
