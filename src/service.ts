import { Injectable, NotFoundException } from '@nestjs/common';
import { createCipheriv } from 'crypto';
import { Command, Console } from 'nestjs-console';

import { IEncrypt, IEncryptOptions } from './interfaces/encrypt';
import { IJwtPayload } from './interfaces/jwt.payload';
import { IAuthProvider } from './interfaces/provider';

@Injectable()
@Console()
export class AuthService implements IEncrypt {
    protected readonly authProviders = new Map<string, IAuthProvider<any>>();
    constructor(protected options: IEncryptOptions) {}

    @Command({
        command: 'password <password>',
        description: 'Encrypt a password'
    })
    encryptCli(value: string): string {
        const encrypted = this.encrypt(value);
        // eslint-disable-next-line no-console
        console.log(encrypted);
        return encrypted;
    }

    encrypt(value: string): string {
        const cipher = createCipheriv(
            'aes-256-ctr',
            Buffer.from(this.options.key, 'hex'),
            Buffer.from(this.options.iv, 'hex')
        );
        let crypted = cipher.update(value, 'utf8', 'hex');
        crypted += cipher.final('hex');
        return crypted;
    }

    registerAuthProvider<U = any>(provider: IAuthProvider<U>): this {
        this.authProviders.set(provider.getName(), provider);
        return this;
    }

    getAuthProvider<U = any>(namespace: string): IAuthProvider<U> {
        return this.authProviders.get(namespace);
    }

    async loadUser<U = any>(data: any): Promise<U> {
        const provider = this.getAuthProvider(data.namespace);
        if (!provider) {
            throw new NotFoundException(`Invalid namespace: Provider "${data.namespace}" not found`);
        }
        const user = await provider.loadUser(data);
        return user;
    }

    validateUser<U = any>(payload: IJwtPayload): Promise<U> {
        return this.loadUser({ _id: payload._id, namespace: payload.namespace });
    }
}
