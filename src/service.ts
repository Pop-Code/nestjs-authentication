import { Injectable, NotFoundException } from '@nestjs/common';
import { createCipheriv } from 'crypto';
import { Console, Command } from 'nestjs-console';
import { IJwtPayload } from './interfaces/jwt.payload';
import { IAuthProvider } from './interfaces/provider';
import { IEncryptOptions, IEncrypt } from './interfaces/encrypt';

@Injectable()
@Console()
export class AuthService implements IEncrypt {
    protected readonly authProviders = new Map<string, IAuthProvider<any>>();
    constructor(protected options: IEncryptOptions) {}

    @Command({
        command: 'password <password>',
        description: 'Encrypt a password'
    })
    encryptCli(value: string) {
        process.stdout.write(this.encrypt(value));
        process.exit(0);
    }

    encrypt(value: string) {
        const cipher = createCipheriv(
            'aes-256-ctr',
            Buffer.from(this.options.key, 'hex'),
            Buffer.from(this.options.iv, 'hex')
        );
        let crypted = cipher.update(value, 'utf8', 'hex');
        crypted += cipher.final('hex');
        return crypted;
    }

    registerAuthProvider<U = any>(provider: IAuthProvider<U>) {
        this.authProviders.set(provider.getName(), provider);
        return this;
    }

    getAuthProvider<U = any>(namespace: string): IAuthProvider<U> {
        return this.authProviders.get(namespace);
    }

    async loadUser(data: any) {
        const provider = this.getAuthProvider(data.namespace);
        if (!provider) {
            throw new NotFoundException(`Invalid namespace: Provider "${data.namespace}" not found`);
        }
        const user = await provider.loadUser(data);
        return user;
    }

    validateUser(payload: IJwtPayload): Promise<any> {
        return this.loadUser({ _id: payload._id, namespace: payload.namespace });
    }
}
