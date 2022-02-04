import { MemoryUser } from '../classes/memory.user';
import { IEncryptor } from '../interfaces/encrypt';
import { IUserProvider } from '../interfaces/provider';
import { AuthProvider } from './auth.provider';

export class AuthMemoryUserProvider<User extends MemoryUser> extends AuthProvider<User> {
    constructor(providerName: string, userProvider: IUserProvider<User>, protected readonly encryptor: IEncryptor) {
        super(providerName, userProvider);
    }

    getName(): string {
        return this.providerName;
    }

    async loadUser(data: Partial<User>): Promise<User | undefined> {
        const user = await this.userProvider.findOne(this.createUserQuery(data));
        return this.userChecker(data, user);
    }

    protected userChecker(data: Partial<User> & { password?: string }, user?: User): User | undefined {
        if (user === undefined) {
            return;
        }
        if (typeof data.password === 'string') {
            const encrypted = this.encryptor.encrypt(data.password);
            if (encrypted !== user.passwordEncrypted) {
                return;
            }
        }
        return user;
    }

    protected createUserQuery(data: Partial<User> & { password?: string }): Record<string, unknown> {
        if (data._id !== undefined) {
            return data;
        }
        return { email: data.email, password: data.password };
    }
}
