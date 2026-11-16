import { timingSafeEqual } from 'crypto';

import { MemoryUser } from '../classes/memory.user';
import { IEncryptor } from '../interfaces/encrypt';
import { IUserProvider } from '../interfaces/provider';
import { AuthProvider } from './auth.provider';

/** The data given to {@link AuthMemoryUserProvider.loadUser}: credentials, or a session / token payload. */
export type MemoryUserCredentials<User extends MemoryUser = MemoryUser> = Partial<User> & { password?: string };

/**
 * An auth provider for {@link MemoryUser} users: finds the user by `_id` or `email`,
 * and checks the password with the given {@link IEncryptor} when the data has one.
 */
export class AuthMemoryUserProvider<User extends MemoryUser> extends AuthProvider<User, MemoryUserCredentials<User>> {
    /**
     * @param providerName the namespace
     * @param userProvider finds the users
     * @param encryptor checks the passwords, typically the one injected with {@link InjectEncryptor}
     */
    constructor(
        providerName: string,
        userProvider: IUserProvider<User>,
        protected readonly encryptor: IEncryptor
    ) {
        super(providerName, userProvider);
    }

    protected async userChecker(data: MemoryUserCredentials<User>, user?: User): Promise<User | undefined> {
        if (user === undefined || user === null) {
            return;
        }
        if (typeof data.password === 'string' && !(await this.checkPassword(data.password, user.passwordEncrypted))) {
            return;
        }
        return user;
    }

    /** Uses `encryptor.compare()` if implemented, else encrypts the password and compares in constant time. */
    protected async checkPassword(password: string, encrypted: string): Promise<boolean> {
        if (typeof encrypted !== 'string') {
            return false;
        }
        if (typeof this.encryptor.compare === 'function') {
            return await this.encryptor.compare(password, encrypted);
        }
        const actual = Buffer.from(await this.encryptor.encrypt(password));
        const expected = Buffer.from(encrypted);
        return actual.length === expected.length && timingSafeEqual(actual, expected);
    }

    protected createUserQuery(data: MemoryUserCredentials<User>): Record<string, unknown> {
        if (data._id !== undefined) {
            return { ...data };
        }
        return { email: data.email, password: data.password };
    }
}
