import { IAuthProvider, IUserProvider } from '../interfaces/provider';

/**
 * Base class of an auth provider: finds the user with a {@link IUserProvider}, then checks it.
 *
 * @typeParam User the user
 * @typeParam Data the data given to `loadUser()` (credentials, session or token payload)
 */
export abstract class AuthProvider<User, Data extends object = Partial<User>> implements IAuthProvider<User, Data> {
    constructor(
        protected readonly providerName: string,
        protected readonly userProvider: IUserProvider<User>
    ) {}

    getName(): string {
        return this.providerName;
    }

    getProvider(): IUserProvider<User> {
        return this.userProvider;
    }

    /** Returns the user if it matches the data (e.g. the password), or `undefined`. */
    protected abstract userChecker(data: Data, user?: User): User | undefined | Promise<User | undefined>;

    /** Returns the query given to {@link IUserProvider.findOne}. */
    protected abstract createUserQuery(data: Data): Record<string, unknown>;

    async loadUser(data: Data): Promise<User | undefined> {
        const user = await this.userProvider.findOne(this.createUserQuery(data));
        return await this.userChecker(data, user);
    }
}
