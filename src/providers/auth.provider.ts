import { IAuthProvider, IUserProvider } from '../interfaces/provider';

export abstract class AuthProvider<User> implements IAuthProvider<User> {
    constructor(protected readonly providerName: string, protected readonly userProvider: IUserProvider<User>) {}

    getName(): string {
        return this.providerName;
    }

    getProvider(): IUserProvider<User> {
        return this.userProvider;
    }

    protected abstract userChecker(data: Partial<User>, user?: User): User | undefined;

    protected abstract createUserQuery(data: Partial<User>): Record<string, unknown>;

    async loadUser(data: Partial<User>): Promise<User | undefined> {
        const query = this.createUserQuery(data);
        const user = await this.userProvider.findOne(query);
        if (user === undefined) {
            return;
        }
        return this.userChecker(data, user);
    }
}
