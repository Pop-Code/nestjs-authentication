import { IEmailPassword } from '../interfaces/emailpassword';
import { IEncrypt } from '../interfaces/encrypt';
import { IAuthProvider, IUserProvider } from '../interfaces/provider';
export declare class AuthUserProvider<T extends IEmailPassword> implements IAuthProvider<T> {
    private readonly providerName;
    private readonly userProvider;
    private readonly encryptor;
    constructor(providerName: string, userProvider: IUserProvider<T>, encryptor: IEncrypt);
    loadUser(data: {
        password: string;
        [key: string]: any;
    }): Promise<T>;
    getName(): string;
}
//# sourceMappingURL=auth.provider.d.ts.map