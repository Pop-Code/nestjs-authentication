import { IEncrypt, IEncryptOptions } from './interfaces/encrypt';
import { IJwtPayload } from './interfaces/jwt.payload';
import { IAuthProvider } from './interfaces/provider';
export declare class AuthService implements IEncrypt {
    protected options: IEncryptOptions;
    protected readonly authProviders: Map<string, IAuthProvider<any>>;
    constructor(options: IEncryptOptions);
    encryptCli(value: string): string;
    encrypt(value: string): string;
    registerAuthProvider<U = any>(provider: IAuthProvider<U>): this;
    getAuthProvider<U = any>(namespace: string): IAuthProvider<U>;
    loadUser<U = any>(data: any): Promise<U>;
    validateUser<U = any>(payload: IJwtPayload): Promise<U>;
}
//# sourceMappingURL=service.d.ts.map