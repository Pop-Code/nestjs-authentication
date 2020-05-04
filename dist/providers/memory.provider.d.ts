import { MemoryUser } from '../classes/memory.user';
import { IUserProvider } from '../interfaces/provider';
export declare class MemoryUserProvider<U extends MemoryUser> implements IUserProvider<U> {
    private readonly users;
    findOne<S extends {
        [key in keyof U]: any;
    }>(data: S): Promise<U>;
    registerUser(user: U): MemoryUserProvider<U>;
}
//# sourceMappingURL=memory.provider.d.ts.map