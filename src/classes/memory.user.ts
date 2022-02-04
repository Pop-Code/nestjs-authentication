import { IAuthUser } from '../interfaces/auth.user';

export interface MemoryUser extends IAuthUser {
    _id: any;
    email: string;
    passwordEncrypted: string;
}
