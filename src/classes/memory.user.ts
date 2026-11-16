import { IAuthUser } from '../interfaces/auth.user';

/**
 * A user handled by {@link MemoryUserProvider} and {@link AuthMemoryUserProvider}.
 */
export interface MemoryUser extends IAuthUser {
    /** The id of the user (`toString()` is used as key). */
    _id: any;
    email: string;
    /** The password encrypted with the {@link Encryptor}. */
    passwordEncrypted: string;
}
