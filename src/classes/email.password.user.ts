import { IAuthUser } from '../interfaces/auth.user';

/**
 * The default shape of the users of {@link EmailPasswordAuthProvider} and {@link MemoryUserProvider}.
 * Not required: give the `getId` / `getPasswordHash` options for another shape.
 */
export interface EmailPasswordUser extends Partial<IAuthUser> {
    /** The id of the user. */
    _id: any;
    email: string;
    /** The password encrypted (hashed) with the encryptor: `await encryptor.encrypt(password)`. */
    passwordEncrypted: string;
}

/** @deprecated use {@link EmailPasswordUser} (same interface) */
export type MemoryUser = EmailPasswordUser;
