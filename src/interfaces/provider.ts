import { AuthUserPayload } from './auth.user';

/**
 * Finds the users with a query. Used by the {@link AuthProvider} base class, to write your own auth providers.
 */
export interface IUserProvider<User = any> {
    /** Returns the user matching the query, or `undefined`. */
    findOne: (query: Record<string, unknown>) => Promise<User | undefined>;
    /** Stores a new password hash of a user. Optional. */
    updatePassword?: (user: User, passwordHash: string) => Promise<void> | void;
}

/**
 * Loads the users of a namespace. Register it with `AuthModule.registerAuthProviders()`.
 *
 * @typeParam User the user
 * @typeParam Data the data given to `loadUser()` (credentials, session or token payload)
 */
export interface IAuthProvider<User = any, Data extends object = Record<string, any>> {
    /**
     * Returns the user matching the data (credentials, token payload or session payload),
     * or `undefined` if there is none or the credentials are not valid.
     */
    loadUser: (data: Data) => (User | undefined) | Promise<User | undefined>;
    /** The namespace of the provider. The provider named `default` is used when there is no namespace. */
    getName: () => string;
    /**
     * Returns the payload stored in the session or a token to load the user back with `loadUser()`,
     * e.g. `{ sub: user.id, namespace: 'default' }`. Used when the user does not implement {@link IAuthUser}.
     */
    serializeUser?: (user: User) => AuthUserPayload;
}
