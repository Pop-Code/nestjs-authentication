/**
 * Finds the users of an auth provider, in a database, an api, the memory...
 */
export interface IUserProvider<User = any> {
    /** Returns the user matching the query, or `undefined`. */
    findOne: (query: Record<string, unknown>) => Promise<User | undefined>;
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
}
