/**
 * The payload stored in the session (and that can be stored in a token) to load the user back.
 * `namespace` is the name of the auth provider that loads the user, `default` if not set.
 */
export type AuthUserPayload = Record<string, unknown> & { namespace?: string };

/**
 * A user that can be stored in a session.
 */
export interface IAuthUser {
    /**
     * Returns the data stored in the session to load the user back on the next requests,
     * typically its id and the namespace of its auth provider: `{ _id: this._id, namespace: 'default' }`.
     */
    authSerialize(): AuthUserPayload;
}
