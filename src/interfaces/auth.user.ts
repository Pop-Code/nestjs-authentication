/**
 * The payload stored in the session (and in a token) to load the user back: the id of the user (`sub`, or `_id` /
 * `id`) and `namespace`, the name of the auth provider that loads it (`default` if not set).
 */
export type AuthUserPayload = Record<string, unknown> & { sub?: unknown; namespace?: string };

/**
 * A user that builds its own payload. Optional: by default, the auth provider of the user builds it
 * (see {@link IAuthProvider.serializeUser}).
 */
export interface IAuthUser {
    /** Returns the payload stored in the session or the token to load the user back. */
    authSerialize(): AuthUserPayload;
}

/** Returns the id of the user in a payload: `sub`, `_id` or `id`. */
export function getPayloadUserId(payload: Record<string, unknown>): unknown {
    return payload.sub ?? payload._id ?? payload.id;
}
