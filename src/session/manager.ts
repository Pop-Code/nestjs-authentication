import { AuthUserPayload } from '../interfaces/auth.user';
import { AuthRequest } from '../transports/interfaces';

/** The session property that holds the login, `passport` like passport (existing sessions keep working). */
export const DEFAULT_SESSION_KEY = 'passport';

const NO_SESSION = 'Login sessions require session support. Did you forget to use `express-session` middleware?';

/** Options of {@link sessionLogIn} and {@link sessionLogOut}. */
export interface SessionLogInOptions {
    /** Keeps the data of the session (it is regenerated). Default `false`. */
    keepSessionInfo?: boolean;
    /** The session property that holds the login. Default `passport`. */
    key?: string;
}

/**
 * Calls `regenerate()` or `save()` of a session, whatever the library:
 *
 * - express-session, @fastify/session: with a callback (or a promise)
 * - cookie sessions without `save()` (@fastify/secure-session, cookie-session): synchronous
 */
async function call(session: any, method: 'regenerate' | 'save'): Promise<void> {
    if (typeof session?.[method] !== 'function') {
        return;
    }
    if (typeof session.save !== 'function') {
        await session[method]();
        return;
    }
    await new Promise<void>((resolve, reject) => {
        const result = session[method]((err?: any) => (err ? reject(err) : resolve()));
        if (result !== undefined && result !== null && typeof result.then === 'function') {
            result.then(() => resolve(), reject);
        }
    });
}

/** Returns a copy of the data of a session (`data()` of @fastify/secure-session, else its own properties). */
function copySession(session: any): Record<string, unknown> {
    const data = typeof session.data === 'function' ? session.data() : { ...session };
    delete data.cookie;
    return data;
}

/** Restores the data of a session, with assignments (the cookie sessions only save assigned properties). */
function restoreSession(session: any, data: Record<string, unknown>): void {
    for (const [key, value] of Object.entries(data)) {
        // skips the read-only properties of the new session (the metadata of @fastify/session)
        const descriptor = Object.getOwnPropertyDescriptor(session, key);
        const readOnly =
            descriptor !== undefined &&
            ('value' in descriptor ? descriptor.writable === false : descriptor.set === undefined);
        if (readOnly) {
            continue;
        }
        session[key] = value;
    }
}

/**
 * Removes the user from the login property of a session. The property is assigned again (not mutated): the cookie
 * sessions (@fastify/secure-session) only save the assigned properties.
 */
export function removeSessionUser(session: any, key = DEFAULT_SESSION_KEY): void {
    const login = session?.[key];
    if (login !== undefined && login !== null && typeof login === 'object') {
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        const { user, ...rest } = login;
        session[key] = rest;
    }
}

/** Returns the payload of the user stored in the session, or `undefined`. */
export function getSessionPayload(request: AuthRequest, key = DEFAULT_SESSION_KEY): AuthUserPayload | undefined {
    const payload = request.session?.[key]?.user;
    return payload !== undefined && payload !== null ? payload : undefined;
}

/**
 * Stores the payload of a user in the session (format of passport: `session.passport.user`).
 * The session is regenerated first (a new id, against session fixation), then saved.
 *
 * @throws Error if the request has no session
 */
export async function sessionLogIn(
    request: AuthRequest,
    payload: AuthUserPayload,
    options: SessionLogInOptions = {}
): Promise<void> {
    if (request.session === undefined || request.session === null) {
        throw new Error(NO_SESSION);
    }
    const key = options.key ?? DEFAULT_SESSION_KEY;
    const previous = options.keepSessionInfo === true ? copySession(request.session) : {};
    // @fastify/session replaces request.session: read it again after regenerate()
    await call(request.session, 'regenerate');
    restoreSession(request.session, previous);
    request.session[key] = { ...(request.session[key] ?? {}), user: payload };
    await call(request.session, 'save');
}

/**
 * Removes the user from the session, saves it, then regenerates it.
 *
 * @throws Error if the request has no session
 */
export async function sessionLogOut(request: AuthRequest, options: SessionLogInOptions = {}): Promise<void> {
    if (request.session === undefined || request.session === null) {
        throw new Error(NO_SESSION);
    }
    const key = options.key ?? DEFAULT_SESSION_KEY;
    removeSessionUser(request.session, key);
    const previous = options.keepSessionInfo === true ? copySession(request.session) : {};
    await call(request.session, 'save');
    await call(request.session, 'regenerate');
    restoreSession(request.session, previous);
}
