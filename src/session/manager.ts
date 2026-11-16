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

const call = (session: any, method: string): Promise<void> =>
    new Promise((resolve, reject) => {
        if (typeof session?.[method] !== 'function') {
            return resolve();
        }
        session[method]((err?: any) => (err ? reject(err) : resolve()));
    });

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
    const previous = { ...request.session };
    await call(request.session, 'regenerate');
    if (options.keepSessionInfo === true) {
        Object.assign(request.session, previous);
    }
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
    if (request.session[key] !== undefined && request.session[key] !== null) {
        delete request.session[key].user;
    }
    const previous = { ...request.session };
    await call(request.session, 'save');
    await call(request.session, 'regenerate');
    if (options.keepSessionInfo === true) {
        Object.assign(request.session, previous);
    }
}
