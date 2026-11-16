import { AuthUserPayload } from '../interfaces/auth.user';
import { AuthRequest } from '../transports/interfaces';
import { SessionLogInOptions, sessionLogIn, sessionLogOut } from './manager';

type Callback = (err?: any) => void;

/** Options of {@link decorateRequest}. */
export interface DecorateRequestOptions extends SessionLogInOptions {
    /** Returns the payload of a user stored by `logIn()`. Default: `user.authSerialize()`. */
    serialize?: (user: any) => AuthUserPayload;
}

function defaultSerialize(user: any): AuthUserPayload {
    if (typeof user?.authSerialize !== 'function') {
        throw new Error(
            'Cannot store the user in the session: give a serialize function, or implement authSerialize()'
        );
    }
    return user.authSerialize();
}

/**
 * Adds `logIn()`, `logOut()`, `isAuthenticated()` and `isUnauthenticated()` to a request, compatible with passport
 * (and their `login()` / `logout()` aliases), if it does not have them. They use the session of the request.
 */
export function decorateRequest(request: AuthRequest, defaults: DecorateRequestOptions = {}): void {
    const { serialize = defaultSerialize, ...sessionDefaults } = defaults;
    if (typeof request.isAuthenticated !== 'function') {
        request.isAuthenticated = function (this: AuthRequest) {
            return this.user !== undefined && this.user !== null;
        };
        request.isUnauthenticated = function (this: AuthRequest) {
            return !this.isAuthenticated();
        };
    }
    if (typeof request.logIn !== 'function') {
        request.logIn = request.login = function (
            this: AuthRequest,
            user: any,
            options?: (SessionLogInOptions & { session?: boolean }) | Callback,
            done?: Callback
        ) {
            const opts = typeof options === 'function' ? {} : (options ?? {});
            const cb = typeof options === 'function' ? options : (done ?? (() => undefined));
            const promise =
                opts.session === false
                    ? Promise.resolve()
                    : Promise.resolve().then(() =>
                          sessionLogIn(this, serialize(user), { ...sessionDefaults, ...opts })
                      );
            promise.then(
                () => {
                    this.user = user;
                    cb();
                },
                (err) => cb(err)
            );
        };
    }
    if (typeof request.logOut !== 'function') {
        request.logOut = request.logout = function (
            this: AuthRequest,
            options?: SessionLogInOptions | Callback,
            done?: Callback
        ) {
            const opts = typeof options === 'function' ? {} : (options ?? {});
            const cb = typeof options === 'function' ? options : (done ?? (() => undefined));
            this.user = null;
            const promise = this.session ? sessionLogOut(this, { ...sessionDefaults, ...opts }) : Promise.resolve();
            promise.then(
                () => cb(),
                (err) => cb(err)
            );
        };
    }
}
