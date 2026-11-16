import { decorateRequest, getSessionPayload, sessionLogIn, sessionLogOut } from '../src';

const createSession = (data: Record<string, unknown> = {}) => {
    const calls: string[] = [];
    const session: any = {
        ...data,
        regenerate(cb: (err?: any) => void) {
            calls.push('regenerate');
            for (const k of Object.keys(this)) {
                if (typeof this[k] !== 'function') delete this[k];
            }
            cb();
        },
        save(cb: (err?: any) => void) {
            calls.push('save');
            cb();
        }
    };
    return { session, calls };
};

describe('session manager', () => {
    test('sessionLogIn() regenerates, stores the payload (passport format) and saves', async () => {
        const { session, calls } = createSession({ cart: [1] });
        const request: any = { headers: {}, session };
        await sessionLogIn(request, { _id: '1', namespace: 'admin' });
        expect(calls).toEqual(['regenerate', 'save']);
        expect(session.passport).toEqual({ user: { _id: '1', namespace: 'admin' } });
        expect(session.cart).toBeUndefined();
        expect(getSessionPayload(request)).toEqual({ _id: '1', namespace: 'admin' });
    });

    test('sessionLogIn() keepSessionInfo and key', async () => {
        const { session } = createSession({ cart: [1] });
        await sessionLogIn({ headers: {}, session }, { _id: '1' }, { keepSessionInfo: true, key: 'auth' });
        expect(session.cart).toEqual([1]);
        expect(session.auth).toEqual({ user: { _id: '1' } });
    });

    test('sessionLogOut() removes the user, saves and regenerates', async () => {
        const { session, calls } = createSession({ passport: { user: { _id: '1' } }, cart: [1] });
        const request: any = { headers: {}, session };
        await sessionLogOut(request);
        expect(calls).toEqual(['save', 'regenerate']);
        expect(getSessionPayload(request)).toBeUndefined();
        expect(session.cart).toBeUndefined();

        const kept = createSession({ passport: { user: { _id: '1' } }, cart: [1] });
        await sessionLogOut({ headers: {}, session: kept.session }, { keepSessionInfo: true });
        expect(kept.session.cart).toEqual([1]);
        expect(kept.session.passport).toEqual({});
    });

    test('errors', async () => {
        await expect(sessionLogIn({ headers: {} }, {})).rejects.toThrow('Login sessions require session support');
        await expect(sessionLogOut({ headers: {} })).rejects.toThrow('Login sessions require session support');
        const failing = { regenerate: (cb: any) => cb(new Error('store down')), save: (cb: any) => cb() };
        await expect(sessionLogIn({ headers: {}, session: failing }, {})).rejects.toThrow('store down');
        // keepSessionInfo skips the read-only properties of the new session
        const locked: any = {
            cart: [1],
            save: (cb: any) => cb(),
            regenerate(cb: any) {
                delete this.cart;
                Object.defineProperty(this, 'meta', { value: 'new', writable: false, enumerable: true });
                Object.defineProperty(this, 'computed', { get: () => 'new', enumerable: true });
                cb();
            },
            meta: 'old',
            computed: 'old'
        };
        await sessionLogIn({ headers: {}, session: locked }, { _id: '3' }, { keepSessionInfo: true });
        expect(locked.cart).toEqual([1]);
        expect(locked.meta).toBe('new');
        expect(locked.computed).toBe('new');
        // promise based methods
        const promised: any = { regenerate: async () => undefined, save: async () => undefined };
        await sessionLogIn({ headers: {}, session: promised }, { _id: '2' });
        expect(promised.passport.user).toEqual({ _id: '2' });
        const rejecting: any = {
            regenerate: () => Promise.reject(new Error('promise down')),
            save: async () => undefined
        };
        await expect(sessionLogIn({ headers: {}, session: rejecting }, {})).rejects.toThrow('promise down');
        // a session without regenerate / save (e.g. cookie-session)
        const simple: any = {};
        await sessionLogIn({ headers: {}, session: simple }, { _id: '1' });
        expect(simple.passport.user).toEqual({ _id: '1' });
    });
});

describe('decorateRequest()', () => {
    const user = { authSerialize: () => ({ _id: '1' }) };

    test('adds passport compatible methods', async () => {
        const { session } = createSession();
        const request: any = { headers: {}, session };
        decorateRequest(request);
        expect(request.isAuthenticated()).toBe(false);
        expect(request.isUnauthenticated()).toBe(true);

        await new Promise<void>((resolve, reject) =>
            request.logIn(user, (err: any) => (err ? reject(err) : resolve()))
        );
        expect(request.user).toBe(user);
        expect(request.isAuthenticated()).toBe(true);
        expect(session.passport.user).toEqual({ _id: '1' });

        await new Promise<void>((resolve, reject) => request.logout((err: any) => (err ? reject(err) : resolve())));
        expect(request.user).toBeNull();
        expect(session.passport).toBeUndefined();
    });

    test('login without session, logout without session', async () => {
        const request: any = { headers: {} };
        decorateRequest(request);
        await new Promise<void>((resolve) => request.login({ any: true }, { session: false }, () => resolve()));
        expect(request.isAuthenticated()).toBe(true);
        await new Promise<void>((resolve) => request.logOut({}, () => resolve()));
        expect(request.isAuthenticated()).toBe(false);
        // no callback
        request.logIn({ any: true }, { session: false });
        request.logOut();
    });

    test('login with a session requires authSerialize()', async () => {
        const request: any = { headers: {}, session: {} };
        decorateRequest(request);
        const err = await new Promise((resolve) => request.logIn({ id: 1 }, {}, resolve));
        expect(String(err)).toContain('authSerialize()');
    });

    test('keeps the existing methods (passport)', () => {
        const isAuthenticated = () => true;
        const logIn = () => undefined;
        const logOut = () => undefined;
        const request: any = { headers: {}, isAuthenticated, logIn, logOut };
        decorateRequest(request);
        expect(request.isAuthenticated).toBe(isAuthenticated);
        expect(request.logIn).toBe(logIn);
        expect(request.logOut).toBe(logOut);
    });
});
