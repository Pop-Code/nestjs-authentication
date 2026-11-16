import jwt from 'jsonwebtoken';

import {
    AuthService,
    AuthStrategyContext,
    AuthStrategyRegistry,
    EmailPasswordStrategy,
    ExtractJwt,
    getTokenScopes,
    IAuthProvider,
    JwtStrategy,
    PassportAuthStrategy,
    SessionStrategy
} from '../src';

const user = { id: '1' };
const provider = (name: string): IAuthProvider => ({
    getName: () => name,
    loadUser: async (data: any) => (data._id === '1' || data.email === 'a@b.c' ? user : undefined)
});
const authService = new AuthService().registerAuthProvider(provider('default')).registerAuthProvider(provider('admin'));
const ctx = (request: any, options = {}): AuthStrategyContext =>
    ({
        request: { headers: {}, ...request },
        transport: 'http',
        executionContext: {} as any,
        options
    }) as AuthStrategyContext;
const bearer = (token: string) => ({ headers: { authorization: `Bearer ${token}` } });

describe('ExtractJwt', () => {
    const req = {
        headers: { authorization: 'Bearer abc', 'x-token': 'h', cookie: 'a=1; token=c%20d' },
        query: { token: 'q' },
        body: { token: 'b' }
    };
    test('extractors', () => {
        expect(ExtractJwt.fromAuthHeaderAsBearerToken()(req)).toBe('abc');
        expect(ExtractJwt.fromAuthHeaderWithScheme('BEARER')(req)).toBe('abc');
        expect(ExtractJwt.fromAuthHeaderWithScheme('basic')(req)).toBeNull();
        expect(ExtractJwt.fromAuthHeaderAsBearerToken()({ headers: { authorization: 'Bearer' } })).toBeNull();
        expect(ExtractJwt.fromHeader('X-Token')(req)).toBe('h');
        expect(ExtractJwt.fromHeader('missing')(req)).toBeNull();
        expect(ExtractJwt.fromHeader('a')({ headers: { a: ['x', 'y'] } })).toBe('x');
        expect(ExtractJwt.fromUrlQueryParameter('token')(req)).toBe('q');
        expect(ExtractJwt.fromUrlQueryParameter('none')(req)).toBeNull();
        expect(ExtractJwt.fromBodyField('token')(req)).toBe('b');
        expect(ExtractJwt.fromBodyField('none')(req)).toBeNull();
        expect(ExtractJwt.fromCookie('token')(req)).toBe('c d');
        expect(ExtractJwt.fromCookie('none')(req)).toBeNull();
        expect(ExtractJwt.fromCookie('token')({ headers: {}, cookies: { token: 'parsed' } })).toBe('parsed');
        expect(ExtractJwt.fromExtractors([ExtractJwt.fromHeader('none'), ExtractJwt.fromBodyField('token')])(req)).toBe(
            'b'
        );
        expect(ExtractJwt.fromExtractors([ExtractJwt.fromHeader('none')])(req)).toBeNull();
    });
});

describe('JwtStrategy', () => {
    const secret = 'secret';
    const strategy = new JwtStrategy(authService, {
        secretOrKey: secret,
        algorithms: ['HS256'],
        issuer: 'app',
        audience: 'api'
    });
    const sign = (payload: object, options: jwt.SignOptions = {}) =>
        jwt.sign(payload, secret, { issuer: 'app', audience: 'api', ...options });

    test('requires a key', () => {
        expect(() => new JwtStrategy(authService, {})).toThrow('secretOrKey or a secretOrKeyProvider');
    });

    test('authenticates a valid token, with its namespace and scopes', async () => {
        const result = await strategy.authenticate(ctx(bearer(sign({ _id: '1', namespace: 'admin', scope: 'a b' }))));
        expect(result).toMatchObject({ user, namespace: 'admin', scopes: ['a', 'b'] });
        expect((result?.info as any).payload).toMatchObject({ _id: '1', iss: 'app' });
    });

    test('fails without a token, or with an invalid one', async () => {
        await expect(strategy.authenticate(ctx({}))).resolves.toBeUndefined();
        await expect(strategy.authenticate(ctx(bearer('garbage')))).resolves.toBeUndefined();
        await expect(
            strategy.authenticate(ctx(bearer(sign({ _id: '1' }, { expiresIn: -10 }))))
        ).resolves.toBeUndefined();
        await expect(
            strategy.authenticate(ctx(bearer(sign({ _id: '1' }, { issuer: 'other' }))))
        ).resolves.toBeUndefined();
        await expect(
            strategy.authenticate(ctx(bearer(sign({ _id: '1' }, { audience: 'other' }))))
        ).resolves.toBeUndefined();
        await expect(
            strategy.authenticate(ctx(bearer(sign({ _id: '1' }, { algorithm: 'HS512' }))))
        ).resolves.toBeUndefined();
        await expect(strategy.authenticate(ctx(bearer(jwt.sign({ _id: '1' }, 'other'))))).resolves.toBeUndefined();
        // an unknown user
        await expect(strategy.authenticate(ctx(bearer(sign({ _id: '2' }))))).resolves.toBeUndefined();
        // a string payload
        const plain = new JwtStrategy(authService, { secretOrKey: secret });
        await expect(plain.verify(jwt.sign('just a string', secret))).resolves.toBeUndefined();
    });

    test('ignoreExpiration and jsonWebTokenOptions', async () => {
        const expired = jwt.sign({ _id: '1' }, secret, { expiresIn: -10 });
        const lax = new JwtStrategy(authService, { secretOrKey: secret, ignoreExpiration: true });
        await expect(lax.authenticate(ctx(bearer(expired)))).resolves.toMatchObject({ user });
        const tolerant = new JwtStrategy(authService, {
            secretOrKey: secret,
            jsonWebTokenOptions: { clockTolerance: 60 }
        });
        await expect(tolerant.authenticate(ctx(bearer(expired)))).resolves.toMatchObject({ user });
    });

    test('secretOrKeyProvider: promise and passport-jwt callback (jwks-rsa)', async () => {
        const token = jwt.sign({ _id: '1' }, 'rotated', { keyid: 'k1' });
        const promised = new JwtStrategy(authService, {
            secretOrKeyProvider: async (_req, raw) =>
                jwt.decode(raw, { complete: true })?.header.kid === 'k1' ? 'rotated' : undefined
        });
        await expect(promised.authenticate(ctx(bearer(token)))).resolves.toMatchObject({ user });
        await expect(promised.authenticate(ctx(bearer(jwt.sign({ _id: '1' }, 'x'))))).resolves.toBeUndefined();

        const callback = new JwtStrategy(authService, {
            secretOrKeyProvider: (_req, _raw, done) => done(null, 'rotated')
        });
        await expect(callback.authenticate(ctx(bearer(token)))).resolves.toMatchObject({ user });
        const failing = new JwtStrategy(authService, {
            secretOrKeyProvider: (_req, _raw, done) => done(new Error('no key'))
        });
        await expect(failing.authenticate(ctx(bearer(token)))).resolves.toBeUndefined();
    });

    test('jwtFromRequest', async () => {
        const fromQuery = new JwtStrategy(authService, {
            secretOrKey: secret,
            jwtFromRequest: ExtractJwt.fromUrlQueryParameter('t')
        });
        await expect(
            fromQuery.authenticate(ctx({ query: { t: jwt.sign({ _id: '1' }, secret) } }))
        ).resolves.toMatchObject({ user });
    });

    test('getTokenScopes()', () => {
        expect(getTokenScopes({ scope: 'a  b' })).toEqual(['a', 'b']);
        expect(getTokenScopes({ scp: ['a', 2, 'c'] })).toEqual(['a', 'c']);
        expect(getTokenScopes({ scopes: 'x' })).toEqual(['x']);
        expect(getTokenScopes({})).toEqual([]);
    });
});

describe('EmailPasswordStrategy', () => {
    const strategy = new EmailPasswordStrategy(authService);

    test('reads the credentials from the body or the query, and the namespace', async () => {
        await expect(strategy.authenticate(ctx({ body: { email: 'a@b.c', password: 'x' } }))).resolves.toEqual({
            user,
            namespace: 'default',
            info: { namespace: 'default' }
        });
        await expect(
            strategy.authenticate(ctx({ query: { email: 'a@b.c', password: 'x', namespace: 'admin' } }))
        ).resolves.toMatchObject({ namespace: 'admin' });
    });

    test('fails without credentials, or with unknown ones', async () => {
        await expect(strategy.authenticate(ctx({}))).resolves.toBeUndefined();
        await expect(strategy.authenticate(ctx({ body: { email: 'a@b.c', password: '' } }))).resolves.toBeUndefined();
        await expect(strategy.authenticate(ctx({ body: { email: 'x@y.z', password: 'x' } }))).resolves.toBeUndefined();
    });
});

describe('SessionStrategy', () => {
    const strategy = new SessionStrategy(authService);

    test('loads the user of the session', async () => {
        const session = { passport: { user: { _id: '1', namespace: 'admin' } } };
        await expect(strategy.authenticate(ctx({ session }))).resolves.toEqual({
            user,
            namespace: 'admin',
            info: { namespace: 'admin' }
        });
        await expect(strategy.authenticate(ctx({ session: {} }))).resolves.toBeUndefined();
    });

    test('removes a user or a namespace that does not exist anymore', async () => {
        const removed = { passport: { user: { _id: '2' } } };
        await expect(strategy.authenticate(ctx({ session: removed }))).resolves.toBeUndefined();
        expect(removed.passport).toEqual({});
        const unknown = { passport: { user: { _id: '1', namespace: 'gone' } } };
        await expect(strategy.authenticate(ctx({ session: unknown }))).resolves.toBeUndefined();
        expect(unknown.passport).toEqual({});
    });

    test('passes the other errors, and fails without a session', async () => {
        const broken = new SessionStrategy(
            new AuthService().registerAuthProvider({
                getName: () => 'default',
                loadUser: async () => Promise.reject(new Error('db down'))
            })
        );
        await expect(broken.authenticate(ctx({ session: { passport: { user: { _id: '1' } } } }))).rejects.toThrow(
            'db down'
        );
        await expect(strategy.authenticate(ctx({}))).rejects.toThrow('Login sessions require session support');
    });

    test('uses the sessionKey option', async () => {
        const custom = new SessionStrategy(authService, { sessionKey: 'auth' });
        await expect(custom.authenticate(ctx({ session: { auth: { user: { _id: '1' } } } }))).resolves.toMatchObject({
            user
        });
    });
});

describe('AuthStrategyRegistry', () => {
    test('registers the strategies, and looks the other names up in passport', () => {
        const registry = new AuthStrategyRegistry();
        const strategy = { name: 'custom', authenticate: async () => undefined };
        expect(registry.register(strategy).get('custom')).toBe(strategy);
        expect([...registry.getStrategies().keys()]).toEqual(['custom']);
        // passport registers the "session" strategy by default
        expect(registry.get('session')).toBeInstanceOf(PassportAuthStrategy);
        expect(() => registry.get('unknown')).toThrow('Unknown authentication strategy "unknown"');
    });
});
