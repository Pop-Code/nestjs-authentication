import { Controller, Get, INestApplication, Module, Post } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import session from 'express-session';
import jwt from 'jsonwebtoken';
import request from 'supertest';

import {
    Auth,
    AuthModule,
    AuthService,
    CurrentUser,
    EmailPasswordAuthProvider,
    Encryptor,
    ENCRYPTOR,
    IEncryptor,
    JwtStrategy,
    MemoryUserProvider,
    MigratingEncryptor,
    ScryptEncryptor
} from '../src';

/** A user with its own shape: no interface, no authSerialize() */
interface Account {
    uuid: string;
    login: string;
    hash: string;
}

const scrypt = new ScryptEncryptor({ cost: 2 ** 10 });
const aes = new Encryptor({
    key: '77c0c891a5a062694a5ef1fdcf3719fe460d9c6e7ad5bda8715e44fdb2c8ae85',
    iv: 'f62456b5e1604435e3a548002d8b8944'
});

const accounts = () =>
    new MemoryUserProvider<Account>({
        getId: (a) => a.uuid,
        getEmail: (a) => a.login,
        setPasswordHash: (a, hash) => (a.hash = hash)
    });

const provider = (users: MemoryUserProvider<Account>, encryptor: IEncryptor = scrypt, namespace?: string) =>
    new EmailPasswordAuthProvider<Account>({
        namespace,
        encryptor,
        findById: (id) => users.findById(id),
        findByEmail: (email) => users.findByEmail(email),
        getId: (a) => a.uuid,
        getPasswordHash: (a) => a.hash,
        updatePasswordHash: (a, hash) => users.updatePassword(a, hash)
    });

describe('EmailPasswordAuthProvider with any user shape', () => {
    test('loads a user by email + password, and by payload', async () => {
        const users = accounts();
        const account: Account = { uuid: 'u1', login: 'a@b.c', hash: await scrypt.encrypt('secret') };
        users.registerUser(account);
        const p = provider(users);

        expect(p.getName()).toBe('default');
        await expect(p.loadUser({ email: 'a@b.c', password: 'secret' })).resolves.toBe(account);
        await expect(p.loadUser({ email: 'a@b.c', password: 'wrong' })).resolves.toBeUndefined();
        await expect(p.loadUser({ email: 'x@y.z', password: 'secret' })).resolves.toBeUndefined();
        await expect(p.loadUser({ sub: 'u1' })).resolves.toBe(account);
        await expect(p.loadUser({ _id: 'u1' })).resolves.toBe(account);
        await expect(p.loadUser({ id: 'u1' })).resolves.toBe(account);
        await expect(p.loadUser({ sub: 'nope' })).resolves.toBeUndefined();
        await expect(p.loadUser({})).resolves.toBeUndefined();
        // an id and a password: the password is checked
        await expect(p.loadUser({ sub: 'u1', password: 'wrong' })).resolves.toBeUndefined();
        // an email without password (a custom payload)
        await expect(p.loadUser({ email: 'a@b.c' })).resolves.toBe(account);
        expect(p.serializeUser(account)).toEqual({ sub: 'u1', namespace: 'default' });
    });

    test('defaults: _id / id and passwordEncrypted / passwordHash', async () => {
        const hash = await scrypt.encrypt('pw');
        const byId = new EmailPasswordAuthProvider<any>({
            encryptor: scrypt,
            findById: () => undefined,
            findByEmail: () => ({ id: 7, passwordHash: hash })
        });
        await expect(byId.loadUser({ email: 'a', password: 'pw' })).resolves.toEqual({ id: 7, passwordHash: hash });
        expect(byId.serializeUser({ id: 7 })).toEqual({ sub: 7, namespace: 'default' });
        expect(byId.serializeUser({ _id: 'x' })).toEqual({ sub: 'x', namespace: 'default' });
        expect(() => byId.serializeUser({})).toThrow('the user has no id');
        const noHash = new EmailPasswordAuthProvider<any>({
            encryptor: scrypt,
            findById: () => undefined,
            findByEmail: () => ({ id: 1 })
        });
        await expect(noHash.loadUser({ email: 'a', password: 'pw' })).resolves.toBeUndefined();
        expect(
            () => new EmailPasswordAuthProvider({ findById: () => undefined, findByEmail: () => undefined } as any)
        ).toThrow('requires an encryptor');
    });

    test('rehash with updatePasswordHash', async () => {
        const users = accounts();
        const account: Account = { uuid: 'u1', login: 'a@b.c', hash: aes.encrypt('secret') };
        users.registerUser(account);
        const p = provider(users, new MigratingEncryptor(scrypt, [aes]));
        await expect(p.loadUser({ email: 'a@b.c', password: 'secret' })).resolves.toBe(account);
        expect(scrypt.canVerify(account.hash)).toBe(true);
    });

    test('MemoryUserProvider accessors and defaults', async () => {
        const users = accounts();
        const account: Account = { uuid: 'u1', login: 'a@b.c', hash: 'h' };
        users.registerUser(account);
        await expect(users.findById('u1')).resolves.toBe(account);
        await expect(users.findById(undefined)).resolves.toBeUndefined();
        await expect(users.findByEmail('a@b.c')).resolves.toBe(account);
        await expect(users.findByEmail('x')).resolves.toBeUndefined();
        await expect(users.findOne({ _id: 'u1' })).resolves.toBe(account);
        await expect(users.findOne({ email: 'a@b.c' })).resolves.toBe(account);
        await expect(users.findOne({})).resolves.toBeUndefined();
        expect(users.removeUser(account)).toBe(true);

        const defaults = new MemoryUserProvider();
        const withHash: any = { id: 2, email: 'b', passwordHash: 'old' };
        const withEncrypted: any = { _id: 3, email: 'c', passwordEncrypted: 'old' };
        defaults.registerUser(withHash).registerUser(withEncrypted);
        await expect(defaults.findById(2)).resolves.toBe(withHash);
        defaults.updatePassword(withHash, 'new');
        defaults.updatePassword(withEncrypted, 'new');
        expect(withHash.passwordHash).toBe('new');
        expect(withEncrypted.passwordEncrypted).toBe('new');
    });
});

describe('serializeUser and signUser', () => {
    const users = accounts();
    const account: Account = { uuid: 'u1', login: 'a@b.c', hash: 'h' };
    users.registerUser(account);
    const authService = new AuthService()
        .registerAuthProvider(provider(users))
        .registerAuthProvider(provider(users, scrypt, 'admin'));

    test('AuthService.serializeUser()', () => {
        expect(authService.serializeUser(account)).toEqual({ sub: 'u1', namespace: 'default' });
        expect(authService.serializeUser(account, 'admin')).toEqual({ sub: 'u1', namespace: 'admin' });
        expect(authService.serializeUser({ authSerialize: () => ({ custom: true }) })).toEqual({ custom: true });
        expect(() => authService.serializeUser(account, 'unknown')).toThrow('implement serializeUser()');
        const noSerialize = new AuthService().registerAuthProvider({
            getName: () => 'default',
            loadUser: () => undefined
        });
        expect(() => noSerialize.serializeUser(account)).toThrow('implement serializeUser()');
    });

    test('JwtStrategy.signUser()', async () => {
        const strategy = new JwtStrategy<Account>(authService, { secretOrKey: 'secret' });
        const token = strategy.signUser(account, { expiresIn: 60, scope: ['a', 'b'], claims: { tenant: 't1' } });
        expect(jwt.verify(token, 'secret')).toMatchObject({
            sub: 'u1',
            namespace: 'default',
            scope: 'a b',
            tenant: 't1'
        });
        const admin = strategy.signUser(account, { namespace: 'admin', scope: 'x', secretOrPrivateKey: 'other' });
        expect(jwt.verify(admin, 'other')).toMatchObject({ sub: 'u1', namespace: 'admin', scope: 'x' });
        const result = await strategy.authenticate({
            request: { headers: { authorization: `Bearer ${token}` } },
            transport: 'http',
            executionContext: {} as any,
            options: {}
        });
        expect(result).toMatchObject({ user: account, namespace: 'default', scopes: ['a', 'b'] });
    });
});

describe('E2E: sessions with any user shape', () => {
    let app: INestApplication;

    @Controller()
    class AppController {
        @Post('login')
        @Auth({ strategies: { emailpassword: {} }, saveSession: true, required: true })
        login(@CurrentUser('uuid') uuid: string) {
            return { uuid };
        }

        @Get('me')
        @Auth({ strategies: {}, fromSession: true, required: true })
        me(@CurrentUser('login') login: string) {
            return { login };
        }
    }

    beforeAll(async () => {
        const users = accounts();
        users.registerUser({ uuid: 'u1', login: 'a@b.c', hash: await scrypt.encrypt('secret') });
        @Module({
            imports: [
                AuthModule.forRoot({ encryptor: scrypt }),
                AuthModule.registerAuthProviders([
                    {
                        provide: 'ACCOUNTS',
                        inject: [ENCRYPTOR],
                        useFactory: (encryptor: IEncryptor) => provider(users, encryptor)
                    }
                ])
            ],
            controllers: [AppController]
        })
        class AppModule {}
        const module = await Test.createTestingModule({ imports: [AppModule] }).compile();
        app = module.createNestApplication();
        app.use(session({ secret: 's', resave: false, saveUninitialized: false }));
        await app.init();
    });
    afterAll(async () => await app.close());

    test('logs in, stores { sub, namespace } in the session, loads the user back', async () => {
        const agent = request.agent(app.getHttpServer());
        await agent.post('/login').send({ email: 'a@b.c', password: 'secret' }).expect(201).expect({ uuid: 'u1' });
        await agent.get('/me').expect(200).expect({ login: 'a@b.c' });
        await request(app.getHttpServer()).get('/me').expect(403);
    });
});
