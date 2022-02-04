import { NestApplication } from '@nestjs/core';
import { Test } from '@nestjs/testing';
import { randomBytes } from 'crypto';
import session from 'express-session';
import { ExtractJwt } from 'passport-jwt';
import request from 'supertest';

import {
    AuthMemoryUserProvider,
    AuthModule,
    AuthService,
    EmailPasswordStrategy,
    Encryptor,
    JwtStrategy,
    MemoryUser,
    MemoryUserProvider,
    MODULE_OPTIONS_TOKEN
} from '../src';
import { TestAuthController } from './controller';

class User implements MemoryUser {
    _id: string;
    email: string;
    passwordEncrypted: string;
    namespace?: string;
    authSerialize(): Record<string, unknown> & { namespace: string } {
        return { _id: this._id, namespace: this.namespace ?? 'default' };
    }
}

const key = randomBytes(32).toString('hex');
const iv = randomBytes(16).toString('hex');

const userTest = new User();
userTest._id = '1';
userTest.email = 'userTest@nestjs-authentication.com';
const userTestPassword = 'password';

const userTest2 = new User();
userTest2._id = '1';
userTest2.email = 'userTest2@nestjs-authentication.com';
userTest2.namespace = 'user';
const userTest2Password = 'password2';

const jwtSecret = 'nestjs-authentication';

let app: NestApplication;

beforeAll(async () => {
    const builder = await Test.createTestingModule({
        imports: [
            AuthModule.forRoot({
                encrypt: { key, iv },
                jwt: { secretOrKey: jwtSecret, jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken() }
            }),
            AuthModule.registerAuthProviders([
                {
                    provide: 'AuthMemoryUserProvider_default',
                    inject: [Encryptor, AuthService],
                    useFactory: (encryptor: Encryptor) => {
                        const memoryUserProvider = new MemoryUserProvider<User>();
                        memoryUserProvider.registerUser(userTest);
                        return new AuthMemoryUserProvider<User>('default', memoryUserProvider, encryptor);
                    }
                },
                {
                    provide: 'AuthMemoryUserProvider_user',
                    inject: [Encryptor, AuthService],
                    useFactory: (encryptor: Encryptor) => {
                        const memoryUserProvider = new MemoryUserProvider<User>();
                        memoryUserProvider.registerUser(userTest2);
                        return new AuthMemoryUserProvider<User>('user', memoryUserProvider, encryptor);
                    }
                }
            ])
        ],
        controllers: [TestAuthController]
    }).compile();

    app = builder.createNestApplication();

    // init the session
    app.use(
        session({
            secret: 'secret',
            resave: false,
            saveUninitialized: false,
            cookie: {
                maxAge: 100000,
                httpOnly: false
            }
        })
    );

    await app.init();

    userTest.passwordEncrypted = app.get(Encryptor).encrypt(userTestPassword);
    userTest2.passwordEncrypted = app.get(Encryptor).encrypt(userTest2Password);
});

describe('AuthModule', () => {
    test('The AuthModule must create the options provider', async () => {
        const options = app.get(MODULE_OPTIONS_TOKEN);
        expect(options).toHaveProperty('encrypt.key');
        expect(options).toHaveProperty('encrypt.iv');
    });

    test('The AuthModule must create the Encryptor', async () => {
        const encryptor = app.get(Encryptor);
        expect(encryptor).toBeInstanceOf(Encryptor);
    });

    test('The AuthModule must create the AuthService', async () => {
        const authService = app.get(AuthService);
        expect(authService).toBeInstanceOf(AuthService);
    });

    test('The AuthModule must create the AuthMemoryUserProvider_default', async () => {
        const memoryProvider = app.get('AuthMemoryUserProvider_default');
        expect(memoryProvider).toBeInstanceOf(AuthMemoryUserProvider);
    });

    test('The AuthModule must create the AuthMemoryUserProvider_user', async () => {
        const memoryProvider = app.get('AuthMemoryUserProvider_user');
        expect(memoryProvider).toBeInstanceOf(AuthMemoryUserProvider);
    });

    test('The AuthModule must create the EmailPasswordStrategy', async () => {
        const strategy = app.get(EmailPasswordStrategy);
        expect(strategy).toBeInstanceOf(EmailPasswordStrategy);
    });

    test('The AuthModule must create the JwtStrategy', async () => {
        const strategy = app.get(JwtStrategy);
        expect(strategy).toBeInstanceOf(JwtStrategy);
    });
});

describe('AuthService', () => {
    test('The AuthService must have the AuthMemoryUserProvider registered', async () => {
        const authService = app.get(AuthService);
        const memoryProvider = authService.getAuthProvider('default');
        expect(memoryProvider).toBeInstanceOf(AuthMemoryUserProvider);
    });
});

describe('E2E EmailPasswordStrategy', () => {
    test(`GET /test/authenticated and returns empty object`, () => {
        return request(app.getHttpServer()).get('/test/authenticated').expect(200).expect({});
    });
    test(`GET /test/protected and throw 403`, () => {
        return request(app.getHttpServer()).get('/test/protected').expect(403);
    });
    test(`POST /test/login_check and log in user and test authenticated/protected`, async () => {
        const user1 = request.agent(app.getHttpServer());
        await user1
            .post('/test/login_check')
            .set('accept', 'application/json')
            .send({ email: userTest.email, password: userTestPassword })
            .expect({ success: true });
        await user1
            .get('/test/authenticated')
            .expect(200)
            .expect((res) => {
                expect(res.body).toHaveProperty('user', userTest);
            });
        await user1
            .get('/test/protected')
            .expect(200)
            .expect((res) => {
                expect(res.body).toHaveProperty('user', userTest);
            });

        await request(app.getHttpServer()).get('/test/authenticated').expect(200);
        await request(app.getHttpServer()).get('/test/protected').expect(403);
    });

    test(`POST /test/login_check and log in the user2 and test authenticated/protected`, async () => {
        const user2 = request.agent(app.getHttpServer());
        await user2
            .post('/test/login_check')
            .set('accept', 'application/json')
            .send({ email: userTest2.email, password: userTest2Password, namespace: 'user' })
            .expect({ success: true });
        await user2
            .get('/test/authenticated')
            .expect(200)
            .expect((res) => {
                expect(res.body).toHaveProperty('user', userTest2);
            });
        await user2
            .get('/test/protected')
            .expect(200)
            .expect((res) => {
                expect(res.body).toHaveProperty('user', userTest2);
            });

        await request(app.getHttpServer()).get('/test/authenticated').expect(200);
        await request(app.getHttpServer()).get('/test/protected').expect(403);
    });

    test(`POST /test/login_check and throw 403`, async () => {
        await request(app.getHttpServer()).post('/test/login_check').set('accept', 'application/json').expect(403);
    });
});

describe('E2E JWTStrategy', () => {
    test(`Generate a jwt`, () => {
        const strategy = app.get(JwtStrategy);
        const token = strategy.sign({ _id: userTest._id }, jwtSecret);
        expect(typeof token).toBe('string');
    });

    test(`POST /test/authenticated and get the user with session false`, async () => {
        const strategy = app.get(JwtStrategy);
        const token = strategy.sign({ _id: userTest._id }, jwtSecret);
        const user = request.agent(app.getHttpServer());
        await user
            .get('/test/authenticated')
            .set('Authorization', `Bearer ${token}`)
            .expect(200)
            .expect((res) => {
                expect(res.body).toHaveProperty('user', userTest);
            });
        await user.get('/test/authenticated').expect({});
    });

    test(`POST /test/protected and get the user`, async () => {
        const strategy = app.get(JwtStrategy);
        const token = strategy.sign({ _id: userTest._id }, jwtSecret);
        const user = request.agent(app.getHttpServer());
        await user
            .get('/test/protected')
            .set('Authorization', `Bearer ${token}`)
            .expect(200)
            .expect((res) => {
                expect(res.body).toHaveProperty('user', userTest);
            });

        await user.get('/test/protected').expect(403);
    });

    test(`POST /test/jwt-session and log in the user`, async () => {
        const strategy = app.get(JwtStrategy);
        const token = strategy.sign({ _id: userTest._id }, jwtSecret);
        const user = request.agent(app.getHttpServer());
        await user
            .get('/test/jwt-session')
            .set('Authorization', `Bearer ${token}`)
            .expect(200)
            .expect((res) => {
                expect(res.body).toHaveProperty('user', userTest);
            });
        await user
            .get('/test/jwt-session')
            .expect(200)
            .expect((res) => {
                expect(res.body).toHaveProperty('user', userTest);
            });
    });
});
