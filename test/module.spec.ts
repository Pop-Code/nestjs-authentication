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
    ENCRYPTOR,
    Encryptor,
    IEncryptor,
    JwtStrategy,
    MemoryUser,
    MemoryUserProvider,
    MODULE_OPTIONS_TOKEN
} from '../src';
import { EmailPasswordController } from './emailpassword.controller';
import { JwtController } from './jwt.controller';
import { MixedController } from './mixed.controller';

class User implements MemoryUser {
    _id: string;
    email: string;
    passwordEncrypted: string;
    namespace?: string;
    authSerialize() {
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
                    inject: [ENCRYPTOR],
                    useFactory: (encryptor: IEncryptor) => {
                        const memoryUserProvider = new MemoryUserProvider<User>();
                        memoryUserProvider.registerUser(userTest);
                        return new AuthMemoryUserProvider<User>('default', memoryUserProvider, encryptor);
                    }
                },
                {
                    provide: 'AuthMemoryUserProvider_user',
                    inject: [ENCRYPTOR],
                    useFactory: (encryptor: IEncryptor) => {
                        const memoryUserProvider = new MemoryUserProvider<User>();
                        memoryUserProvider.registerUser(userTest2);
                        return new AuthMemoryUserProvider<User>('user', memoryUserProvider, encryptor);
                    }
                }
            ])
        ],
        controllers: [EmailPasswordController, JwtController, MixedController]
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
    test('The AuthService must have the providers registered', async () => {
        const authService = app.get(AuthService);

        const memoryProvider = authService.getAuthProvider('default');
        expect(memoryProvider).toBeInstanceOf(AuthMemoryUserProvider);

        const memoryProvider2 = authService.getAuthProvider('user');
        expect(memoryProvider2).toBeInstanceOf(AuthMemoryUserProvider);
    });
});

describe('E2E EmailPasswordStrategy', () => {
    describe('Authenticated', () => {
        test(`GET /emailpassword/authenticated return the user if cookie set, empty if not`, async () => {
            const user1 = request.agent(app.getHttpServer());
            await user1
                .post('/emailpassword/login_check')
                .set('accept', 'application/json')
                .send({ email: userTest.email, password: userTestPassword })
                .expect({ success: true });
            await user1
                .get('/emailpassword/authenticated')
                .expect(200)
                .expect((res) => {
                    expect(res.body).toHaveProperty('user', userTest);
                });
            await request(app.getHttpServer()).get('/emailpassword/authenticated').expect(200);
        });
        test(`GET /emailpassword/authenticated return the good user`, async () => {
            const user1 = request.agent(app.getHttpServer());
            await user1
                .post('/emailpassword/login_check')
                .set('accept', 'application/json')
                .send({ email: userTest.email, password: userTestPassword })
                .expect({ success: true });
            await user1
                .get('/emailpassword/authenticated')
                .expect(200)
                .expect((res) => {
                    expect(res.body).toHaveProperty('user', userTest);
                });

            const user2 = request.agent(app.getHttpServer());
            await user2
                .post('/emailpassword/login_check')
                .set('accept', 'application/json')
                .send({ email: userTest2.email, password: userTest2Password, namespace: 'user' })
                .expect({ success: true });
            await user2
                .get('/emailpassword/authenticated')
                .expect(200)
                .expect((res) => {
                    expect(res.body).toHaveProperty('user', userTest2);
                });
            await request(app.getHttpServer()).get('/emailpassword/authenticated').expect(200);
        });
    });

    describe('Protected', () => {
        test(`GET /emailpassword/protected return the user if cookie set, throw 403 if not`, async () => {
            const user1 = request.agent(app.getHttpServer());
            await user1
                .post('/emailpassword/login_check')
                .set('accept', 'application/json')
                .send({ email: userTest.email, password: userTestPassword })
                .expect({ success: true });
            await user1
                .get('/emailpassword/protected')
                .expect(200)
                .expect((res) => {
                    expect(res.body).toHaveProperty('user', userTest);
                });
            await request(app.getHttpServer()).get('/emailpassword/protected').expect(403);
        });
        test(`GET /emailpassword/protected return the good user`, async () => {
            const user1 = request.agent(app.getHttpServer());
            await user1
                .post('/emailpassword/login_check')
                .set('accept', 'application/json')
                .send({ email: userTest.email, password: userTestPassword })
                .expect({ success: true });
            await user1
                .get('/emailpassword/protected')
                .expect(200)
                .expect((res) => {
                    expect(res.body).toHaveProperty('user', userTest);
                });
            const user2 = request.agent(app.getHttpServer());
            await user2
                .post('/emailpassword/login_check')
                .set('accept', 'application/json')
                .send({ email: userTest2.email, password: userTest2Password, namespace: 'user' })
                .expect({ success: true });
            await user2
                .get('/emailpassword/protected')
                .expect(200)
                .expect((res) => {
                    expect(res.body).toHaveProperty('user', userTest2);
                });
            await request(app.getHttpServer()).get('/emailpassword/protected').expect(403);
        });
    });

    describe('Session', () => {
        test(`GET /emailpassword/nosession return empty user if cookie set`, async () => {
            const user1 = request.agent(app.getHttpServer());
            await user1
                .post('/emailpassword/login_check')
                .set('accept', 'application/json')
                .send({ email: userTest.email, password: userTestPassword })
                .expect({ success: true });

            await user1
                .get('/emailpassword/session')
                .expect(200)
                .expect((res) => {
                    expect(res.body).not.toHaveProperty('user');
                });

            await request(app.getHttpServer())
                .get('/emailpassword/session')
                .expect((res) => expect(res.body).not.toHaveProperty('user'));
        });
        test(`GET /emailpassword/protected return the good user`, async () => {
            const user1 = request.agent(app.getHttpServer());
            await user1
                .post('/emailpassword/login_check')
                .set('accept', 'application/json')
                .send({ email: userTest.email, password: userTestPassword })
                .expect({ success: true });
            await user1
                .get('/emailpassword/session')
                .expect(200)
                .expect((res) => {
                    expect(res.body).not.toHaveProperty('user');
                });
            const user2 = request.agent(app.getHttpServer());
            await user2
                .post('/emailpassword/login_check')
                .set('accept', 'application/json')
                .send({ email: userTest2.email, password: userTest2Password, namespace: 'user' })
                .expect({ success: true });
            await user2
                .get('/emailpassword/session')
                .expect(200)
                .expect((res) => {
                    expect(res.body).not.toHaveProperty('user');
                });
            await request(app.getHttpServer()).get('/emailpassword/session').expect(200);
        });
    });

    describe('Logout', () => {
        test(`GET /emailpassword/logout and logout the user`, async () => {
            const user1 = request.agent(app.getHttpServer());
            await user1
                .post('/emailpassword/login_check')
                .set('accept', 'application/json')
                .send({ email: userTest.email, password: userTestPassword })
                .expect({ success: true });
            await user1
                .get('/emailpassword/authenticated')
                .expect(200)
                .expect((res) => {
                    expect(res.body).toHaveProperty('user', userTest);
                });
            await user1.post('/emailpassword/logout').expect(200);

            await user1.post('/emailpassword/authenticated').expect((res) => {
                expect(res.body).not.toHaveProperty('user');
            });
        });
    });
});

describe('E2E JWTStrategy', () => {
    test(`Generate a jwt`, () => {
        const strategy = app.get(JwtStrategy);
        const token = strategy.sign({ _id: userTest._id }, jwtSecret);
        expect(typeof token).toBe('string');
    });

    describe('Authenticated', () => {
        test(`GET /jwt/authenticated return the user if token set, empty if not`, async () => {
            const strategy = app.get(JwtStrategy);
            const token = strategy.sign({ _id: userTest._id }, jwtSecret);
            const user1 = request.agent(app.getHttpServer());
            await user1
                .get('/jwt/authenticated')
                .set('Authorization', `Bearer ${token}`)
                .expect(200)
                .expect((res) => {
                    expect(res.body).toHaveProperty('user', userTest);
                });
            await user1
                .get('/jwt/authenticated')
                .expect(200)
                .expect((res) => {
                    expect(res.body).not.toHaveProperty('user');
                });
            await user1.get('/jwt/authenticated').expect(200);
            await request(app.getHttpServer()).get('/jwt/authenticated').expect(200);
        });
        test(`GET /jwt/authenticated return the good user`, async () => {
            const strategy = app.get(JwtStrategy);
            const token = strategy.sign({ _id: userTest._id }, jwtSecret);
            const user1 = request.agent(app.getHttpServer());
            await user1
                .get('/jwt/authenticated')
                .set('Authorization', `Bearer ${token}`)
                .expect(200)
                .expect((res) => {
                    expect(res.body).toHaveProperty('user', userTest);
                });

            const token2 = strategy.sign({ _id: userTest2._id, namespace: 'user' }, jwtSecret);
            await user1
                .get('/jwt/authenticated')
                .set('Authorization', `Bearer ${token2}`)
                .expect(200)
                .expect((res) => {
                    expect(res.body).toHaveProperty('user', userTest2);
                });
            await user1.get('/jwt/authenticated').expect(200);
        });
    });

    describe('Protected', () => {
        test(`GET /jwt/protected return the user if token set, throw if not`, async () => {
            const strategy = app.get(JwtStrategy);
            const token = strategy.sign({ _id: userTest._id }, jwtSecret);
            const user1 = request.agent(app.getHttpServer());
            await user1
                .get('/jwt/protected')
                .set('Authorization', `Bearer ${token}`)
                .expect(200)
                .expect((res) => {
                    expect(res.body).toHaveProperty('user', userTest);
                });
            await user1.get('/jwt/protected').expect(403);
            await request(app.getHttpServer()).get('/jwt/protected').expect(403);
        });
        test(`GET /jwt/protected return the good user`, async () => {
            const strategy = app.get(JwtStrategy);
            const token = strategy.sign({ _id: userTest._id }, jwtSecret);
            const user1 = request.agent(app.getHttpServer());
            await user1
                .get('/jwt/protected')
                .set('Authorization', `Bearer ${token}`)
                .expect(200)
                .expect((res) => {
                    expect(res.body).toHaveProperty('user', userTest);
                });
            const token2 = strategy.sign({ _id: userTest2._id, namespace: 'user' }, jwtSecret);
            await user1
                .get('/jwt/protected')
                .set('Authorization', `Bearer ${token2}`)
                .expect(200)
                .expect((res) => {
                    expect(res.body).toHaveProperty('user', userTest2);
                });
            await user1.get('/jwt/protected').expect(403);
        });
    });

    describe('Session', () => {
        test(`GET /jwt/session return the user if token set, throw if not`, async () => {
            const strategy = app.get(JwtStrategy);
            const token = strategy.sign({ _id: userTest._id }, jwtSecret);

            // this request must login the user and persist it in the session for next call
            const user1 = request.agent(app.getHttpServer());
            await user1
                .get('/jwt/session')
                .set('Authorization', `Bearer ${token}`)
                .expect(200)
                .expect((res) => {
                    expect(res.body).toHaveProperty('user', userTest);
                });

            // this request must get the user from session, even if no token is provided
            await user1
                .get('/jwt/from-session')
                .expect(200)
                .expect((res) => {
                    expect(res.body).toHaveProperty('user', userTest);
                });

            await request(app.getHttpServer()).get('/jwt/from-session').expect(403);
        });
    });
});

describe('E2E MixedStrategy (emailpassword and jwt)', () => {
    let user1: ReturnType<typeof request.agent>;
    beforeAll(async () => {
        user1 = request.agent(app.getHttpServer());
        await user1
            .post('/emailpassword/login_check')
            .set('accept', 'application/json')
            .send({ email: userTest.email, password: userTestPassword })
            .expect({ success: true });
    });

    describe('Authenticated', () => {
        test(`GET /mixed/authenticated return the user from session`, async () => {
            await user1
                .get('/mixed/authenticated')
                .expect(200)
                .expect((res) => {
                    expect(res.body).toHaveProperty('user', userTest);
                });
        });
        test(`GET /mixed/authenticated return the user from jwt token`, async () => {
            const strategy = app.get(JwtStrategy);
            const token = strategy.sign({ _id: userTest2._id, namespace: 'user' }, jwtSecret);
            await request
                .agent(app.getHttpServer())
                .get('/mixed/authenticated')
                .set('Authorization', `Bearer ${token}`)
                .expect(200)
                .expect((res) => {
                    expect(res.body).toHaveProperty('user', userTest2);
                });
        });
        test(`GET /mixed/authenticated do not return the user (no cookie, no token)`, async () => {
            await request
                .agent(app.getHttpServer())
                .get('/mixed/authenticated')
                .expect(200)
                .expect((res) => {
                    expect(res.body).not.toHaveProperty('user');
                });
        });
    });

    describe('Protected', () => {
        test(`GET /mixed/protected return the user from session`, async () => {
            await user1
                .get('/mixed/protected')
                .expect(200)
                .expect((res) => {
                    expect(res.body).toHaveProperty('user', userTest);
                });
        });
        test(`GET /mixed/protected return the user from jwt token`, async () => {
            const strategy = app.get(JwtStrategy);
            const token = strategy.sign({ _id: userTest2._id, namespace: 'user' }, jwtSecret);
            await request
                .agent(app.getHttpServer())
                .get('/mixed/protected')
                .set('Authorization', `Bearer ${token}`)
                .expect(200)
                .expect((res) => {
                    expect(res.body).toHaveProperty('user', userTest2);
                });
        });
        test(`GET /mixed/protected throw (no cookie, no token)`, async () => {
            await request.agent(app.getHttpServer()).get('/mixed/protected').expect(403);
        });
    });

    describe('Session', () => {
        test(`GET /mixed/session do not return the user from session (user is logged in)`, async () => {
            await user1
                .get('/mixed/session')
                .expect(200)
                .expect((res) => {
                    expect(res.body).not.toHaveProperty('user');
                });
        });
        test(`GET /mixed/session return the user from jwt token`, async () => {
            const strategy = app.get(JwtStrategy);
            const token = strategy.sign({ _id: userTest2._id, namespace: 'user' }, jwtSecret);
            await request
                .agent(app.getHttpServer())
                .get('/mixed/session')
                .set('Authorization', `Bearer ${token}`)
                .expect(200)
                .expect((res) => {
                    expect(res.body).toHaveProperty('user', userTest2);
                });
        });
        test(`GET /mixed/session return empty`, async () => {
            await request
                .agent(app.getHttpServer())
                .get('/mixed/session')
                .expect(200)
                .expect((res) => {
                    expect(res.body).not.toHaveProperty('user');
                });
        });
    });
});

describe('E2E failures', () => {
    test('POST /emailpassword/login_check with a wrong password returns 403', async () => {
        await request(app.getHttpServer())
            .post('/emailpassword/login_check')
            .send({ email: userTest.email, password: 'wrong' })
            .expect(403);
    });

    test('POST /emailpassword/login_check with an unknown email returns 403', async () => {
        await request(app.getHttpServer())
            .post('/emailpassword/login_check')
            .send({ email: 'nobody@nestjs-authentication.com', password: userTestPassword })
            .expect(403);
    });

    test('POST /emailpassword/login_check without credentials returns 403', async () => {
        await request(app.getHttpServer()).post('/emailpassword/login_check').expect(403);
    });

    test('POST /emailpassword/login_check with the credentials of another namespace returns 403', async () => {
        await request(app.getHttpServer())
            .post('/emailpassword/login_check')
            .send({ email: userTest2.email, password: userTest2Password })
            .expect(403);
    });

    test('POST /emailpassword/login_check with an unknown namespace returns 404', async () => {
        await request(app.getHttpServer())
            .post('/emailpassword/login_check?namespace=unknown')
            .send({ email: userTest.email, password: userTestPassword })
            .expect(404);
    });

    test('GET /jwt/protected with an invalid token returns 403', async () => {
        const token = app.get(JwtStrategy).sign({ _id: userTest._id }, 'not-the-secret');
        await request(app.getHttpServer()).get('/jwt/protected').set('Authorization', `Bearer ${token}`).expect(403);
        await request(app.getHttpServer()).get('/jwt/protected').set('Authorization', 'Bearer garbage').expect(403);
    });

    test('GET /jwt/protected with an expired token returns 403', async () => {
        const token = app.get(JwtStrategy).sign({ _id: userTest._id, exp: Math.floor(Date.now() / 1000) - 60 });
        await request(app.getHttpServer()).get('/jwt/protected').set('Authorization', `Bearer ${token}`).expect(403);
    });

    test('GET /jwt/protected with the token of an unknown user returns 403', async () => {
        const token = app.get(JwtStrategy).sign({ _id: 'unknown' });
        await request(app.getHttpServer()).get('/jwt/protected').set('Authorization', `Bearer ${token}`).expect(403);
    });

    test('the session of a removed user is not authenticated anymore', async () => {
        const removed = new User();
        removed._id = 'removed';
        removed.email = 'removed@nestjs-authentication.com';
        removed.passwordEncrypted = app.get(Encryptor).encrypt('password');
        const provider = app.get<AuthMemoryUserProvider<User>>('AuthMemoryUserProvider_default');
        const users = provider.getProvider() as MemoryUserProvider<User>;
        users.registerUser(removed);

        const agent = request.agent(app.getHttpServer());
        await agent
            .post('/emailpassword/login_check')
            .send({ email: removed.email, password: 'password' })
            .expect({ success: true });
        await agent.get('/emailpassword/protected').expect(200);

        users.removeUser(removed);
        await agent.get('/emailpassword/protected').expect(403);
        await agent
            .get('/emailpassword/authenticated')
            .expect(200)
            .expect((res) => expect(res.body).not.toHaveProperty('user'));
    });
});

afterAll(async () => {
    await app.close();
});
