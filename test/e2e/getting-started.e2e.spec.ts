/**
 * The code of the wiki "Getting started" tutorial, tested as is.
 * Keep it in sync with https://github.com/Pop-Code/nestjs-authentication/wiki/Getting-Started
 */
import { Body, Controller, Get, INestApplication, Injectable, Module, Post } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { randomUUID } from 'crypto';
import request from 'supertest';

import {
    Auth,
    AuthModule,
    CurrentUser,
    EmailPasswordAuthProvider,
    ENCRYPTOR,
    IEncryptor,
    InjectEncryptor,
    JwtStrategy,
    ScryptEncryptor,
    unauthorized
} from '../../src';

// users/user.ts: your user, any shape
export class User {
    constructor(
        public id: string,
        public email: string,
        public passwordHash: string
    ) {}
}

// users/users.service.ts
@Injectable()
export class UsersService {
    private readonly users = new Map<string, User>();

    constructor(@InjectEncryptor() private readonly encryptor: IEncryptor) {}

    async register(email: string, password: string): Promise<User> {
        const user = new User(randomUUID(), email, await this.encryptor.encrypt(password));
        this.users.set(user.id, user);
        return user;
    }

    async findById(id: string): Promise<User | undefined> {
        return this.users.get(id);
    }

    async findByEmail(email: string): Promise<User | undefined> {
        return [...this.users.values()].find((user) => user.email === email);
    }
}

// users/users.module.ts
@Module({
    providers: [UsersService],
    exports: [UsersService]
})
export class UsersModule {}

// auth.controller.ts
@Controller('auth')
export class AuthController {
    constructor(
        private readonly users: UsersService,
        private readonly jwt: JwtStrategy<User>
    ) {}

    @Post('register')
    async register(@Body() body: { email: string; password: string }) {
        const user = await this.users.register(body.email, body.password);
        return { id: user.id };
    }

    @Post('login')
    @Auth({ strategies: { emailpassword: {} } })
    login(@CurrentUser() user: User) {
        return { token: this.jwt.signUser(user, { expiresIn: '1h' }) };
    }

    @Get('me')
    @Auth()
    me(@CurrentUser() user: User) {
        return { id: user.id, email: user.email };
    }
}

// app.module.ts
@Module({
    imports: [
        AuthModule.forRoot({
            encryptor: new ScryptEncryptor(),
            jwt: { secretOrKey: process.env.JWT_SECRET ?? 'change-me', algorithms: ['HS256'] },
            // the options of @Auth()
            defaults: {
                strategies: { jwt: {} },
                required: true,
                exceptionFactory: unauthorized({ challenge: 'Bearer' })
            }
        }),
        AuthModule.registerAuthProviders(
            [
                {
                    provide: 'USERS_AUTH_PROVIDER',
                    inject: [ENCRYPTOR, UsersService],
                    useFactory: (encryptor: IEncryptor, users: UsersService) =>
                        new EmailPasswordAuthProvider<User>({
                            encryptor,
                            findById: (id) => users.findById(id),
                            findByEmail: (email) => users.findByEmail(email),
                            getId: (user) => user.id,
                            getPasswordHash: (user) => user.passwordHash
                        })
                }
            ],
            [UsersModule]
        ),
        UsersModule
    ],
    controllers: [AuthController]
})
export class AppModule {}

describe('Getting started tutorial', () => {
    let app: INestApplication;

    beforeAll(async () => {
        const module = await Test.createTestingModule({ imports: [AppModule] }).compile();
        app = await module.createNestApplication().init();
    });
    afterAll(async () => await app.close());

    test('register, log in, call a protected route', async () => {
        const server = app.getHttpServer();
        const credentials = { email: 'john@example.com', password: 's3cret!' };

        const registered = await request(server).post('/auth/register').send(credentials).expect(201);

        const { body } = await request(server).post('/auth/login').send(credentials).expect(201);
        expect(typeof body.token).toBe('string');

        await request(server)
            .get('/auth/me')
            .set('Authorization', `Bearer ${body.token}`)
            .expect(200)
            .expect({ id: registered.body.id, email: credentials.email });
    });

    test('the errors of the tutorial', async () => {
        const server = app.getHttpServer();
        await request(server).post('/auth/register').send({ email: 'jane@example.com', password: 'right' });
        await request(server)
            .post('/auth/login')
            .send({ email: 'jane@example.com', password: 'wrong' })
            .expect(401)
            .expect('WWW-Authenticate', 'Bearer');
        await request(server).get('/auth/me').expect(401);
        await request(server).get('/auth/me').set('Authorization', 'Bearer not-a-token').expect(401);
    });
});
