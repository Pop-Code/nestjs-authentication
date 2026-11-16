/**
 * The code of the wiki "Users" page, tested as is.
 * Keep it in sync with https://github.com/Pop-Code/nestjs-authentication/wiki/Auth-Providers
 */
import { Controller, Get, INestApplication, Module, Post } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';

import {
    Auth,
    AuthContext,
    AuthModule,
    CurrentAuth,
    CurrentUser,
    EmailPasswordAuthProvider,
    ENCRYPTOR,
    IEncryptor,
    JwtStrategy,
    MemoryUserProvider
} from '../../src';
import { appAuthImports, testEncryptor } from './app/auth';
import { UsersService } from './app/users.service';

// admins/admin.ts: another shape
export interface Admin {
    uuid: string;
    login: string;
    hash: string;
}

// admins/admins.module.ts: the admins, in memory
export const ADMINS = 'ADMINS';

@Module({
    providers: [
        {
            provide: ADMINS,
            useFactory: () => new MemoryUserProvider<Admin>({ getId: (a) => a.uuid, getEmail: (a) => a.login })
        }
    ],
    exports: [ADMINS]
})
export class AdminsModule {}

// the auth provider of the "admin" namespace
export const adminsAuthProvider = {
    provide: 'ADMINS_AUTH_PROVIDER',
    inject: [ENCRYPTOR, ADMINS],
    useFactory: (encryptor: IEncryptor, admins: MemoryUserProvider<Admin>) =>
        new EmailPasswordAuthProvider<Admin>({
            namespace: 'admin',
            encryptor,
            findById: (id) => admins.findById(id),
            findByEmail: (email) => admins.findByEmail(email),
            getId: (admin) => admin.uuid,
            getPasswordHash: (admin) => admin.hash
        })
};

// auth.controller.ts
@Controller('auth')
export class AuthController {
    constructor(private readonly jwt: JwtStrategy) {}

    // POST /auth/login for the users, POST /auth/login?namespace=admin for the admins
    @Post('login')
    @Auth({ strategies: { emailpassword: {} } })
    login(@CurrentUser() user: unknown, @CurrentAuth() auth: AuthContext) {
        return { token: this.jwt.signUser(user, { namespace: auth.namespace, expiresIn: '1h' }) };
    }

    @Get('me')
    @Auth()
    me(@CurrentAuth() auth: AuthContext) {
        return { namespace: auth.namespace };
    }
}

describe('Users page', () => {
    let app: INestApplication;

    beforeAll(async () => {
        @Module({
            imports: [...appAuthImports(), AuthModule.registerAuthProviders([adminsAuthProvider], [AdminsModule])],
            controllers: [AuthController]
        })
        class AppModule {}
        const module = await Test.createTestingModule({ imports: [AppModule] }).compile();
        app = await module.createNestApplication().init();
        await app.get(UsersService).register('john@example.com', 'user-secret');
        app.get<MemoryUserProvider<Admin>>(ADMINS).registerUser({
            uuid: 'a1',
            login: 'admin@example.com',
            hash: await testEncryptor.encrypt('admin-secret')
        });
    });
    afterAll(async () => await app.close());

    const login = (url: string, email: string, password: string) =>
        request(app.getHttpServer()).post(url).send({ email, password });

    test('two namespaces', async () => {
        const user = await login('/auth/login', 'john@example.com', 'user-secret').expect(201);
        await request(app.getHttpServer())
            .get('/auth/me')
            .set('Authorization', `Bearer ${user.body.token}`)
            .expect({ namespace: 'default' });

        const admin = await login('/auth/login?namespace=admin', 'admin@example.com', 'admin-secret').expect(201);
        await request(app.getHttpServer())
            .get('/auth/me')
            .set('Authorization', `Bearer ${admin.body.token}`)
            .expect({ namespace: 'admin' });

        // an admin is not a user, and the other way around
        await login('/auth/login', 'admin@example.com', 'admin-secret').expect(401);
        await login('/auth/login?namespace=admin', 'john@example.com', 'user-secret').expect(401);
        // an unknown namespace
        await login('/auth/login?namespace=unknown', 'john@example.com', 'user-secret').expect(404);
    });
});
