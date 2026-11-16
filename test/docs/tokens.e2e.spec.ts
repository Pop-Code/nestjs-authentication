/**
 * The code of the wiki "Tokens (JWT)" page, tested as is.
 * Keep it in sync with https://github.com/Pop-Code/nestjs-authentication/wiki/JWT
 */
import { Controller, Get, INestApplication, Module, Post } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import jwt from 'jsonwebtoken';
import request from 'supertest';

import { Auth, AuthContext, CurrentAuth, CurrentUser, ExtractJwt, JwtStrategy } from '../../src';
import { appAuthImports, JWT_SECRET } from './app/auth';
import { User } from './app/user';
import { UsersService } from './app/users.service';

// auth.controller.ts
@Controller('auth')
export class AuthController {
    constructor(private readonly jwt: JwtStrategy<User>) {}

    @Post('login')
    @Auth({ strategies: { emailpassword: {} } })
    login(@CurrentUser() user: User) {
        return {
            token: this.jwt.signUser(user, {
                expiresIn: '1h',
                scope: ['orders:read'],
                claims: { email: user.email }
            })
        };
    }

    @Get('me')
    @Auth()
    me(@CurrentAuth() auth: AuthContext<User>) {
        return { id: auth.user.id, scopes: auth.scopes };
    }
}

describe('Tokens page', () => {
    let app: INestApplication;

    beforeAll(async () => {
        @Module({
            imports: appAuthImports({
                jwt: {
                    secretOrKey: JWT_SECRET,
                    algorithms: ['HS256'],
                    issuer: 'https://api.example.com',
                    audience: 'my-api',
                    // the Authorization header, or a "token" cookie
                    jwtFromRequest: ExtractJwt.fromExtractors([
                        ExtractJwt.fromAuthHeaderAsBearerToken(),
                        ExtractJwt.fromCookie('token')
                    ])
                }
            }),
            controllers: [AuthController]
        })
        class AppModule {}
        const module = await Test.createTestingModule({ imports: [AppModule] }).compile();
        app = await module.createNestApplication().init();
        await app.get(UsersService).register('john@example.com', 'secret');
    });
    afterAll(async () => await app.close());

    test('issue a token, read it from the header or a cookie', async () => {
        const { body } = await request(app.getHttpServer())
            .post('/auth/login')
            .send({ email: 'john@example.com', password: 'secret' })
            .expect(201);
        // what the token contains
        const payload = jwt.decode(body.token) as Record<string, unknown>;
        expect(payload).toMatchObject({ namespace: 'default', scope: 'orders:read', email: 'john@example.com' });
        expect(typeof payload.sub).toBe('string');

        // signUser() does not set the issuer and the audience the strategy checks: the token is rejected
        await request(app.getHttpServer()).get('/auth/me').set('Authorization', `Bearer ${body.token}`).expect(401);
    });

    test('verify the issuer and the audience', async () => {
        const user = (await app.get(UsersService).findByEmail('john@example.com')) as User;
        const strategy = app.get(JwtStrategy);
        const token = strategy.signUser(user, {
            expiresIn: '1h',
            issuer: 'https://api.example.com',
            audience: 'my-api'
        });
        await request(app.getHttpServer())
            .get('/auth/me')
            .set('Authorization', `Bearer ${token}`)
            .expect(200)
            .expect({ id: user.id, scopes: [] });
        await request(app.getHttpServer()).get('/auth/me').set('Cookie', `token=${token}`).expect(200);
        const other = strategy.signUser(user, { issuer: 'https://evil.example.com', audience: 'my-api' });
        await request(app.getHttpServer()).get('/auth/me').set('Authorization', `Bearer ${other}`).expect(401);
    });
});
