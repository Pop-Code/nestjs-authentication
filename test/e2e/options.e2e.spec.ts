import { Controller, Get, INestApplication, Module } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';

import { AuthContext, AuthModule, CurrentAuth, JwtStrategy, Public, RequireScopes, ExtractJwt } from '../../src';
import { authImports, iv, john, jwtSecret, key } from '../fixtures';

@Controller()
class AppController {
    @Get('me')
    me(@CurrentAuth() auth: AuthContext) {
        return { email: auth.user.email, scopes: auth.scopes };
    }

    @Get('health')
    @Public()
    health() {
        return { ok: true };
    }

    @Get('admin')
    @RequireScopes('role:admin')
    adminRoute() {
        return { ok: true };
    }
}

describe('E2E globalGuard, defaults and the scopes option', () => {
    let app: INestApplication;

    beforeAll(async () => {
        const [, providers] = authImports();
        @Module({
            imports: [
                AuthModule.forRoot({
                    encrypt: { key, iv },
                    jwt: { secretOrKey: jwtSecret, jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken() },
                    globalGuard: true,
                    defaults: { strategies: { jwt: {} }, required: true },
                    // the roles of the user as scopes
                    scopes: (auth) => (auth.user.email === john.email ? ['role:admin'] : [])
                }),
                providers
            ],
            controllers: [AppController]
        })
        class AppModule {}
        const module = await Test.createTestingModule({ imports: [AppModule] }).compile();
        app = await module.createNestApplication().init();
    });
    afterAll(async () => await app.close());

    test('all the routes use the defaults, @Public opts out', async () => {
        const token = app.get(JwtStrategy).sign({ ...john.authSerialize(), scope: 'read' });
        await request(app.getHttpServer())
            .get('/me')
            .set('Authorization', `Bearer ${token}`)
            .expect(200)
            .expect({ email: john.email, scopes: ['read', 'role:admin'] });
        await request(app.getHttpServer()).get('/me').expect(403);
        await request(app.getHttpServer()).get('/health').expect(200);
    });

    test('the scopes option adds scopes', async () => {
        const token = app.get(JwtStrategy).sign(john.authSerialize());
        await request(app.getHttpServer()).get('/admin').set('Authorization', `Bearer ${token}`).expect(200);
    });
});
