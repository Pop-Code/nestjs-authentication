import { INestApplication } from '@nestjs/common';
import { FastifyAdapter, NestFastifyApplication } from '@nestjs/platform-fastify';
import { Test } from '@nestjs/testing';
import request from 'supertest';

import { JwtStrategy } from '../../src';
import { admin, john, password } from '../fixtures';
import { HttpAppModule } from './app';

const suites: [string, () => Promise<INestApplication>][] = [
    [
        'express',
        async () => {
            const module = await Test.createTestingModule({ imports: [HttpAppModule] }).compile();
            return await module.createNestApplication().init();
        }
    ],
    [
        'fastify',
        async () => {
            const module = await Test.createTestingModule({ imports: [HttpAppModule] }).compile();
            const app = module.createNestApplication<NestFastifyApplication>(new FastifyAdapter());
            await app.init();
            await app.getHttpAdapter().getInstance().ready();
            return app;
        }
    ]
];

describe.each(suites)('E2E http (%s)', (_name, create) => {
    let app: INestApplication;
    let token: string;
    let adminToken: string;

    beforeAll(async () => {
        app = await create();
        token = app.get(JwtStrategy).sign(john.authSerialize());
        adminToken = app.get(JwtStrategy).sign(admin.authSerialize());
    });
    afterAll(async () => await app.close());

    test('@CurrentUser() and @CurrentAuth()', async () => {
        await request(app.getHttpServer())
            .get('/http/me')
            .set('Authorization', `Bearer ${token}`)
            .expect(200)
            .expect({ id: '1', email: john.email, strategy: 'jwt', namespace: 'default', transport: 'http' });
        await request(app.getHttpServer())
            .get('/http/me')
            .set('Authorization', `Bearer ${adminToken}`)
            .expect(200)
            .expect((res) => expect(res.body).toMatchObject({ email: admin.email, namespace: 'admin' }));
        await request(app.getHttpServer()).get('/http/me').expect(403);
    });

    test('@CurrentUser() is undefined when not authenticated', async () => {
        await request(app.getHttpServer()).get('/http/optional').expect(200).expect({ authenticated: false });
        await request(app.getHttpServer())
            .get('/http/optional')
            .set('Authorization', `Bearer ${token}`)
            .expect(200)
            .expect({ authenticated: true });
    });

    test('withDefaults() and unauthorized(): 401 with WWW-Authenticate', async () => {
        await request(app.getHttpServer()).get('/http/api').expect(401).expect('WWW-Authenticate', 'Bearer');
        await request(app.getHttpServer())
            .get('/http/api')
            .set('Authorization', `Bearer ${token}`)
            .expect(200)
            .expect({ email: john.email });
    });

    test('emailpassword strategy (body and namespace)', async () => {
        await request(app.getHttpServer())
            .post('/http/login')
            .send({ email: john.email, password })
            .expect(201)
            .expect({ email: john.email, strategy: 'emailpassword', namespace: 'default' });
        await request(app.getHttpServer())
            .post('/http/login?namespace=admin')
            .send({ email: admin.email, password })
            .expect(201)
            .expect({ email: admin.email, strategy: 'emailpassword', namespace: 'admin' });
        await request(app.getHttpServer()).post('/http/login').send({ email: john.email, password: 'x' }).expect(403);
        await request(app.getHttpServer()).post('/http/login').expect(403);
    });

    test('AuthContextService in a service', async () => {
        await request(app.getHttpServer())
            .get('/http/profile')
            .set('Authorization', `Bearer ${token}`)
            .expect(200)
            .expect({ profile: { email: john.email, strategy: 'jwt', namespace: 'default' } });
        await request(app.getHttpServer()).get('/http/profile').expect(200).expect({ profile: null });
    });

    test('concurrent requests keep their own context', async () => {
        const results = await Promise.all(
            Array.from({ length: 20 }, (_, i) =>
                request(app.getHttpServer())
                    .get('/http/profile')
                    .set('Authorization', `Bearer ${i % 2 === 0 ? token : adminToken}`)
            )
        );
        results.forEach((res, i) => expect(res.body.profile.email).toBe(i % 2 === 0 ? john.email : admin.email));
    });
});
