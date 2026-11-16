import fastifyCookie from '@fastify/cookie';
import fastifySecureSession from '@fastify/secure-session';
import fastifySession from '@fastify/session';
import { Controller, Get, HttpCode, INestApplication, Module, Post, Req } from '@nestjs/common';
import { FastifyAdapter, NestFastifyApplication } from '@nestjs/platform-fastify';
import { Test } from '@nestjs/testing';
import session from 'express-session';
import request from 'supertest';

import { Auth, CurrentUser, sessionLogOut } from '../../src';
import { authImports, john, password, User } from '../fixtures';

@Controller('auth')
class SessionController {
    @Post('login')
    @HttpCode(200)
    @Auth({ strategies: { emailpassword: {} }, saveSession: true, required: true })
    login(@CurrentUser('email') email: string) {
        return { email };
    }

    @Post('login-keep')
    @HttpCode(200)
    @Auth({ strategies: { emailpassword: {} }, saveSession: true, keepSessionInfo: true, required: true })
    loginKeep(@CurrentUser('email') email: string) {
        return { email };
    }

    @Get('me')
    @Auth({ strategies: {}, fromSession: true, required: true })
    me(@CurrentUser() user: User) {
        return { email: user.email };
    }

    @Post('cart')
    @HttpCode(200)
    cart(@Req() req: any) {
        req.session.cart = ['book'];
        return {};
    }

    @Get('cart')
    getCart(@Req() req: any) {
        return { cart: req.session.cart ?? null };
    }

    @Post('logout')
    @HttpCode(200)
    @Auth({ strategies: {}, fromSession: true, required: true })
    async logout(@Req() req: any) {
        await sessionLogOut(req);
        return { success: true };
    }
}

@Module({ imports: authImports(), controllers: [SessionController] })
class AppModule {}

const SECRET = 'a-secret-with-at-least-32-characters!';

const suites: [string, () => Promise<INestApplication>][] = [
    [
        'express + express-session',
        async () => {
            const module = await Test.createTestingModule({ imports: [AppModule] }).compile();
            const app = module.createNestApplication();
            app.use(session({ secret: SECRET, resave: false, saveUninitialized: false }));
            return await app.init();
        }
    ],
    [
        'fastify + @fastify/session',
        async () => {
            const module = await Test.createTestingModule({ imports: [AppModule] }).compile();
            const app = module.createNestApplication<NestFastifyApplication>(new FastifyAdapter());
            await app.register(fastifyCookie as any);
            await app.register(fastifySession as any, { secret: SECRET, cookie: { secure: false } });
            await app.init();
            await app.getHttpAdapter().getInstance().ready();
            return app;
        }
    ],
    [
        'fastify + @fastify/secure-session',
        async () => {
            const module = await Test.createTestingModule({ imports: [AppModule] }).compile();
            const app = module.createNestApplication<NestFastifyApplication>(new FastifyAdapter());
            await app.register(fastifySecureSession as any, {
                secret: SECRET,
                salt: 'mq9hDxBVDbspDR6n',
                cookie: { path: '/', httpOnly: true }
            });
            await app.init();
            await app.getHttpAdapter().getInstance().ready();
            return app;
        }
    ]
];

describe.each(suites)('E2E sessions (%s)', (_name, create) => {
    let app: INestApplication;

    beforeAll(async () => {
        app = await create();
    });
    afterAll(async () => await app.close());

    test('logs in, recognizes the user, logs out', async () => {
        const agent = request.agent(app.getHttpServer());
        await agent.get('/auth/me').expect(403);
        await agent.post('/auth/login').send({ email: john.email, password }).expect(200).expect({ email: john.email });
        await agent.get('/auth/me').expect(200).expect({ email: john.email });
        await agent.get('/auth/me').expect(200);
        await agent.post('/auth/logout').expect(200).expect({ success: true });
        await agent.get('/auth/me').expect(403);
    });

    test('a wrong password does not log in', async () => {
        const agent = request.agent(app.getHttpServer());
        await agent.post('/auth/login').send({ email: john.email, password: 'wrong' }).expect(403);
        await agent.get('/auth/me').expect(403);
    });

    test('the login regenerates the session, keepSessionInfo keeps its data', async () => {
        const agent = request.agent(app.getHttpServer());
        await agent.post('/auth/cart').expect(200);
        await agent.get('/auth/cart').expect({ cart: ['book'] });
        await agent.post('/auth/login').send({ email: john.email, password }).expect(200);
        await agent.get('/auth/cart').expect({ cart: null });

        const keeper = request.agent(app.getHttpServer());
        await keeper.post('/auth/cart').expect(200);
        await keeper.post('/auth/login-keep').send({ email: john.email, password }).expect(200);
        await keeper.get('/auth/cart').expect({ cart: ['book'] });
        await keeper.get('/auth/me').expect(200);
    });
});
