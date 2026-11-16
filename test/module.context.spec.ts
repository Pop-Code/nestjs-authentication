import { Controller, ExecutionContext, Get, Module, UseGuards } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';

import { AuthContextService, AuthGuard, AuthModule, AuthTransport, AuthTransports, CurrentAuth } from '../src';

@Controller()
class TestController {
    constructor(private readonly auth: AuthContextService) {}

    @Get('local')
    @UseGuards(new AuthGuard({ strategies: { 'test-local': {} } }))
    local(@CurrentAuth() auth: unknown) {
        return { decorator: auth !== undefined, service: this.auth.isAuthenticated() };
    }
}

const createApp = async (options: Parameters<typeof AuthModule.forRoot>[0]) => {
    @Module({ imports: [AuthModule.forRoot(options)], controllers: [TestController] })
    class AppModule {}
    const module = await Test.createTestingModule({ imports: [AppModule] }).compile();
    return await module.createNestApplication().init();
};

// a passport strategy that authenticates every request
import passport from 'passport';
import { Strategy } from 'passport-strategy';
class AlwaysStrategy extends Strategy {
    name = 'test-local';
    authenticate() {
        this.success({ id: 1 });
    }
}
passport.use(new AlwaysStrategy());

describe('AuthModule context and transports options', () => {
    afterEach(() => AuthTransports.reset());

    test('the context interceptor is enabled by default', async () => {
        const app = await createApp({});
        await request(app.getHttpServer()).get('/local').expect({ decorator: true, service: true });
        await app.close();
    });

    test('context: false disables the interceptor (the decorators still work)', async () => {
        const app = await createApp({ context: false });
        await request(app.getHttpServer()).get('/local').expect({ decorator: true, service: false });
        await app.close();
    });

    test('transports registers the transports', async () => {
        const seen: string[] = [];
        const transport: AuthTransport = {
            name: 'tracing',
            supports: (ctx: ExecutionContext) => ctx.getType() === 'http',
            getRequest: (ctx: ExecutionContext) => {
                seen.push('getRequest');
                return ctx.switchToHttp().getRequest();
            }
        };
        const app = await createApp({ transports: [transport] });
        expect(AuthTransports.all()[0]).toBe(transport);
        await request(app.getHttpServer()).get('/local').expect(200);
        expect(seen.length).toBeGreaterThan(0);
        await app.close();
    });
});
