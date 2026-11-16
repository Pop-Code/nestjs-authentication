import { Controller, Get, INestApplication, Injectable, Module, Post } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Test } from '@nestjs/testing';
import { Strategy as LocalStrategy } from 'passport-local';
import { Strategy } from 'passport-strategy';
import request from 'supertest';

import {
    Auth,
    AuthContext,
    AuthScopes,
    AuthStrategy,
    AuthStrategyContext,
    CurrentAuth,
    CurrentUser,
    JwtStrategy,
    Public,
    RequireAnyScope,
    RequireScopes,
    unauthorized
} from '../../src';
import { AuthModule } from '../../src';
import { admin, authImports, john, User } from '../fixtures';

/** A native strategy with dependency injection. */
@Injectable()
class ApiKeys {
    find(key: string) {
        return key === 'key-1' ? { id: 'client-1', scopes: ['reports:read'] } : undefined;
    }
}

@Module({ providers: [ApiKeys], exports: [ApiKeys] })
class ApiKeysModule {}

@Injectable()
class ApiKeyStrategy implements AuthStrategy {
    readonly name = 'apikey';
    constructor(private readonly keys: ApiKeys) {}

    async authenticate({ request }: AuthStrategyContext) {
        const key = request.headers['x-api-key'];
        const client = typeof key === 'string' ? this.keys.find(key) : undefined;
        return client ? { user: client, namespace: 'api', scopes: client.scopes } : undefined;
    }
}

/** A passport strategy defined with @nestjs/passport. */
@Injectable()
class LegacyLocalStrategy extends PassportStrategy(LocalStrategy, 'legacy-local') {
    constructor() {
        super({ usernameField: 'email' });
    }
    validate(email: string, password: string) {
        return email === 'legacy@example.com' && password === 'pw' ? { id: 'legacy' } : null;
    }
}

/** A passport strategy that redirects (OAuth like). */
class RedirectStrategy extends Strategy {
    name = 'redirect';
    authenticate() {
        this.redirect('https://provider.example.com/authorize');
    }
}
class ErrorStrategy extends Strategy {
    name = 'broken';
    authenticate() {
        this.error(new Error('provider down'));
    }
}
// eslint-disable-next-line @typescript-eslint/no-require-imports
const passport = require('passport');
passport.use(new RedirectStrategy());
passport.use(new ErrorStrategy());

@Auth({ strategies: { jwt: {} }, required: true, exceptionFactory: unauthorized({ challenge: 'Bearer' }) })
@Controller('orders')
class OrderController {
    @Get()
    list(@CurrentUser('email') email: string) {
        return { email };
    }

    @Get('public')
    @Public()
    publicRoute(@CurrentUser() user?: User) {
        return { authenticated: user !== undefined };
    }

    @Post()
    @RequireScopes('orders:write')
    create(@CurrentAuth() auth: AuthContext) {
        return { scopes: auth.scopes };
    }

    @Get('any')
    @RequireAnyScope('orders:admin', 'orders:read')
    any() {
        return { ok: true };
    }
}

@Controller('reports')
class ReportController {
    @Get()
    @Auth({ strategies: { apikey: {}, jwt: {} } })
    @RequireScopes('reports:read')
    list(@CurrentAuth() auth: AuthContext) {
        return { id: auth.user.id ?? auth.user._id, strategy: auth.strategy, namespace: auth.namespace };
    }

    @Get('none')
    none(@CurrentUser() user?: unknown) {
        // no metadata: the global guard does not apply
        return { authenticated: user !== undefined };
    }
}

@Controller('passport')
class PassportController {
    @Post('login')
    @Auth({ strategies: { 'legacy-local': {} }, required: true })
    login(@CurrentAuth() auth: AuthContext) {
        return { user: auth.user, strategy: auth.strategy };
    }

    @Get('oauth')
    @Auth({ strategies: { redirect: { scope: ['openid', 'email'] } } })
    oauth() {
        throw new Error('not called: the strategy redirects');
    }

    @Get('broken')
    @Auth({ strategies: { broken: {} } })
    broken() {
        return {};
    }
}

describe('E2E global guard, strategies and scopes', () => {
    let app: INestApplication;
    let sign: (payload: Record<string, unknown>) => string;

    beforeAll(async () => {
        const [root, providers] = authImports();
        @Module({
            imports: [root, providers, AuthModule.registerStrategies([ApiKeyStrategy], [ApiKeysModule])],
            controllers: [OrderController, ReportController, PassportController],
            providers: [LegacyLocalStrategy]
        })
        class TestModule {}
        const module = await Test.createTestingModule({ imports: [TestModule] }).compile();
        app = await module.createNestApplication().init();
        const jwt = app.get(JwtStrategy);
        sign = (payload) => jwt.sign(payload);
    });
    afterAll(async () => await app.close());

    const get = (url: string, token?: string) => {
        const req = request(app.getHttpServer()).get(url);
        return token ? req.set('Authorization', `Bearer ${token}`) : req;
    };

    test('@Auth on a class: required, with the exception factory', async () => {
        await get('/orders', sign(john.authSerialize())).expect(200).expect({ email: john.email });
        await get('/orders').expect(401).expect('WWW-Authenticate', 'Bearer');
    });

    test('@Public: authenticates if possible, never rejects', async () => {
        await get('/orders/public').expect(200).expect({ authenticated: false });
        await get('/orders/public', sign(john.authSerialize())).expect(200).expect({ authenticated: true });
    });

    test('@RequireScopes: the scopes of the token', async () => {
        const writer = sign({ ...john.authSerialize(), scope: 'orders:write orders:read' });
        await request(app.getHttpServer())
            .post('/orders')
            .set('Authorization', `Bearer ${writer}`)
            .expect(201)
            .expect({ scopes: ['orders:write', 'orders:read'] });
        const reader = sign({ ...john.authSerialize(), scope: 'orders:read' });
        await request(app.getHttpServer())
            .post('/orders')
            .set('Authorization', `Bearer ${reader}`)
            .expect(403)
            .expect((res) => expect(res.body.message).toBe('Insufficient scope'));
        const wildcard = sign({ ...john.authSerialize(), scp: ['orders:*'] });
        await request(app.getHttpServer()).post('/orders').set('Authorization', `Bearer ${wildcard}`).expect(201);
        // not authenticated: the exception factory of the class
        await request(app.getHttpServer()).post('/orders').expect(401);
    });

    test('@RequireAnyScope', async () => {
        await get('/orders/any', sign({ ...john.authSerialize(), scope: 'orders:read' })).expect(200);
        await get('/orders/any', sign({ ...john.authSerialize(), scope: 'users:read' })).expect(403);
    });

    test('a native strategy registered with registerStrategies()', async () => {
        await request(app.getHttpServer())
            .get('/reports')
            .set('x-api-key', 'key-1')
            .expect(200)
            .expect({ id: 'client-1', strategy: 'apikey', namespace: 'api' });
        await request(app.getHttpServer()).get('/reports').set('x-api-key', 'wrong').expect(403);
        // @RequireScopes makes the route required
        await get('/reports').expect(403);
        await get('/reports', sign({ ...admin.authSerialize(), scope: 'reports:read' }))
            .expect(200)
            .expect({ id: '2', strategy: 'jwt', namespace: 'admin' });
    });

    test('a route without metadata is not handled by the global guard', async () => {
        await get('/reports/none', sign(john.authSerialize())).expect(200).expect({ authenticated: false });
    });

    test('passport strategies through the adapter', async () => {
        await request(app.getHttpServer())
            .post('/passport/login')
            .send({ email: 'legacy@example.com', password: 'pw' })
            .expect(201)
            .expect({ user: { id: 'legacy' }, strategy: 'legacy-local' });
        await request(app.getHttpServer())
            .post('/passport/login')
            .send({ email: 'legacy@example.com', password: 'wrong' })
            .expect(403);
        await get('/passport/oauth').expect(302).expect('Location', 'https://provider.example.com/authorize');
        await get('/passport/broken').expect(500);
    });

    test('AuthScopes lists the declared scopes', () => {
        const scopes = app.get(AuthScopes);
        expect(scopes.all('required')).toEqual(['orders:admin', 'orders:read', 'orders:write', 'reports:read']);
        expect(scopes.all('requested')).toEqual(['email', 'openid']);
        expect(scopes.getDeclarations()).toContainEqual({
            scope: 'orders:write',
            kind: 'required',
            source: 'OrderController.create'
        });
        scopes.add({ scope: 'extra', kind: 'requested', source: 'manual' });
        scopes.add({ scope: 'extra', kind: 'requested', source: 'manual' });
        expect(scopes.all().filter((s) => s === 'extra')).toHaveLength(1);
    });
});
