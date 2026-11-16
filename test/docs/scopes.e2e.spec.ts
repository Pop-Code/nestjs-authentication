/**
 * The code of the wiki "Scopes and roles" page, tested as is.
 * Keep it in sync with https://github.com/Pop-Code/nestjs-authentication/wiki/Scopes
 */
import { Controller, Delete, Get, INestApplication, Module, Post } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';

import { Auth, AuthScopes, JwtStrategy, Public, RequireAnyScope, RequireScopes } from '../../src';
import { appAuthImports } from './app/auth';
import { User } from './app/user';
import { UsersService } from './app/users.service';

// orders/orders.controller.ts
@Auth()
@Controller('orders')
export class OrdersController {
    @Get()
    @RequireScopes('orders:read')
    list() {
        return { orders: [] };
    }

    @Post()
    @RequireScopes('orders:read', 'orders:write') // all of them
    create() {
        return { created: true };
    }

    @Delete(':id')
    @RequireAnyScope('orders:admin', 'role:admin') // at least one
    remove() {
        return { removed: true };
    }
}

// scopes.controller.ts: the scopes of the application
@Controller('scopes')
export class ScopesController {
    constructor(private readonly scopes: AuthScopes) {}

    @Get()
    @Public()
    list() {
        return { required: this.scopes.all('required') };
    }
}

describe('Scopes and roles page', () => {
    let app: INestApplication;
    let sign: (user: User, scope?: string[]) => string;
    let john: User;
    let admin: User;

    beforeAll(async () => {
        @Module({
            imports: appAuthImports({
                // the roles of the user are scopes too: role:admin...
                scopes: (auth) => (auth.user as User).roles.map((role) => `role:${role}`)
            }),
            controllers: [OrdersController, ScopesController]
        })
        class AppModule {}
        const module = await Test.createTestingModule({ imports: [AppModule] }).compile();
        app = await module.createNestApplication().init();
        john = await app.get(UsersService).register('john@example.com', 'secret');
        admin = await app.get(UsersService).register('admin@example.com', 'secret', ['admin']);
        sign = (user, scope) => app.get(JwtStrategy).signUser(user, { scope });
    });
    afterAll(async () => await app.close());

    const call = (method: 'get' | 'post' | 'delete', url: string, token: string) =>
        request(app.getHttpServer())[method](url).set('Authorization', `Bearer ${token}`);

    test('the scopes of the token', async () => {
        await call('get', '/orders', sign(john, ['orders:read'])).expect(200);
        await call('get', '/orders', sign(john)).expect(403);
        await call('post', '/orders', sign(john, ['orders:read'])).expect(403);
        await call('post', '/orders', sign(john, ['orders:read', 'orders:write'])).expect(201);
        await call('post', '/orders', sign(john, ['orders:*'])).expect(201); // a wildcard
    });

    test('the roles as scopes', async () => {
        await call('delete', '/orders/1', sign(john)).expect(403);
        await call('delete', '/orders/1', sign(admin)).expect(200);
    });

    test('the response of a missing scope', async () => {
        const res = await call('get', '/orders', sign(john)).expect(403);
        expect(res.body).toMatchObject({ statusCode: 403, message: 'Insufficient scope' });
    });

    test('AuthScopes', async () => {
        await request(app.getHttpServer())
            .get('/scopes')
            .expect({ required: ['orders:admin', 'orders:read', 'orders:write', 'role:admin'] });
    });
});
