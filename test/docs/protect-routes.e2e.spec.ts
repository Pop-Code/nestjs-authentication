/**
 * The code of the wiki "Protect routes" page, tested as is.
 * Keep it in sync with https://github.com/Pop-Code/nestjs-authentication/wiki/Guard
 */
import { Controller, Get, INestApplication, Module, UseGuards } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';

import { Auth, AuthGuard, CurrentUser, JwtStrategy, Public, unauthorized } from '../../src';
import { appAuthImports } from './app/auth';
import { User } from './app/user';
import { UsersService } from './app/users.service';

// orders/orders.controller.ts
@Auth() // every route of the controller: the defaults of the module
@Controller('orders')
export class OrdersController {
    @Get()
    list(@CurrentUser() user: User) {
        return { owner: user.email, orders: [] };
    }

    @Get('catalog')
    @Public() // anyone; the user is set when the request has a valid token
    catalog(@CurrentUser() user?: User) {
        return { personalized: user !== undefined };
    }
}

// health.controller.ts: a route without decorator is not protected
@Controller('health')
export class HealthController {
    @Get()
    health() {
        return { ok: true };
    }
}

// legacy.controller.ts: a guard per route, without the defaults
@Controller('legacy')
export class LegacyController {
    @Get()
    @UseGuards(new AuthGuard({ strategies: { jwt: {} }, required: true, exceptionFactory: unauthorized() }))
    legacy(@CurrentUser('email') email: string) {
        return { email };
    }
}

describe('Protect routes page', () => {
    let app: INestApplication;
    let token: string;

    beforeAll(async () => {
        @Module({ imports: appAuthImports(), controllers: [OrdersController, HealthController, LegacyController] })
        class AppModule {}
        const module = await Test.createTestingModule({ imports: [AppModule] }).compile();
        app = await module.createNestApplication().init();
        const user = await app.get(UsersService).register('john@example.com', 'secret');
        token = app.get(JwtStrategy).signUser(user);
    });
    afterAll(async () => await app.close());

    const get = (url: string, bearer?: string) => {
        const req = request(app.getHttpServer()).get(url);
        return bearer ? req.set('Authorization', `Bearer ${bearer}`) : req;
    };

    test('@Auth() on the class', async () => {
        await get('/orders', token).expect(200).expect({ owner: 'john@example.com', orders: [] });
        await get('/orders').expect(401).expect('WWW-Authenticate', 'Bearer');
        await get('/orders', 'not-a-token').expect(401);
    });

    test('@Public()', async () => {
        await get('/orders/catalog').expect(200).expect({ personalized: false });
        await get('/orders/catalog', token).expect(200).expect({ personalized: true });
    });

    test('no decorator, and a guard per route', async () => {
        await get('/health').expect(200);
        await get('/legacy').expect(401);
        await get('/legacy', token).expect(200).expect({ email: 'john@example.com' });
    });

    test('globalGuard: every route, @Public() opts out', async () => {
        @Module({ imports: appAuthImports({ globalGuard: true }), controllers: [OrdersController, HealthController] })
        class GlobalModule {}
        const module = await Test.createTestingModule({ imports: [GlobalModule] }).compile();
        const global = await module.createNestApplication().init();
        await request(global.getHttpServer()).get('/health').expect(401);
        await request(global.getHttpServer()).get('/orders/catalog').expect(200);
        await global.close();
    });
});
