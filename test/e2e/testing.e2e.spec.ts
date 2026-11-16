/**
 * The code of the wiki "Testing" page, tested as is.
 * Keep it in sync with https://github.com/Pop-Code/nestjs-authentication/wiki/Testing
 */
import { Controller, Get, INestApplication, Injectable, Module } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';

import {
    Auth,
    AuthContextService,
    AuthModule,
    AuthStrategy,
    CurrentUser,
    JwtStrategy,
    runWithAuthContext
} from '../../src';
import { authImports, john, User } from '../fixtures';

@Injectable()
class OrderService {
    constructor(private readonly auth: AuthContextService<User>) {}

    create(item: string) {
        return { item, owner: this.auth.getUserOrFail().email };
    }
}

@Controller('orders')
class OrderController {
    constructor(private readonly orders: OrderService) {}

    @Get()
    @Auth({ strategies: { jwt: {} }, required: true })
    list(@CurrentUser('email') email: string) {
        return { email };
    }
}

describe('Testing page', () => {
    test('a real token', async () => {
        @Module({ imports: authImports(), controllers: [OrderController], providers: [OrderService] })
        class AppModule {}
        const module = await Test.createTestingModule({ imports: [AppModule] }).compile();
        const app: INestApplication = await module.createNestApplication().init();

        const token = app.get(JwtStrategy).sign(john.authSerialize());
        await request(app.getHttpServer())
            .get('/orders')
            .set('Authorization', `Bearer ${token}`)
            .expect(200)
            .expect({ email: john.email });
        await app.close();
    });

    test('a fake strategy replaces jwt', async () => {
        const fakeJwt: AuthStrategy = {
            name: 'jwt',
            authenticate: async ({ request }) =>
                request.headers['x-test-user'] === 'john' ? { user: john, namespace: 'default' } : undefined
        };
        @Module({
            imports: [...authImports(), AuthModule.registerStrategies([{ provide: 'FAKE_JWT', useValue: fakeJwt }])],
            controllers: [OrderController],
            providers: [OrderService]
        })
        class AppModule {}
        const module = await Test.createTestingModule({ imports: [AppModule] }).compile();
        const app: INestApplication = await module.createNestApplication().init();

        await request(app.getHttpServer())
            .get('/orders')
            .set('x-test-user', 'john')
            .expect(200)
            .expect({ email: john.email });
        await request(app.getHttpServer()).get('/orders').expect(403);
        await app.close();
    });

    test('a service with runWithAuthContext()', () => {
        const orders = new OrderService(new AuthContextService<User>());
        const order = runWithAuthContext({ user: john, strategy: 'test', transport: 'test' }, () =>
            orders.create('book')
        );
        expect(order).toEqual({ item: 'book', owner: john.email });
        expect(() => orders.create('book')).toThrow('Unauthorized');
    });
});
