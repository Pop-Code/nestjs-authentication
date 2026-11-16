/**
 * The code of the wiki "Testing" page, tested as is.
 * Keep it in sync with https://github.com/Pop-Code/nestjs-authentication/wiki/Testing
 */
import { Controller, Get, INestApplication, Module } from '@nestjs/common';
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
import { appAuthImports } from './app/auth';
import { User } from './app/user';
import { UsersService } from './app/users.service';

// the code under test
@Controller('orders')
class OrdersController {
    @Get()
    @Auth()
    list(@CurrentUser() user: User) {
        return { owner: user.email };
    }
}

class OrdersService {
    constructor(private readonly auth: AuthContextService<User>) {}

    create(item: string) {
        return { item, owner: this.auth.getUserOrFail().email };
    }
}

@Module({ imports: appAuthImports(), controllers: [OrdersController] })
class AppModule {}

describe('Testing page', () => {
    describe('with a real token', () => {
        let app: INestApplication;
        let token: string;

        beforeAll(async () => {
            const module = await Test.createTestingModule({ imports: [AppModule] }).compile();
            app = await module.createNestApplication().init();
            const user = await app.get(UsersService).register('john@example.com', 'secret');
            token = app.get(JwtStrategy).signUser(user);
        });
        afterAll(async () => await app.close());

        it('returns the orders of the user', async () => {
            await request(app.getHttpServer())
                .get('/orders')
                .set('Authorization', `Bearer ${token}`)
                .expect(200)
                .expect({ owner: 'john@example.com' });
        });

        it('rejects a request without token', async () => {
            await request(app.getHttpServer()).get('/orders').expect(401);
        });
    });

    describe('with a fake strategy', () => {
        let app: INestApplication;
        const john = new User('1', 'john@example.com', '');

        beforeAll(async () => {
            // replaces the jwt strategy: the x-test-user header logs a user in
            const fakeJwt: AuthStrategy<User> = {
                name: 'jwt',
                authenticate: async ({ request }) =>
                    request.headers['x-test-user'] === 'john' ? { user: john, scopes: ['orders:read'] } : undefined
            };
            const module = await Test.createTestingModule({
                imports: [AppModule, AuthModule.registerStrategies([{ provide: 'FAKE_JWT', useValue: fakeJwt }])]
            }).compile();
            app = await module.createNestApplication().init();
        });
        afterAll(async () => await app.close());

        it('returns the orders of the user', async () => {
            await request(app.getHttpServer())
                .get('/orders')
                .set('x-test-user', 'john')
                .expect(200)
                .expect({ owner: 'john@example.com' });
        });
    });

    describe('a service that reads the current user', () => {
        const john = new User('1', 'john@example.com', '');
        const orders = new OrdersService(new AuthContextService<User>());

        it('creates an order for the current user', () => {
            const order = runWithAuthContext({ user: john, strategy: 'test', transport: 'test' }, () =>
                orders.create('book')
            );
            expect(order).toEqual({ item: 'book', owner: 'john@example.com' });
        });

        it('fails without a user', () => {
            expect(() => orders.create('book')).toThrow('Unauthorized');
        });
    });
});
