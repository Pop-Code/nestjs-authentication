/**
 * The code of the wiki "The current user" page, tested as is.
 * Keep it in sync with https://github.com/Pop-Code/nestjs-authentication/wiki/Auth-Context
 */
import { Body, Controller, INestApplication, Injectable, Module, Post } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';

import { Auth, AuthContextService, JwtStrategy, runWithAuthContext } from '../../src';
import { appAuthImports } from './app/auth';
import { User } from './app/user';
import { UsersService } from './app/users.service';

// orders/orders.service.ts: no request, no parameter: the user of the current request
@Injectable()
export class OrdersService {
    constructor(private readonly auth: AuthContextService<User>) {}

    async create(item: string) {
        await new Promise((resolve) => setTimeout(resolve, 1)); // still available after an await
        const user = this.auth.getUserOrFail();
        return { item, ownerId: user.id, via: this.auth.get()?.strategy };
    }
}

// orders/orders.controller.ts
@Controller('orders')
export class OrdersController {
    constructor(private readonly orders: OrdersService) {}

    @Post()
    @Auth()
    create(@Body() body: { item: string }) {
        return this.orders.create(body.item);
    }
}

describe('The current user page', () => {
    let app: INestApplication;
    let user: User;

    beforeAll(async () => {
        @Module({ imports: appAuthImports(), controllers: [OrdersController], providers: [OrdersService] })
        class AppModule {}
        const module = await Test.createTestingModule({ imports: [AppModule] }).compile();
        app = await module.createNestApplication().init();
        user = await app.get(UsersService).register('john@example.com', 'secret');
    });
    afterAll(async () => await app.close());

    test('in a service', async () => {
        await request(app.getHttpServer())
            .post('/orders')
            .set('Authorization', `Bearer ${app.get(JwtStrategy).signUser(user)}`)
            .send({ item: 'book' })
            .expect(201)
            .expect({ item: 'book', ownerId: user.id, via: 'jwt' });
    });

    test('in a job', async () => {
        const order = await runWithAuthContext({ user, strategy: 'job', transport: 'queue' }, () =>
            app.get(OrdersService).create('book')
        );
        expect(order).toEqual({ item: 'book', ownerId: user.id, via: 'job' });
        await expect(app.get(OrdersService).create('book')).rejects.toThrow('Unauthorized');
    });
});
