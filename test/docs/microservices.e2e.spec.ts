/**
 * The code of the wiki "Microservices" page, tested as is (TCP transporter).
 * Keep it in sync with https://github.com/Pop-Code/nestjs-authentication/wiki/Microservices
 */
import { Controller, INestApplication, Module } from '@nestjs/common';
import { ClientProxy, ClientsModule, MessagePattern, Payload, Transport } from '@nestjs/microservices';
import { Test } from '@nestjs/testing';
import { firstValueFrom } from 'rxjs';

import { Auth, CurrentUser, JwtStrategy } from '../../src';
import { appAuthImports } from './app/auth';
import { User } from './app/user';
import { UsersService } from './app/users.service';

const PORT = 4791;

// orders.controller.ts (the microservice)
@Controller()
export class OrdersMessagesController {
    @MessagePattern('orders.list')
    @Auth()
    list(@CurrentUser() user: User, @Payload() data: { page: number }) {
        return { owner: user.email, page: data.page, orders: [] };
    }
}

describe('Microservices page', () => {
    let app: INestApplication;
    let client: ClientProxy;
    let user: User;

    beforeAll(async () => {
        @Module({
            imports: [
                ...appAuthImports(),
                ClientsModule.register([{ name: 'ORDERS', transport: Transport.TCP, options: { port: PORT } }])
            ],
            controllers: [OrdersMessagesController]
        })
        class AppModule {}
        const module = await Test.createTestingModule({ imports: [AppModule] }).compile();
        app = module.createNestApplication();
        // inheritAppConfig: the global guard of the AuthModule also protects the microservice
        app.connectMicroservice({ transport: Transport.TCP, options: { port: PORT } }, { inheritAppConfig: true });
        await app.startAllMicroservices();
        await app.init();
        client = app.get('ORDERS');
        await client.connect();
        user = await app.get(UsersService).register('john@example.com', 'secret');
    });
    afterAll(async () => {
        client.close();
        await app.close();
    });

    test('the token in data.headers', async () => {
        const token = app.get(JwtStrategy).signUser(user);
        // the client
        const orders = await firstValueFrom(
            client.send('orders.list', { headers: { authorization: `Bearer ${token}` }, page: 1 })
        );
        expect(orders).toEqual({ owner: 'john@example.com', page: 1, orders: [] });
    });

    test('without a token', async () => {
        await expect(firstValueFrom(client.send('orders.list', { page: 1 }))).rejects.toEqual({
            status: 401,
            message: 'Unauthorized'
        });
    });
});

describe('Microservices page (standalone microservice)', () => {
    test('the global guard protects a standalone microservice', async () => {
        const port = PORT + 1;
        @Module({
            imports: [
                ...appAuthImports(),
                ClientsModule.register([{ name: 'ORDERS', transport: Transport.TCP, options: { port } }])
            ],
            controllers: [OrdersMessagesController]
        })
        class MicroserviceModule {}
        const module = await Test.createTestingModule({ imports: [MicroserviceModule] }).compile();
        const microservice = module.createNestMicroservice({ transport: Transport.TCP, options: { port } });
        await microservice.listen();
        const client = microservice.get<ClientProxy>('ORDERS');
        await client.connect();

        const user = await microservice.get(UsersService).register('jane@example.com', 'secret');
        const token = microservice.get(JwtStrategy).signUser(user);
        await expect(
            firstValueFrom(client.send('orders.list', { headers: { authorization: `Bearer ${token}` }, page: 2 }))
        ).resolves.toEqual({ owner: 'jane@example.com', page: 2, orders: [] });
        await expect(firstValueFrom(client.send('orders.list', { page: 2 }))).rejects.toEqual({
            status: 401,
            message: 'Unauthorized'
        });
        client.close();
        await microservice.close();
    });
});
