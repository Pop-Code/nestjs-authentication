/**
 * The code of the wiki "Microservices" page, tested as is (TCP transporter): an API forwards the token of the user
 * to an orders microservice. Keep it in sync with https://github.com/Pop-Code/nestjs-authentication/wiki/Microservices
 */
import {
    Controller,
    Get,
    Headers,
    Inject,
    INestApplication,
    INestMicroservice,
    Injectable,
    Module,
    Query
} from '@nestjs/common';
import { ClientProxy, ClientsModule, MessagePattern, Payload, Transport } from '@nestjs/microservices';
import { Test } from '@nestjs/testing';
import { firstValueFrom } from 'rxjs';
import request from 'supertest';

import { Auth, CurrentUser, JwtStrategy } from '../../src';
import { appAuthImports, testEncryptor } from './app/auth';
import { User } from './app/user';
import { UsersService } from './app/users.service';

const ORDERS_PORT = 4791;

// ---------- the orders microservice ----------

// orders/orders.controller.ts
@Controller()
export class OrdersMessagesController {
    @MessagePattern('orders.list')
    @Auth()
    list(@CurrentUser() user: User, @Payload() data: { page: number }) {
        return { owner: user.email, page: data.page, orders: [] };
    }
}

// orders/orders.module.ts
@Module({ imports: appAuthImports(), controllers: [OrdersMessagesController] })
export class OrdersModule {}

// ---------- the API, a client of the microservice ----------

// api/orders.client.ts
@Injectable()
export class OrdersClient {
    constructor(@Inject('ORDERS_SERVICE') private readonly client: ClientProxy) {}

    list(authorization: string, page: number) {
        // the token goes in data.headers, next to the data
        return firstValueFrom(this.client.send('orders.list', { headers: { authorization }, page }));
    }
}

// api/orders.controller.ts
@Controller('orders')
export class ApiOrdersController {
    constructor(private readonly orders: OrdersClient) {}

    @Get()
    @Auth()
    list(@Headers('authorization') authorization: string, @Query('page') page = '1') {
        // forwards the token of the user: the microservice knows who asks
        return this.orders.list(authorization, Number(page));
    }
}

// api/api.module.ts
@Module({
    imports: [
        ...appAuthImports(),
        ClientsModule.register([
            { name: 'ORDERS_SERVICE', transport: Transport.TCP, options: { host: 'localhost', port: ORDERS_PORT } }
        ])
    ],
    controllers: [ApiOrdersController],
    providers: [OrdersClient]
})
export class ApiModule {}

describe('Microservices page', () => {
    // the two services share their users, like two services that use the same database
    const users = new UsersService(testEncryptor);
    let microservice: INestMicroservice;
    let api: INestApplication;
    let token: string;

    beforeAll(async () => {
        const ordersModule = await Test.createTestingModule({ imports: [OrdersModule] })
            .overrideProvider(UsersService)
            .useValue(users)
            .compile();
        // orders/main.ts: a standalone microservice
        microservice = ordersModule.createNestMicroservice({
            transport: Transport.TCP,
            options: { port: ORDERS_PORT }
        });
        await microservice.listen();

        const apiModule = await Test.createTestingModule({ imports: [ApiModule] })
            .overrideProvider(UsersService)
            .useValue(users)
            .compile();
        api = await apiModule.createNestApplication().init();

        const user = await users.register('john@example.com', 'secret');
        token = api.get(JwtStrategy).signUser(user);
    });
    afterAll(async () => {
        await api.close();
        await microservice.close();
    });

    test('the API forwards the token of the user to the microservice', async () => {
        await request(api.getHttpServer())
            .get('/orders?page=2')
            .set('Authorization', `Bearer ${token}`)
            .expect(200)
            .expect({ owner: 'john@example.com', page: 2, orders: [] });
    });

    test('the microservice rejects a message without token', async () => {
        await expect(api.get(OrdersClient).list('', 1)).rejects.toEqual({ status: 401, message: 'Unauthorized' });
    });
});

describe('Microservices page (hybrid application)', () => {
    test('inheritAppConfig: true protects the handlers of a hybrid application', async () => {
        const port = ORDERS_PORT + 1;
        @Module({
            imports: [
                ...appAuthImports(),
                ClientsModule.register([{ name: 'ORDERS_SERVICE', transport: Transport.TCP, options: { port } }])
            ],
            controllers: [OrdersMessagesController],
            providers: [OrdersClient]
        })
        class HybridModule {}
        const module = await Test.createTestingModule({ imports: [HybridModule] }).compile();
        const app = module.createNestApplication();
        // main.ts of a hybrid application
        app.connectMicroservice({ transport: Transport.TCP, options: { port } }, { inheritAppConfig: true });
        await app.startAllMicroservices();
        await app.init();

        const user = await app.get(UsersService).register('jane@example.com', 'secret');
        const token = app.get(JwtStrategy).signUser(user);
        await expect(app.get(OrdersClient).list(`Bearer ${token}`, 1)).resolves.toEqual({
            owner: 'jane@example.com',
            page: 1,
            orders: []
        });
        await expect(app.get(OrdersClient).list('', 1)).rejects.toEqual({ status: 401, message: 'Unauthorized' });
        await app.close();
    });
});
