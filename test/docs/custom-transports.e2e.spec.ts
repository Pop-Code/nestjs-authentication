/**
 * The code of the wiki "Custom transports" page, tested as is.
 * Keep it in sync with https://github.com/Pop-Code/nestjs-authentication/wiki/Custom-Transports
 */
import { Controller, ExecutionContext, INestApplication, Module } from '@nestjs/common';
import { ClientProxy, ClientsModule, MessagePattern, Payload, Transport } from '@nestjs/microservices';
import { Test } from '@nestjs/testing';
import { firstValueFrom } from 'rxjs';

import {
    Auth,
    AuthGuard,
    AuthRequest,
    AuthStrategyRegistry,
    AuthTransport,
    AuthTransports,
    createRequest,
    CurrentUser,
    getRequestAuthContext,
    JwtStrategy,
    RequestCache,
    toAuthorization
} from '../../src';
import { appAuthImports } from './app/auth';
import { User } from './app/user';
import { UsersService } from './app/users.service';

// meta-token.transport.ts: the messages carry their token in data.meta.token
export class MetaTokenTransport implements AuthTransport {
    // the name of the built-in transport: its errors are still converted to RpcException
    readonly name = 'rpc';
    private readonly requests = new RequestCache();

    supports(context: ExecutionContext): boolean {
        return context.getType() === 'rpc';
    }

    getRequest(context: ExecutionContext): AuthRequest {
        const data = context.switchToRpc().getData();
        // one request per message: the guard and the decorators share it
        return this.requests.get(data, () => {
            const authorization = toAuthorization(data?.meta?.token); // 'abc' -> 'Bearer abc'
            return createRequest(undefined, {
                headers: authorization ? { authorization } : {},
                body: data
            });
        });
    }
}

// orders.controller.ts
@Controller()
export class OrdersMessagesController {
    @MessagePattern('orders.list')
    @Auth()
    list(@CurrentUser() user: User, @Payload() data: { page: number }) {
        return { owner: user.email, page: data.page };
    }
}

const PORT = 4795;

describe('Custom transports page', () => {
    afterEach(() => AuthTransports.reset()); // the registered transports are global: reset them between tests

    test('change how a built-in transport reads the credentials', async () => {
        @Module({
            imports: [
                ...appAuthImports({ transports: [new MetaTokenTransport()] }),
                ClientsModule.register([{ name: 'ORDERS', transport: Transport.TCP, options: { port: PORT } }])
            ],
            controllers: [OrdersMessagesController]
        })
        class AppModule {}
        const module = await Test.createTestingModule({ imports: [AppModule] }).compile();
        const app: INestApplication = module.createNestApplication();
        app.connectMicroservice({ transport: Transport.TCP, options: { port: PORT } }, { inheritAppConfig: true });
        await app.startAllMicroservices();
        await app.init();
        const client = app.get<ClientProxy>('ORDERS');
        await client.connect();

        const user = await app.get(UsersService).register('john@example.com', 'secret');
        const token = app.get(JwtStrategy).signUser(user);
        // the client
        await expect(firstValueFrom(client.send('orders.list', { meta: { token }, page: 1 }))).resolves.toEqual({
            owner: 'john@example.com',
            page: 1
        });
        await expect(firstValueFrom(client.send('orders.list', { page: 1 }))).rejects.toEqual({
            status: 401,
            message: 'Unauthorized'
        });
        client.close();
        await app.close();
    });

    test('a context type the library does not know', async () => {
        // bot.transport.ts: e.g. a bot framework whose handlers have the context type 'bot'
        class BotTransport implements AuthTransport {
            readonly name = 'bot';
            private readonly requests = new RequestCache();

            supports(context: ExecutionContext): boolean {
                return context.getType<string>() === 'bot';
            }

            getRequest(context: ExecutionContext): AuthRequest {
                const update = context.getArgByIndex(0); // what the framework gives to the handler
                return this.requests.get(update, () =>
                    createRequest(undefined, { headers: { 'x-bot-user': String(update.from.id) }, body: update })
                );
            }
        }

        // a strategy for the users of the bot (see the Custom strategies page)
        const registry = new AuthStrategyRegistry().register({
            name: 'bot',
            authenticate: async ({ request }) =>
                request.headers['x-bot-user'] === '42' ? { user: { id: 42 }, namespace: 'bot' } : undefined
        });
        AuthTransports.register(new BotTransport());

        // what NestJS does before calling a handler: here by hand, with the context of the framework
        const botContext = (update: unknown) =>
            ({
                getType: () => 'bot',
                getArgByIndex: (index: number) => [update][index],
                getHandler: () => undefined,
                getClass: () => undefined
            }) as unknown as ExecutionContext;
        const guard = new AuthGuard({ strategies: { bot: {} }, required: true }, registry);

        const update = { from: { id: 42 }, text: '/orders' };
        await expect(guard.canActivate(botContext(update))).resolves.toBe(true);
        const request = AuthTransports.get(botContext(update)).getRequest(botContext(update));
        expect(getRequestAuthContext(request)).toMatchObject({ user: { id: 42 }, strategy: 'bot', transport: 'bot' });
        await expect(guard.canActivate(botContext({ from: { id: 7 } }))).resolves.toBe(false);
    });
});
