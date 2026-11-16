import { Controller, INestApplication, Module, UseGuards } from '@nestjs/common';
import { ClientProxy, ClientsModule, MessagePattern, Payload, Transport } from '@nestjs/microservices';
import { Test } from '@nestjs/testing';
import { firstValueFrom } from 'rxjs';

import { AuthContext, AuthGuard, CurrentAuth, CurrentUser, JwtStrategy, unauthorized } from '../../src';
import { authImports, john, User } from '../fixtures';

const PORT = 4789;

@Controller()
class MessagesController {
    @MessagePattern('me')
    @UseGuards(new AuthGuard({ strategies: { jwt: {} }, required: true }))
    me(@CurrentUser() user: User, @CurrentAuth() auth: AuthContext<User>, @Payload() data: any) {
        return { email: user.email, transport: auth.transport, value: data.value };
    }

    @MessagePattern('strict')
    @UseGuards(new AuthGuard({ strategies: { jwt: {} }, required: true, exceptionFactory: unauthorized() }))
    strict() {
        return true;
    }
}

@Module({
    imports: [
        ...authImports(),
        ClientsModule.register([{ name: 'CLIENT', transport: Transport.TCP, options: { port: PORT } }])
    ],
    controllers: [MessagesController]
})
class RpcAppModule {}

describe('E2E microservices (TCP)', () => {
    let app: INestApplication;
    let client: ClientProxy;

    beforeAll(async () => {
        const module = await Test.createTestingModule({ imports: [RpcAppModule] }).compile();
        app = module.createNestApplication();
        app.connectMicroservice({ transport: Transport.TCP, options: { port: PORT } });
        await app.startAllMicroservices();
        await app.init();
        client = app.get('CLIENT');
        await client.connect();
    });
    afterAll(async () => {
        client.close();
        await app.close();
    });

    test('authenticates with data.headers', async () => {
        const token = app.get(JwtStrategy).sign(john.authSerialize());
        await expect(
            firstValueFrom(client.send('me', { headers: { authorization: `Bearer ${token}` }, value: 42 }))
        ).resolves.toEqual({ email: john.email, transport: 'rpc', value: 42 });
    });

    test('rejects an unauthenticated message', async () => {
        await expect(firstValueFrom(client.send('me', { value: 1 }))).rejects.toMatchObject({
            message: 'Forbidden resource'
        });
        await expect(firstValueFrom(client.send('strict', {}))).rejects.toEqual({
            status: 401,
            message: 'Unauthorized'
        });
    });
});
