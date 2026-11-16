import { INestApplication, Module, UseGuards, UseInterceptors } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { MessageBody, SubscribeMessage, WebSocketGateway } from '@nestjs/websockets';
import { AddressInfo } from 'net';
import { io, Socket } from 'socket.io-client';

import {
    AuthContext,
    AuthContextService,
    AuthGuard,
    CurrentAuth,
    CurrentUser,
    JwtStrategy,
    unauthorized,
    Auth,
    RequireScopes,
    AuthContextInterceptor
} from '../../src';
import { admin, authImports, john, User } from '../fixtures';

// NestJS < 12 does not apply the global interceptors to the gateways: needed by AuthContextService with new AuthGuard()
@UseInterceptors(AuthContextInterceptor)
@WebSocketGateway()
class EventsGateway {
    constructor(private readonly auth: AuthContextService<User>) {}

    @SubscribeMessage('me')
    @UseGuards(new AuthGuard({ strategies: { jwt: {} }, required: true }))
    me(@CurrentUser() user: User, @CurrentAuth() auth: AuthContext<User>, @MessageBody() body: unknown) {
        return { email: user.email, transport: auth.transport, namespace: auth.namespace, body };
    }

    @SubscribeMessage('service')
    @UseGuards(new AuthGuard({ strategies: { jwt: {} } }))
    service() {
        return { email: this.auth.getUser()?.email ?? null };
    }

    @SubscribeMessage('decorated')
    @Auth({ strategies: { jwt: {} }, required: true })
    @RequireScopes('chat:write')
    decorated(@CurrentUser('email') email: string) {
        return { email };
    }

    @SubscribeMessage('strict')
    @UseGuards(new AuthGuard({ strategies: { jwt: {} }, required: true, exceptionFactory: unauthorized() }))
    strict() {
        return { ok: true };
    }
}

@Module({ imports: authImports(), providers: [EventsGateway] })
class WsAppModule {}

describe('E2E websockets (socket.io)', () => {
    let app: INestApplication;
    let url: string;
    const sockets: Socket[] = [];

    const connect = async (options: Parameters<typeof io>[1] = {}) => {
        const socket = io(url, { transports: ['websocket'], forceNew: true, ...options });
        sockets.push(socket);
        await new Promise<void>((resolve, reject) => {
            socket.on('connect', () => resolve());
            socket.on('connect_error', reject);
        });
        return socket;
    };
    const emit = (socket: Socket, event: string, data: unknown = {}) =>
        new Promise<any>((resolve) => {
            socket.once('exception', (error) => resolve({ exception: error }));
            socket.emit(event, data, (response: unknown) => resolve(response));
        });

    beforeAll(async () => {
        const module = await Test.createTestingModule({ imports: [WsAppModule] }).compile();
        app = module.createNestApplication();
        await app.listen(0);
        url = `http://localhost:${(app.getHttpServer().address() as AddressInfo).port}`;
    });
    afterAll(async () => {
        sockets.forEach((s) => s.disconnect());
        await app.close();
    });

    test('authenticates with the handshake auth token', async () => {
        const token = app.get(JwtStrategy).sign(john.authSerialize());
        const socket = await connect({ auth: { token } });
        await expect(emit(socket, 'me', { a: 1 })).resolves.toEqual({
            email: john.email,
            transport: 'ws',
            namespace: 'default',
            body: { a: 1 }
        });
        // every message of the connection
        await expect(emit(socket, 'me')).resolves.toMatchObject({ email: john.email });
    });

    test('authenticates with the authorization header', async () => {
        const token = app.get(JwtStrategy).sign(admin.authSerialize());
        const socket = await connect({ extraHeaders: { Authorization: `Bearer ${token}` } });
        await expect(emit(socket, 'me')).resolves.toMatchObject({ email: admin.email, namespace: 'admin' });
    });

    test('AuthContextService in a gateway', async () => {
        const token = app.get(JwtStrategy).sign(john.authSerialize());
        await expect(emit(await connect({ auth: { token } }), 'service')).resolves.toEqual({ email: john.email });
        await expect(emit(await connect(), 'service')).resolves.toEqual({ email: null });
    });

    test('@Auth and @RequireScopes with the global guard', async () => {
        const writer = app.get(JwtStrategy).sign({ ...john.authSerialize(), scope: 'chat:write' });
        await expect(emit(await connect({ auth: { token: writer } }), 'decorated')).resolves.toEqual({
            email: john.email
        });
        const reader = app.get(JwtStrategy).sign(john.authSerialize());
        await expect(emit(await connect({ auth: { token: reader } }), 'decorated')).resolves.toMatchObject({
            exception: { status: 403, message: 'Insufficient scope' }
        });
        await expect(emit(await connect(), 'decorated')).resolves.toMatchObject({
            exception: { message: 'Forbidden resource' }
        });
    });

    test('rejects the messages of an unauthenticated connection', async () => {
        const socket = await connect();
        await expect(emit(socket, 'me')).resolves.toMatchObject({
            exception: { status: 'error', message: 'Forbidden resource' }
        });
        await expect(emit(socket, 'strict')).resolves.toMatchObject({
            exception: { status: 401, message: 'Unauthorized' }
        });
        const invalid = await connect({ auth: { token: 'invalid' } });
        await expect(emit(invalid, 'me')).resolves.toHaveProperty('exception');
    });
});
