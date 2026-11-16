/**
 * The code of the wiki "WebSockets" page (socket.io), tested as is.
 * Keep it in sync with https://github.com/Pop-Code/nestjs-authentication/wiki/WebSockets
 */
import { INestApplication, Module } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { MessageBody, SubscribeMessage, WebSocketGateway } from '@nestjs/websockets';
import { AddressInfo } from 'net';
import { io, Socket } from 'socket.io-client';

import { Auth, CurrentUser, JwtStrategy, RequireScopes } from '../../src';
import { appAuthImports } from './app/auth';
import { User } from './app/user';
import { UsersService } from './app/users.service';

// chat.gateway.ts
@WebSocketGateway()
export class ChatGateway {
    @SubscribeMessage('message')
    @Auth()
    @RequireScopes('chat:write')
    message(@CurrentUser() user: User, @MessageBody() text: string) {
        return { from: user.email, text };
    }
}

describe('WebSockets page (socket.io)', () => {
    let app: INestApplication;
    let url: string;
    let user: User;
    const sockets: Socket[] = [];

    beforeAll(async () => {
        @Module({ imports: appAuthImports(), providers: [ChatGateway] })
        class AppModule {}
        const module = await Test.createTestingModule({ imports: [AppModule] }).compile();
        app = module.createNestApplication();
        await app.listen(0);
        url = `http://localhost:${(app.getHttpServer().address() as AddressInfo).port}`;
        user = await app.get(UsersService).register('john@example.com', 'secret');
    });
    afterAll(async () => {
        sockets.forEach((socket) => socket.disconnect());
        await app.close();
    });

    // the client: io(url, { auth: { token } })
    const connect = (token?: string) =>
        new Promise<Socket>((resolve, reject) => {
            const socket = io(url, { transports: ['websocket'], forceNew: true, auth: token ? { token } : {} });
            sockets.push(socket);
            socket.once('connect', () => resolve(socket));
            socket.once('connect_error', reject);
        });
    const emit = (socket: Socket, text: string) =>
        new Promise<any>((resolve) => {
            socket.once('exception', (error) => resolve({ exception: error }));
            socket.emit('message', text, (response: unknown) => resolve(response));
        });

    test('the token of the handshake authenticates the messages', async () => {
        const socket = await connect(app.get(JwtStrategy).signUser(user, { scope: ['chat:write'] }));
        await expect(emit(socket, 'hi')).resolves.toEqual({ from: 'john@example.com', text: 'hi' });
    });

    test('the errors', async () => {
        await expect(emit(await connect(), 'hi')).resolves.toMatchObject({
            exception: { status: 401, message: 'Unauthorized' }
        });
        const noScope = await connect(app.get(JwtStrategy).signUser(user));
        await expect(emit(noScope, 'hi')).resolves.toMatchObject({
            exception: { status: 403, message: 'Insufficient scope' }
        });
    });
});
