/**
 * The code of the wiki "WebSockets" page (ws adapter), tested as is.
 * Keep it in sync with https://github.com/Pop-Code/nestjs-authentication/wiki/WebSockets
 */
import { INestApplication, Module } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { WsAdapter } from '@nestjs/platform-ws';
import { OnGatewayConnection, SubscribeMessage, WebSocketGateway } from '@nestjs/websockets';
import { IncomingMessage } from 'http';
import { AddressInfo } from 'net';
import { Auth, CurrentUser, ExtractJwt, JwtStrategy, WsAuthTransport } from '../../src';
import WebSocket from 'ws';

import { appAuthImports, JWT_SECRET } from './app/auth';
import { User } from './app/user';
import { UsersService } from './app/users.service';

// events.gateway.ts
@WebSocketGateway({ path: '/events' })
export class EventsGateway implements OnGatewayConnection {
    // the ws adapter does not keep the upgrade request: give it to the transport
    handleConnection(client: WebSocket, request: IncomingMessage) {
        WsAuthTransport.setRequest(client, request);
    }

    @SubscribeMessage('profile')
    @Auth()
    profile(@CurrentUser() user: User) {
        return { event: 'profile', data: { email: user.email } };
    }
}

// app.module.ts
@Module({
    imports: appAuthImports({
        jwt: {
            secretOrKey: JWT_SECRET,
            algorithms: ['HS256'],
            // a browser cannot set the headers of a websocket: also read ?access_token=
            jwtFromRequest: ExtractJwt.fromExtractors([
                ExtractJwt.fromAuthHeaderAsBearerToken(),
                ExtractJwt.fromUrlQueryParameter('access_token')
            ])
        }
    }),
    providers: [EventsGateway]
})
class AppModule {}

describe('WebSockets page (ws adapter)', () => {
    let app: INestApplication;
    let url: string;
    let john: User;

    beforeAll(async () => {
        const module = await Test.createTestingModule({ imports: [AppModule] }).compile();
        app = module.createNestApplication();
        app.useWebSocketAdapter(new WsAdapter(app));
        await app.listen(0);
        url = `ws://localhost:${(app.getHttpServer().address() as AddressInfo).port}/events`;
        john = await app.get(UsersService).register('john@example.com', 'secret');
    });
    afterAll(async () => await app.close());

    const connect = (options: WebSocket.ClientOptions = {}, query = '') =>
        new Promise<WebSocket>((resolve, reject) => {
            const socket = new WebSocket(url + query, options);
            socket.once('open', () => resolve(socket));
            socket.once('error', reject);
        });
    const send = (socket: WebSocket, event: string) =>
        new Promise<any>((resolve) => {
            socket.once('message', (raw) => resolve(JSON.parse(raw.toString())));
            socket.send(JSON.stringify({ event, data: {} }));
        });

    test('the token of the upgrade request authenticates the messages', async () => {
        const token = app.get(JwtStrategy).signUser(john);
        const socket = await connect({ headers: { Authorization: `Bearer ${token}` } });
        await expect(send(socket, 'profile')).resolves.toEqual({ event: 'profile', data: { email: john.email } });
        socket.close();
    });

    test('a token in the query string', async () => {
        const token = app.get(JwtStrategy).signUser(john);
        const socket = await connect({}, `?access_token=${token}`);
        await expect(send(socket, 'profile')).resolves.toEqual({ event: 'profile', data: { email: john.email } });
        socket.close();
    });

    test('without a token the message is rejected', async () => {
        const socket = await connect();
        await expect(send(socket, 'profile')).resolves.toMatchObject({
            event: 'exception',
            data: { status: 401, message: 'Unauthorized' }
        });
        socket.close();
    });
});
