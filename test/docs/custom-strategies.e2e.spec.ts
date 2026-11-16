/**
 * The code of the wiki "Custom strategies" page, tested as is.
 * Keep it in sync with https://github.com/Pop-Code/nestjs-authentication/wiki/Custom-Strategies
 */
import { Controller, Get, INestApplication, Injectable, Module } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { createHmac, randomBytes, randomUUID } from 'crypto';
import request from 'supertest';

import {
    Auth,
    AuthContext,
    AuthModule,
    AuthStrategy,
    AuthStrategyContext,
    AuthStrategyResult,
    CurrentAuth,
    JwtStrategy
} from '../../src';
import { appAuthImports } from './app/auth';
import { UsersService } from './app/users.service';

// api-keys/api-client.ts
export interface ApiClient {
    id: string;
    name: string;
    keyHash: string; // the HMAC of the key: the key itself is never stored
    scopes: string[];
}

// api-keys/api-clients.service.ts
@Injectable()
export class ApiClientsService {
    // your table of clients, with an index on keyHash
    private readonly clients = new Map<string, ApiClient>();
    // a secret of the server, not stored with the clients (an environment variable, a vault...)
    private readonly pepper: string;

    constructor() {
        const pepper = process.env.API_KEY_PEPPER;
        if (pepper === undefined || pepper.length < 32) {
            throw new Error('API_KEY_PEPPER must be set (at least 32 characters)');
        }
        this.pepper = pepper;
    }

    /** Creates a client and returns its key: show it once to the client, it cannot be found again. */
    create(name: string, scopes: string[]): { client: ApiClient; key: string } {
        const key = `sk_${randomBytes(32).toString('base64url')}`; // 256 random bits
        const client: ApiClient = { id: randomUUID(), name, keyHash: this.hash(key), scopes };
        this.clients.set(client.keyHash, client);
        return { client, key };
    }

    async findByKey(key: string): Promise<ApiClient | undefined> {
        return this.clients.get(this.hash(key));
    }

    private hash(key: string): string {
        return createHmac('sha256', this.pepper).update(key).digest('hex');
    }
}

// api-keys/api-key.strategy.ts
@Injectable()
export class ApiKeyStrategy implements AuthStrategy<ApiClient> {
    readonly name = 'apikey';

    constructor(private readonly clients: ApiClientsService) {}

    async authenticate({ request }: AuthStrategyContext): Promise<AuthStrategyResult<ApiClient> | undefined> {
        const key = request.headers['x-api-key'];
        if (typeof key !== 'string') {
            return undefined; // no API key: the next strategy is tried
        }
        const client = await this.clients.findByKey(key);
        if (client === undefined) {
            return undefined; // a wrong key: the authentication fails
        }
        return { user: client, namespace: 'api', scopes: client.scopes };
    }
}

// api-keys/api-keys.module.ts
@Module({
    providers: [ApiClientsService],
    exports: [ApiClientsService]
})
export class ApiKeysModule {}

// reports.controller.ts
@Controller('reports')
export class ReportsController {
    @Get()
    @Auth({ strategies: { apikey: {}, jwt: {} } }) // an API key, or a token
    list(@CurrentAuth() auth: AuthContext) {
        return { strategy: auth.strategy, namespace: auth.namespace ?? null, scopes: auth.scopes };
    }
}

describe('Custom strategies page', () => {
    let app: INestApplication;
    let key: string;

    beforeAll(async () => {
        process.env.API_KEY_PEPPER = 'a-test-pepper-of-at-least-32-characters';
        @Module({
            imports: [
                ...appAuthImports(),
                ApiKeysModule,
                AuthModule.registerStrategies([ApiKeyStrategy], [ApiKeysModule])
            ],
            controllers: [ReportsController]
        })
        class AppModule {}
        const module = await Test.createTestingModule({ imports: [AppModule] }).compile();
        app = await module.createNestApplication().init();
        ({ key } = app.get(ApiClientsService).create('billing', ['orders:read']));
    });
    afterAll(async () => await app.close());

    test('an API key or a token', async () => {
        await request(app.getHttpServer())
            .get('/reports')
            .set('x-api-key', key)
            .expect(200)
            .expect({ strategy: 'apikey', namespace: 'api', scopes: ['orders:read'] });
        await request(app.getHttpServer()).get('/reports').set('x-api-key', 'wrong').expect(401);
        await request(app.getHttpServer()).get('/reports').expect(401);

        const user = await app.get(UsersService).register('john@example.com', 'secret');
        await request(app.getHttpServer())
            .get('/reports')
            .set('Authorization', `Bearer ${app.get(JwtStrategy).signUser(user)}`)
            .expect(200)
            .expect({ strategy: 'jwt', namespace: 'default', scopes: [] });
    });

    test('the keys are random, and only their HMAC is stored', () => {
        const clients = app.get(ApiClientsService);
        const first = clients.create('a', []);
        const second = clients.create('b', []);
        expect(first.key).toMatch(/^sk_[A-Za-z0-9_-]{43}$/);
        expect(first.key).not.toBe(second.key);
        expect(first.client.keyHash).not.toContain(first.key);
        expect(first.client.keyHash).toMatch(/^[0-9a-f]{64}$/);
    });
});
