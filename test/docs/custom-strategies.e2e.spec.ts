/**
 * The code of the wiki "Custom strategies" page, tested as is.
 * Keep it in sync with https://github.com/Pop-Code/nestjs-authentication/wiki/Custom-Strategies
 */
import { Controller, Get, INestApplication, Injectable, Module } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { createHash } from 'crypto';
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
    keyHash: string; // the sha256 of the key: the key itself is never stored
    scopes: string[];
}

// api-keys/api-clients.service.ts
@Injectable()
export class ApiClientsService {
    private readonly clients: ApiClient[] = [
        { id: 'c1', name: 'billing', keyHash: sha256('sk_live_billing'), scopes: ['orders:read'] }
    ];

    async findByKey(key: string): Promise<ApiClient | undefined> {
        return this.clients.find((client) => client.keyHash === sha256(key));
    }
}

function sha256(value: string): string {
    return createHash('sha256').update(value).digest('hex');
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

    beforeAll(async () => {
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
    });
    afterAll(async () => await app.close());

    test('an API key or a token', async () => {
        await request(app.getHttpServer())
            .get('/reports')
            .set('x-api-key', 'sk_live_billing')
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
});
