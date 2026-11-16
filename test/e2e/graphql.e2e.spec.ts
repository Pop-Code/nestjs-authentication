import { ApolloDriver, ApolloDriverConfig } from '@nestjs/apollo';
import { INestApplication, Module, UseGuards } from '@nestjs/common';
import { Field, GraphQLModule, ObjectType, Query, Resolver, Subscription } from '@nestjs/graphql';
import { Test } from '@nestjs/testing';
import { createClient } from 'graphql-ws';
import { AddressInfo } from 'net';
import request from 'supertest';
import WebSocket from 'ws';

import { AuthContext, AuthContextService, AuthGuard, CurrentAuth, CurrentUser, JwtStrategy } from '../../src';
import { admin, authImports, john, User } from '../fixtures';

@ObjectType()
class Me {
    @Field()
    email: string;
    @Field()
    namespace: string;
    @Field()
    transport: string;
}

@Resolver(() => Me)
class MeResolver {
    constructor(private readonly auth: AuthContextService<User>) {}

    @Query(() => Me)
    @UseGuards(new AuthGuard({ strategies: { jwt: {} }, required: true }))
    me(@CurrentUser() user: User, @CurrentAuth() auth: AuthContext<User>): Me {
        return { email: user.email, namespace: auth.namespace ?? '', transport: auth.transport };
    }

    @Query(() => String, { nullable: true })
    @UseGuards(new AuthGuard({ strategies: { jwt: {} } }))
    async email(): Promise<string | undefined> {
        await new Promise((r) => setTimeout(r, 1));
        return this.auth.getUser()?.email;
    }

    @Subscription(() => Me, { resolve: (value: Me) => value })
    @UseGuards(new AuthGuard({ strategies: { jwt: {} }, required: true }))
    async *meChanged(@CurrentUser() user: User, @CurrentAuth() auth: AuthContext<User>): AsyncGenerator<Me> {
        yield { email: user.email, namespace: auth.namespace ?? '', transport: auth.transport };
    }
}

@Module({
    imports: [
        ...authImports(),
        GraphQLModule.forRoot<ApolloDriverConfig>({
            driver: ApolloDriver,
            autoSchemaFile: true,
            subscriptions: { 'graphql-ws': true },
            context: ({ req, res, connectionParams, extra }) => ({ req, res, connectionParams, extra })
        })
    ],
    providers: [MeResolver]
})
class GraphqlAppModule {}

describe('E2E GraphQL (apollo)', () => {
    let app: INestApplication;
    let wsUrl: string;
    let token: string;

    beforeAll(async () => {
        const module = await Test.createTestingModule({ imports: [GraphqlAppModule] }).compile();
        app = module.createNestApplication();
        await app.listen(0);
        wsUrl = `ws://localhost:${(app.getHttpServer().address() as AddressInfo).port}/graphql`;
        token = app.get(JwtStrategy).sign(john.authSerialize());
    });
    afterAll(async () => await app.close());

    const query = (q: string, auth?: string) => {
        const req = request(app.getHttpServer()).post('/graphql').send({ query: q });
        return auth !== undefined ? req.set('Authorization', auth) : req;
    };

    test('queries over http', async () => {
        const res = await query('{ me { email namespace transport } }', `Bearer ${token}`).expect(200);
        expect(res.body.data.me).toEqual({ email: john.email, namespace: 'default', transport: 'graphql' });
        const unauthenticated = await query('{ me { email } }').expect(200);
        expect(unauthenticated.body.errors[0].message).toBe('Forbidden resource');
    });

    test('AuthContextService in a resolver', async () => {
        expect((await query('{ email }', `Bearer ${token}`)).body.data.email).toBe(john.email);
        expect((await query('{ email }')).body.data.email).toBeNull();
    });

    const subscribe = (connectionParams: Record<string, unknown>) => {
        const client = createClient({
            url: wsUrl,
            webSocketImpl: WebSocket,
            connectionParams,
            lazy: true,
            retryAttempts: 0
        });
        return new Promise<any>((resolve) => {
            let result: any;
            client.subscribe(
                { query: 'subscription { meChanged { email namespace transport } }' },
                {
                    next: (value) => (result = value),
                    error: (error) => {
                        resolve({ error });
                        void client.dispose();
                    },
                    complete: () => {
                        resolve(result);
                        void client.dispose();
                    }
                }
            );
        });
    };

    test('subscriptions over graphql-ws with the token in the connection params', async () => {
        await expect(subscribe({ authorization: `Bearer ${token}` })).resolves.toEqual({
            data: { meChanged: { email: john.email, namespace: 'default', transport: 'graphql' } }
        });
        const adminToken = app.get(JwtStrategy).sign(admin.authSerialize());
        await expect(subscribe({ token: adminToken })).resolves.toMatchObject({
            data: { meChanged: { email: admin.email, namespace: 'admin' } }
        });
    });

    test('subscriptions reject an unauthenticated connection', async () => {
        const result = await subscribe({});
        const errors = result.errors ?? result.error;
        expect(JSON.stringify(errors)).toContain('Forbidden resource');
    });
});
