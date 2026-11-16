/**
 * The code of the wiki "GraphQL" page, tested as is.
 * Keep it in sync with https://github.com/Pop-Code/nestjs-authentication/wiki/GraphQL
 */
import { ApolloDriver, ApolloDriverConfig } from '@nestjs/apollo';
import { INestApplication, Module } from '@nestjs/common';
import { Field, GraphQLModule, ID, ObjectType, Query, Resolver, Subscription } from '@nestjs/graphql';
import { Test } from '@nestjs/testing';
import { createClient } from 'graphql-ws';
import { AddressInfo } from 'net';
import request from 'supertest';
import WebSocket from 'ws';

import { Auth, CurrentUser, JwtStrategy, Public, RequireScopes } from '../../src';
import { appAuthImports } from './app/auth';
import { User } from './app/user';
import { UsersService } from './app/users.service';

// profile.model.ts
@ObjectType()
export class Profile {
    @Field(() => ID)
    id: string;

    @Field()
    email: string;
}

// profile.resolver.ts
@Resolver(() => Profile)
export class ProfileResolver {
    @Query(() => Profile)
    @Auth()
    me(@CurrentUser() user: User): Profile {
        return { id: user.id, email: user.email };
    }

    @Query(() => String)
    @Public()
    hello(@CurrentUser() user?: User): string {
        return user ? `Hello ${user.email}` : 'Hello guest';
    }

    @Query(() => [String])
    @Auth()
    @RequireScopes('orders:read')
    orders(): string[] {
        return ['order-1'];
    }

    @Subscription(() => Profile, { resolve: (profile: Profile) => profile })
    @Auth()
    async *profileChanged(@CurrentUser() user: User): AsyncGenerator<Profile> {
        yield { id: user.id, email: user.email };
    }
}

// app.module.ts
@Module({
    imports: [
        ...appAuthImports(),
        GraphQLModule.forRoot<ApolloDriverConfig>({
            driver: ApolloDriver,
            autoSchemaFile: true,
            subscriptions: { 'graphql-ws': true },
            // the request for the queries, and the connection for the subscriptions
            context: ({ req, res, connectionParams, extra }) => ({ req, res, connectionParams, extra })
        })
    ],
    providers: [ProfileResolver]
})
class AppModule {}

describe('GraphQL page', () => {
    let app: INestApplication;
    let token: string;
    let user: User;
    let wsUrl: string;

    beforeAll(async () => {
        const module = await Test.createTestingModule({ imports: [AppModule] }).compile();
        app = module.createNestApplication();
        await app.listen(0);
        wsUrl = `ws://localhost:${(app.getHttpServer().address() as AddressInfo).port}/graphql`;
        user = await app.get(UsersService).register('john@example.com', 'secret');
        token = app.get(JwtStrategy).signUser(user, { scope: ['orders:read'] });
    });
    afterAll(async () => await app.close());

    const query = (q: string, bearer?: string) => {
        const req = request(app.getHttpServer()).post('/graphql').send({ query: q });
        return bearer ? req.set('Authorization', `Bearer ${bearer}`) : req;
    };

    test('queries', async () => {
        expect((await query('{ me { id email } }', token)).body.data.me).toEqual({ id: user.id, email: user.email });
        const denied = await query('{ me { id } }');
        expect(denied.body.errors[0].message).toBe('Unauthorized');
        expect(denied.body.errors[0].extensions.code).toBe('UNAUTHENTICATED');
        expect(denied.body.data).toBeNull();

        expect((await query('{ hello }')).body.data.hello).toBe('Hello guest');
        expect((await query('{ hello }', token)).body.data.hello).toBe('Hello john@example.com');

        expect((await query('{ orders }', token)).body.data.orders).toEqual(['order-1']);
        const noScope = app.get(JwtStrategy).signUser(user);
        const forbidden = await query('{ orders }', noScope);
        expect(forbidden.body.errors[0].message).toBe('Insufficient scope');
        expect(forbidden.body.errors[0].extensions.code).toBe('FORBIDDEN');
        expect(forbidden.status).toBe(200); // GraphQL errors keep the http status 200
    });

    test('subscriptions', async () => {
        const client = createClient({
            url: wsUrl,
            webSocketImpl: WebSocket,
            connectionParams: { authorization: `Bearer ${token}` }
        });
        const result = await new Promise<any>((resolve, reject) => {
            let value: unknown;
            client.subscribe(
                { query: 'subscription { profileChanged { email } }' },
                { next: (v) => (value = v), error: reject, complete: () => resolve(value) }
            );
        });
        await client.dispose();
        expect(result).toEqual({ data: { profileChanged: { email: 'john@example.com' } } });
    });
});
