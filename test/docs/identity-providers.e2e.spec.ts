/**
 * The code of the wiki "Tokens (JWT) > Identity providers" section, tested as is with a local JWKS server.
 * Keep it in sync with https://github.com/Pop-Code/nestjs-authentication/wiki/JWT#identity-providers-jwks
 */
import { Controller, Get, INestApplication, Injectable, Module } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { generateKeyPairSync, KeyObject } from 'crypto';
import { createServer, Server } from 'http';
import jwt from 'jsonwebtoken';
import { passportJwtSecret } from 'jwks-rsa';
import { AddressInfo } from 'net';
import request from 'supertest';

import { Auth, AuthContext, AuthModule, AuthService, CurrentAuth, IAuthProvider, JwtStrategy } from '../../src';

// your users: they have the id of the identity provider
class User {
    constructor(
        public id: string,
        public externalId: string,
        public email?: string
    ) {}
}

@Injectable()
class UsersService {
    readonly users = new Map<string, User>();

    async findOrCreateByExternalId(externalId: string, email?: string): Promise<User> {
        let user = [...this.users.values()].find((u) => u.externalId === externalId);
        if (user === undefined) {
            user = new User(`u${this.users.size + 1}`, externalId, email);
            this.users.set(user.id, user);
        }
        return user;
    }
}

@Module({ providers: [UsersService], exports: [UsersService] })
class UsersModule {}

// loads the users of the tokens of the identity provider: `sub` is its id of the user
@Injectable()
class IdentityProviderUsers implements IAuthProvider<User> {
    constructor(private readonly users: UsersService) {}

    getName() {
        return 'idp';
    }

    async loadUser(payload: Record<string, any>) {
        return await this.users.findOrCreateByExternalId(payload.sub, payload.email);
    }
}

@Controller()
class OrderController {
    @Get('orders')
    @Auth({ strategies: { idp: {} }, required: true })
    orders(@CurrentAuth() auth: AuthContext<User>) {
        return { id: auth.user.id, externalId: auth.user.externalId, strategy: auth.strategy, scopes: auth.scopes };
    }
}

describe('Identity provider (JWKS)', () => {
    let jwksServer: Server;
    let issuer: string;
    let privateKey: KeyObject;
    let otherKey: KeyObject;
    let app: INestApplication;

    beforeAll(async () => {
        // a fake identity provider: publishes its public key as a JWKS
        const pair = generateKeyPairSync('rsa', { modulusLength: 2048 });
        privateKey = pair.privateKey;
        otherKey = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;
        const jwk = { ...pair.publicKey.export({ format: 'jwk' }), kid: 'key-1', use: 'sig', alg: 'RS256' };
        jwksServer = createServer((req, res) => {
            res.setHeader('content-type', 'application/json');
            res.end(JSON.stringify({ keys: [jwk] }));
        });
        await new Promise<void>((resolve) => jwksServer.listen(0, resolve));
        issuer = `http://localhost:${(jwksServer.address() as AddressInfo).port}/`;

        @Module({
            imports: [
                AuthModule.forRoot({}),
                AuthModule.registerAuthProviders([IdentityProviderUsers], [UsersModule]),
                AuthModule.registerStrategies([
                    {
                        provide: 'IDP_STRATEGY',
                        inject: [AuthService],
                        useFactory: (authService: AuthService) =>
                            new JwtStrategy(authService, {
                                name: 'idp',
                                namespace: 'idp',
                                secretOrKeyProvider: passportJwtSecret({
                                    jwksUri: `${issuer}.well-known/jwks.json`,
                                    cache: true,
                                    rateLimit: true
                                }),
                                algorithms: ['RS256'],
                                issuer,
                                audience: 'https://api.example.com'
                            })
                    }
                ])
            ],
            controllers: [OrderController]
        })
        class AppModule {}
        const module = await Test.createTestingModule({ imports: [AppModule] }).compile();
        app = await module.createNestApplication().init();
    });

    afterAll(async () => {
        await app.close();
        await new Promise((resolve) => jwksServer.close(resolve));
    });

    const token = (claims: Record<string, unknown> = {}, options: jwt.SignOptions = {}, key = privateKey) =>
        jwt.sign({ sub: 'idp|42', email: 'john@example.com', scope: 'orders:read', ...claims }, key, {
            algorithm: 'RS256',
            keyid: 'key-1',
            issuer,
            audience: 'https://api.example.com',
            expiresIn: 60,
            ...options
        });

    const get = (bearer?: string) => {
        const req = request(app.getHttpServer()).get('/orders');
        return bearer !== undefined ? req.set('Authorization', `Bearer ${bearer}`) : req;
    };

    test('a token of the identity provider is verified with its JWKS, and its user is found or created', async () => {
        const first = await get(token()).expect(200);
        expect(first.body).toEqual({ id: 'u1', externalId: 'idp|42', strategy: 'idp', scopes: ['orders:read'] });
        // the same user next time
        await get(token())
            .expect(200)
            .expect({ id: 'u1', externalId: 'idp|42', strategy: 'idp', scopes: ['orders:read'] });
    });

    test('a namespace claim cannot pick another auth provider', async () => {
        await get(token({ namespace: 'default' })).expect(200);
    });

    test('rejects the tokens that are not valid', async () => {
        await get().expect(403);
        await get(token({}, { audience: 'other-api' })).expect(403);
        await get(token({}, { issuer: 'https://evil.example.com/' })).expect(403);
        await get(token({}, {}, otherKey)).expect(403); // signed by another key
        await get(token({}, { keyid: 'unknown' })).expect(403); // a key the JWKS does not have
        await get(token({}, { expiresIn: -10 })).expect(403);
        await get(
            jwt.sign({ sub: 'idp|42' }, 'a-shared-secret', { issuer, audience: 'https://api.example.com' })
        ).expect(403); // HS256: not an accepted algorithm
    });
});
