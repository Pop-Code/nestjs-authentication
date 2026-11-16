# nestjs-authentication

[![Test](https://github.com/Pop-Code/nestjs-authentication/actions/workflows/test.yml/badge.svg?branch=master)](https://github.com/Pop-Code/nestjs-authentication/actions/workflows/test.yml)
[![npm](https://img.shields.io/npm/v/nestjs-authentication.svg)][npm]
[![codecov](https://codecov.io/gh/Pop-Code/nestjs-authentication/branch/master/graph/badge.svg)](https://codecov.io/gh/Pop-Code/nestjs-authentication)

Authentication for [NestJS](https://nestjs.com) with several user sources and every transport. Any [passport](https://www.passportjs.org) strategy works too, but passport is optional.

- One guard, global with `@Auth()` / `@Public()` or per route, that tries one or more strategies in order, optionally from the session first
- Native `jwt` (jsonwebtoken), `emailpassword` and `session` strategies, your own (`AuthStrategy`), and the passport ecosystem through an adapter
- Scopes: `@RequireScopes()` from the token claims or your roles, and the list of the scopes of the application
- Auth providers per **namespace**: users, admins, api clients... each loaded from its own source
- Login sessions (express-session), with the user stored as a small payload and loaded back on each request
- Every transport: http (express, fastify), GraphQL (queries, mutations, subscriptions), websockets (socket.io, ws), microservices
- `@CurrentUser()`, `@CurrentAuth()`, and the user of the current request in any service (`AuthContextService`)
- Password hashing with scrypt (built in), migration of legacy hashes on login, or your own encryptor (bcrypt, argon2...)

## Requirements

| nestjs-authentication | NestJS     | @nestjs/passport | passport | Node.js  |
| --------------------- | ---------- | ---------------- | -------- | -------- |
| 0.5.x                 | 10, 11, 12 | 10, 11, 12       | 0.6, 0.7 | >= 22.12 |
| 0.4.x                 | 8          | 8                | 0.5      | >= 14    |

## Install

```bash
npm install nestjs-authentication
# for login sessions
npm install express-session
# optional, to use passport strategies (OAuth providers, SAML, LDAP...)
npm install passport
```

## Quick start

```ts
// app.module.ts
@Module({
    imports: [
        AuthModule.forRootAsync({
            inject: [ConfigService],
            useFactory: (config: ConfigService) => ({
                encryptor: new ScryptEncryptor(),
                jwt: { secretOrKey: config.getOrThrow('JWT_SECRET'), algorithms: ['HS256'] },
                // the routes with @Auth() (or all of them with globalGuard: true)
                defaults: { strategies: { jwt: {} }, fromSession: true, required: true, exceptionFactory: unauthorized() }
            })
        }),
        // the users of the "default" namespace; UserRepository implements IUserProvider (findOne)
        AuthModule.registerAuthProviders(
            [
                {
                    provide: 'USERS',
                    inject: [ENCRYPTOR, UserRepository],
                    useFactory: (encryptor: IEncryptor, users: UserRepository) =>
                        new AuthMemoryUserProvider('default', users, encryptor)
                }
            ],
            [UserModule]
        )
    ],
    controllers: [AuthController, OrderController]
})
export class AppModule {}

// auth.controller.ts
@Controller('auth')
export class AuthController {
    constructor(private readonly jwt: JwtStrategy) {}

    // email + password in the body: stores the user in the session and returns a token
    @Post('login')
    @Auth({ strategies: { emailpassword: { session: true } } })
    login(@CurrentUser() user: User) {
        return { token: this.jwt.sign({ ...user.authSerialize(), scope: 'orders:read' }, undefined, { expiresIn: '1h' }) };
    }
}

// order.controller.ts: a session cookie or a bearer token (401 if there is none), and a scope of the token
@Auth()
@Controller('orders')
export class OrderController {
    constructor(private readonly auth: AuthContextService<User>) {}

    @Get()
    @RequireScopes('orders:read')
    list(@CurrentUser() user: User) {}
}

// events.gateway.ts: the same on websockets (token in the socket.io handshake auth), GraphQL and microservices
@SubscribeMessage('orders')
@Auth()
orders(@CurrentUser() user: User) {}

// main.ts
app.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false }));
```

## Documentation

- [Wiki](https://github.com/Pop-Code/nestjs-authentication/wiki)
- [API](https://pop-code.github.io/nestjs-authentication)
- [Changelog](https://github.com/Pop-Code/nestjs-authentication/blob/master/CHANGELOG.md)

## Development

```bash
yarn install
yarn lint && yarn build && yarn test
yarn doc # regenerate the API reference in ./docs
```

The tests need Node.js >= 24.9 (Jest loads the ESM-only NestJS 12 packages).
See [RELEASING.md](./RELEASING.md) to publish a version.

[npm]: https://www.npmjs.com/package/nestjs-authentication
