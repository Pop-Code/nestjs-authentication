# nestjs-authentication

[![Test](https://github.com/Pop-Code/nestjs-authentication/actions/workflows/test.yml/badge.svg?branch=master)](https://github.com/Pop-Code/nestjs-authentication/actions/workflows/test.yml)
[![npm](https://img.shields.io/npm/v/nestjs-authentication.svg)][npm]
[![codecov](https://codecov.io/gh/Pop-Code/nestjs-authentication/branch/master/graph/badge.svg)](https://codecov.io/gh/Pop-Code/nestjs-authentication)

Authentication for [NestJS](https://nestjs.com) with several user sources, built on [passport](https://www.passportjs.org).

- One guard, `AuthGuard`, that tries one or more passport strategies in order, optionally from the session first
- Built-in `emailpassword` (passport-local) and `jwt` (passport-jwt) strategies
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
npm install nestjs-authentication @nestjs/passport passport
# for login sessions
npm install express-session
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
                jwt: {
                    secretOrKey: config.getOrThrow('JWT_SECRET'),
                    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken()
                }
            })
        }),
        AuthModule.registerAuthProviders([
            {
                provide: 'USERS',
                inject: [ENCRYPTOR, UserRepository],
                // the "default" namespace; UserRepository implements IUserProvider (findOne)
                useFactory: (encryptor: IEncryptor, users: UserRepository) =>
                    new AuthMemoryUserProvider('default', users, encryptor)
            }
        ])
    ],
    controllers: [AuthController]
})
export class AppModule {}

// auth.controller.ts
@Controller('auth')
export class AuthController {
    constructor(@Inject(JwtStrategy) private readonly jwt: JwtStrategy) {}

    // email + password in the body; stores the user in the session and returns a token
    @Post('login')
    @UseGuards(new AuthGuard({ strategies: { emailpassword: { session: true } }, required: true }))
    login(@CurrentUser() user: User) {
        return { token: this.jwt.sign(user.authSerialize(), undefined, { expiresIn: '1h' }) };
    }

    // a session cookie or a bearer token; 401 if there is none
    @Get('me')
    @UseGuards(new AuthGuard({ strategies: { jwt: {} }, fromSession: true, required: true, exceptionFactory: unauthorized() }))
    me(@CurrentUser() user: User) {
        return user;
    }
}

// events.gateway.ts: the same guard on websockets (token in the socket.io handshake auth), GraphQL and microservices
@SubscribeMessage('me')
@UseGuards(new AuthGuard({ strategies: { jwt: {} }, required: true }))
me(@CurrentUser() user: User) {
    return user;
}

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
