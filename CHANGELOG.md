# Changelog

All notable changes to this project will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - 2026-11-16

See the [upgrade guide](https://github.com/Pop-Code/nestjs-authentication/wiki/Upgrading).

### BREAKING CHANGE

- Support NestJS v12 only (peer dependencies `@nestjs/common` and `@nestjs/core` `^12.0.0`), drop NestJS v8
- Node engine is now `>= 22.12.0` (required to load the ESM-only NestJS v12 packages with `require(esm)`)
- passport is optional: the strategies are native ([`AuthStrategy`](https://github.com/Pop-Code/nestjs-authentication/wiki/Strategies)), and the passport strategies work through an adapter when passport is installed
    - `@nestjs/passport` is no longer a peer dependency, `passport` is an optional one (`^0.6.0 || ^0.7.0`: 0.5 is affected by a session fixation vulnerability, CVE-2022-25896), and `passport-jwt`, `passport-local` and `debug` are no longer dependencies
    - `JwtStrategy` (built on jsonwebtoken v9, see its [migration notes](https://github.com/auth0/node-jsonwebtoken/wiki/Migration-Notes:-v8-to-v9)) and `EmailPasswordStrategy` are native strategies: they no longer extend `PassportStrategy` and are not registered in passport. Their constructors, `validate()`, `getNamespace()` and `JwtStrategy.sign()` are unchanged
    - `JwtStrategyOptions` has the option names of passport-jwt (`secretOrKey`, `secretOrKeyProvider`, `jwtFromRequest`, `algorithms`, `issuer`, `audience`, `ignoreExpiration`, `jsonWebTokenOptions`); `passReqToCallback` is not accepted, and `jwtFromRequest` defaults to the bearer token. Import `ExtractJwt` from `nestjs-authentication` (the passport-jwt extractors still work)
    - `UserSerializer` is removed: the native `session` strategy stores the user in the same place (`session.passport.user`), so the existing sessions keep working
    - `passport.initialize()` is no longer applied to the routes; the guard adds `req.logIn()`, `req.logOut()` (with a callback) and `req.isAuthenticated()`, compatible with passport
- Logging in regenerates the session (against session fixation): set `keepSessionInfo: true` in the strategy options to keep its data
- A session whose user or auth provider does not exist anymore is not authenticated (the user is removed from the session); the other errors of `loadUser()` are thrown
- `AuthGuard` with `fromSession: true` fails (500) when there is no session middleware, instead of silently ignoring the session
- `AuthModule` registers `AuthGuard` as a global guard. It only acts on the routes with `@Auth()`, `@Public()` or `@RequireScopes()` (or all of them with `globalGuard: true`), so the routes protected with `@UseGuards(new AuthGuard(...))` are not affected
- Your users keep their shape: `IAuthUser` (`authSerialize()`) and the `_id` / `email` / `passwordEncrypted` properties are no longer required
    - `AuthMemoryUserProvider` is renamed `EmailPasswordAuthProvider` (the old name is a deprecated alias): it takes your functions (`findById`, `findByEmail`, `getId`, `getPasswordHash`, `updatePasswordHash`) instead of a user provider. The 0.4 constructor `(namespace, userProvider, encryptor)` still works
    - With the 0.4 constructor, the user provider only receives `findOne({ _id })` or `findOne({ email })`: it no longer receives the password in clear text, nor the other properties of the payload
    - The payload stored in the sessions and the tokens is built by the auth provider: `{ sub, namespace }` (`user.authSerialize()` is still used when the user implements it). The `_id` and `id` of the existing sessions and tokens are still read
    - `MemoryUser` is renamed `EmailPasswordUser` and `MemoryUserCredentials` `EmailPasswordCredentials` (deprecated aliases)
- `AuthGuard.getRequestReponse()` (typo) is renamed `getRequestResponse()`
- `AuthService.loadUser()` is typed `Promise<U | undefined>`
- `Encryptor` throws if the key is not 32 bytes or the iv is not 16 bytes (it threw on the first `encrypt()`)

### Deprecated

- `AuthGuard.scopes` and `AuthGuard.registerScopes()`: use the `AuthScopes` service
- The `Encryptor` (aes-256-ctr with a fixed key and iv) is kept for compatibility: prefer `ScryptEncryptor`, and `MigratingEncryptor` to migrate the stored passwords

### Fixed

- `forRootAsync()`: the `imports` are imported by the module, so `inject` can use their providers (they were ignored)
- `AuthGuard`: `null` users are not logged in (a `typeof user !== null` check was always true), and `request.authInfo` is an object keyed by strategy (it was an array)
- `EmailPasswordStrategy` no longer throws when the request has no body (express 5), and ignores a non string namespace
- Websockets and microservices are supported (they threw a `NotImplementedException`), and GraphQL subscriptions (they failed on the missing `context.req`)
- `registerAuthProviders()` accepts class providers, and the modules that provide their dependencies (`imports`)
- The module exports the `EmailPasswordStrategy`

### Added

- Strategies: the `AuthStrategy` interface, `AuthModule.registerStrategies(providers, imports?)`, the `AuthStrategyRegistry`, the native `session` strategy (`SessionStrategy`), and `PassportAuthStrategy` (any passport strategy by name, OAuth redirects end the request)
- `EmailPasswordAuthProvider<User>` options, `MemoryUserProvider<User>` accessors (`getId`, `getEmail`, `setPasswordHash`) with `findById()` and `findByEmail()`, `IAuthProvider.serializeUser()`, `AuthService.serializeUser()`, and `JwtStrategy.signUser(user, { expiresIn, scope, namespace, claims })`
- `JwtStrategy`: `secretOrKeyProvider` returns a promise or uses the passport-jwt callback (so `passportJwtSecret()` of jwks-rsa works for JWKS), `verify()`, `sign()` uses the `secretOrKey` option when no key is given, and the `scope` / `scp` / `scopes` claims are the scopes of the request
- `ExtractJwt` (passport-jwt API, plus `fromCookie()`)
- Global guard and decorators: `@Auth(options)` on a class or a method, `@Public()`, and the `defaults` and `globalGuard` module options
- Scopes: `@RequireScopes(...)` and `@RequireAnyScope(...)` (wildcards: `orders:*`, `*`), `AuthContext.scopes`, the `scopes` module option (e.g. roles as scopes), the `scopeExceptionFactory` guard option (default: 403 `Insufficient scope`), and the `AuthScopes` service that lists the scopes required and requested in the application
- Transports: the guard and the decorators work on http (express and fastify), GraphQL (queries, mutations and subscriptions over graphql-ws), websockets (socket.io, ws) and microservices (gRPC, NATS, Kafka, RabbitMQ, TCP...)
    - GraphQL: reads `context.req`, `context.request`, `context.reply.request`, and for subscriptions the upgrade request and the token in `connectionParams`
    - socket.io: the handshake headers, cookies, session, query and `auth.token`; ws: `WsAuthTransport.setRequest(client, request)`
    - microservices: the message metadata, or `data.headers`
    - your own transports with the `transports` option of the module or of a guard (`AuthTransport`, `AuthTransports`)
- Auth context: `@CurrentUser()`, `@CurrentUser('property')`, `@CurrentAuth()` (user, strategy, namespace, auth info, transport, scopes) on every transport, and `AuthContextService` / `getAuthContext()` in any service, with `AsyncLocalStorage` (global `AuthContextInterceptor`, disable with `context: false`). `runWithAuthContext()` for jobs and tests
- Errors: the `exceptionFactory` guard option, `unauthorized()` (401, optional `WWW-Authenticate` challenge), `forbidden()`, `toTransportException()` (`WsException` / `RpcException`)
- `AuthGuard.withDefaults()` returns a guard class with default options
- Sessions: `sessionLogIn()`, `sessionLogOut()`, `getSessionPayload()`, `removeSessionUser()`, `decorateRequest()`, and the `sessionKey` module option. They work with express-session, @fastify/session and @fastify/secure-session (callback, promise or synchronous session methods, cookie sessions)
- `JwtStrategy` options `namespace` (loads all the users of the tokens with the auth provider of a namespace: the tokens of an identity provider) and `name` (a second jwt strategy)
- Pluggable encryptor: the `encryptor` option (an `IEncryptor` instance, or a class instantiated with dependency injection) is provided with the `ENCRYPTOR` token and the `@InjectEncryptor()` decorator. The default `Encryptor` is still used when only `encrypt` is set
- `IEncryptor.compare()` (optional, may be async) to check a password against a salted hash (bcrypt, argon2...); `encrypt()` may be async; `canVerify()` and `needsRehash()`
- `ScryptEncryptor`: password hashing with scrypt (built in Node.js), salted, with the parameters stored in the hash
- `MigratingEncryptor`: hashes with a new encryptor, verifies the legacy values and re-hashes them on login, with `IUserProvider.updatePassword()`
- `Encryptor.compare()` and `Encryptor.canVerify()`; `AuthMemoryUserProvider` compares the passwords in constant time
- `AuthService.getAuthProviders()`, `MemoryUserProvider.removeUser()` and `updatePassword()`, the `DEFAULT_NAMESPACE` constant, the `AuthUserPayload`, `AuthModuleOptions` and `AuthModuleAsyncOptions` types
- `AuthProvider` and `IAuthProvider` have a second type parameter for the data given to `loadUser()`
- Tests of the code of the wiki tutorial and testing guide
- Documentation: TSDoc on the public API (kept in the published typings), a new README, guides in the [wiki](https://github.com/Pop-Code/nestjs-authentication/wiki)

### Changed

- Update dev dependencies (TypeScript 6, Jest 30, ESLint 10 with flat config, Prettier 3, typedoc 0.28, express 5 through @nestjs/platform-express 12) and switch to yarn v1
- Tests: unit tests of every component, and end-to-end tests with express, fastify, Apollo (queries and graphql-ws subscriptions), socket.io, a TCP microservice and passport strategies
- CI: tests on Node 24 and 26, a job with passport 0.6, and a smoke test on Node 22 (also without passport); bump all GitHub Actions; CodeQL and GitHub Pages (API reference) workflows
- Release workflow: create the GitHub release with the `gh` CLI and stage the npm release (trusted publishing with provenance), see `RELEASING.md`
- Dependabot: weekly, grouped updates for npm and GitHub Actions, keeping the supported ranges
- Define package contents with the `files` field in `package.json` (replaces `.npmignore`)
- The build removes `tsconfig.build.tsbuildinfo` (a stale file made `tsc -b` skip the build after `dist` was removed)
- Security reports go through GitHub private vulnerability reporting (`SECURITY.md`)
