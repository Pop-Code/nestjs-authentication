# Changelog

All notable changes to this project will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### BREAKING CHANGE

Since 0.5.0:

- passport is optional: the strategies are native ([`AuthStrategy`](https://github.com/Pop-Code/nestjs-authentication/wiki/Strategies)), and the passport strategies work through an adapter when passport is installed
    - `@nestjs/passport` is no longer a peer dependency, `passport` is an optional one, and `passport-jwt`, `passport-local` and the `@types/passport*` packages are no longer dependencies
    - `JwtStrategy` (built on jsonwebtoken) and `EmailPasswordStrategy` are native strategies: they no longer extend `PassportStrategy` and are not registered in passport. Their constructors, `validate()`, `getNamespace()` and `JwtStrategy.sign()` are unchanged
    - `JwtStrategyOptions` has the option names of passport-jwt (`secretOrKey`, `secretOrKeyProvider`, `jwtFromRequest`, `algorithms`, `issuer`, `audience`, `ignoreExpiration`, `jsonWebTokenOptions`); `jwtFromRequest` defaults to the bearer token. Import `ExtractJwt` from `nestjs-authentication` (the passport-jwt extractors still work)
    - `UserSerializer` is removed: the native `session` strategy stores the user in the same place (`session.passport.user`), so the existing sessions keep working
    - `passport.initialize()` is no longer applied to the routes; the guard adds `req.logIn()`, `req.logOut()` and `req.isAuthenticated()` (compatible with passport)
    - passport strategies are called with `session: false`: the guard logs the user in (`session: true` in the guard options works as before)
- `AuthModule` registers `AuthGuard` as a global guard. It only acts on the routes with `@Auth()`, `@Public()` or `@RequireScopes()` (or all of them with `globalGuard: true`), so the routes protected with `@UseGuards(new AuthGuard(...))` are not affected
- `AuthGuard.scopes` and `AuthGuard.registerScopes()` are deprecated: use the `AuthScopes` service

### Added

- Strategies: the `AuthStrategy` interface, `AuthModule.registerStrategies(providers, imports?)`, the `AuthStrategyRegistry`, the native `session` strategy (`SessionStrategy`), and `PassportAuthStrategy` (any passport strategy by name, OAuth redirects end the request)
- `JwtStrategy`: `secretOrKeyProvider` returns a promise or uses the passport-jwt callback (so `passportJwtSecret()` of jwks-rsa works for JWKS), `verify()`, the `scope` / `scp` / `scopes` claims are the scopes of the request
- `ExtractJwt` (passport-jwt API, plus `fromCookie()`)
- Global guard and decorators: `@Auth(options)` on a class or a method, `@Public()`, and the `defaults` and `globalGuard` module options
- Scopes: `@RequireScopes(...)` and `@RequireAnyScope(...)` (wildcards: `orders:*`, `*`), `AuthContext.scopes`, the `scopes` module option (e.g. roles as scopes), the `scopeExceptionFactory` guard option (default: 403 `Insufficient scope`), and the `AuthScopes` service that lists the scopes required and requested in the application
- Sessions: `sessionLogIn()`, `sessionLogOut()`, `getSessionPayload()`, `decorateRequest()`, and the `sessionKey` module option
- `registerAuthProviders(providers, imports)` and `registerStrategies(providers, imports)`: the modules that provide the dependencies of the providers

- Transports: the `AuthGuard` and the decorators work on http (express **and fastify**), GraphQL (queries, mutations and **subscriptions** over graphql-ws), **websockets** (socket.io, ws) and **microservices** (gRPC, NATS, Kafka, RabbitMQ, TCP...). Before, websockets and microservices threw a `NotImplementedException` and GraphQL subscriptions failed on the missing `context.req`
    - GraphQL: reads `context.req`, `context.request`, `context.reply.request`, and for subscriptions the upgrade request and the token in `connectionParams`
    - socket.io: the handshake headers, cookies, session, query and `auth.token`; ws: `WsAuthTransport.setRequest(client, request)`
    - microservices: the message metadata, or `data.headers`
    - your own transports with the `transports` option of the module or of a guard (`AuthTransport`, `AuthTransports`)
- Auth context: `@CurrentUser()`, `@CurrentUser('property')`, `@CurrentAuth()` (user, strategy, namespace, auth info, transport) on every transport, and `AuthContextService` / `getAuthContext()` in any service, with `AsyncLocalStorage` (global `AuthContextInterceptor`, disable with `context: false`). `runWithAuthContext()` for jobs and tests
- Errors: the `exceptionFactory` guard option, `unauthorized()` (401, optional `WWW-Authenticate` challenge), `forbidden()`, `toTransportException()` (`WsException` / `RpcException`)
- `AuthGuard.withDefaults()` returns a guard class with default options
- `ScryptEncryptor`: password hashing with scrypt (built in Node.js), salted, with the parameters stored in the hash
- `MigratingEncryptor`: hashes with a new encryptor, verifies the legacy values and re-hashes them on login. `IEncryptor.canVerify()` / `needsRehash()`, `IUserProvider.updatePassword()`, `MemoryUserProvider.updatePassword()`
- `Encryptor.canVerify()`

### Changed

- The `Encryptor` (aes-256-ctr) is documented as legacy: prefer `ScryptEncryptor`
- `AuthGuard.getRequestResponse()` uses the transports
- CI: a job tests passport 0.6
- The smoke test checks the built package works without passport
- The build removes `tsconfig.build.tsbuildinfo` (a stale file made `tsc -b` skip the build after `dist` was removed)
- Tests: unit tests of the transports, the encryptors, the auth context and the errors; end-to-end tests with express, fastify, Apollo (queries and graphql-ws subscriptions), socket.io and a TCP microservice

## [0.5.0] - 2026-11-15

### BREAKING CHANGE

- Support NestJS v12 only (peer dependencies `@nestjs/common` and `@nestjs/core` `^12.0.0`), drop NestJS v8
- Require passport `^0.6.0 || ^0.7.0` (0.5 is affected by a session fixation vulnerability, CVE-2022-25896). Since passport 0.6, `req.logIn()` regenerates the session (pass `keepSessionInfo: true` in the strategy options to keep its data), and `req.logOut()` requires a callback
- Node engine is now `>= 22.12.0` (required to load the ESM-only NestJS v12 packages with `require(esm)`)
- jsonwebtoken v9 (used by `JwtStrategy.sign()`): see its [migration notes](https://github.com/auth0/node-jsonwebtoken/wiki/Migration-Notes:-v8-to-v9)
- `AuthGuard` with `fromSession: true` fails (500) when there is no session middleware, instead of silently ignoring the session
- `UserSerializer.deserializeUser()`: a session whose user or provider does not exist anymore is not authenticated (passport removes the user from the session), and the other errors are passed to passport. It no longer returns `'pass'`
- The `jwt` option is typed `JwtStrategyOptions`: `passReqToCallback` is not accepted (it broke `JwtStrategy.validate()`)
- `AuthService.loadUser()` is typed `Promise<U | undefined>`
- `Encryptor` throws if the key is not 32 bytes or the iv is not 16 bytes (it threw on the first `encrypt()`)
- `AuthGuard.getRequestReponse()` (typo) is renamed `getRequestResponse()`
- Remove the unused `debug` dependency

### Fixed

- `forRootAsync()`: the `imports` are imported by the module, so `inject` can use their providers (they were ignored)
- `AuthGuard`: `null` users are not logged in (a `typeof user !== null` check was always true), and `request.authInfo` is an object keyed by strategy (it was an array)
- `EmailPasswordStrategy` no longer throws when the request has no body (express 5), and ignores a non string namespace
- `registerAuthProviders()` accepts class providers
- The module exports the `EmailPasswordStrategy`

### Added

- Pluggable encryptor: the `encryptor` option (an `IEncryptor` instance, or a class instantiated with dependency injection) is provided with the `ENCRYPTOR` token and the `@InjectEncryptor()` decorator. The default `Encryptor` (aes-256-ctr) is still used when only `encrypt` is set
- `IEncryptor.compare()` (optional, may be async) to check a password against a salted hash (bcrypt, argon2...). `encrypt()` may be async
- `Encryptor.compare()`; `AuthMemoryUserProvider` compares the passwords in constant time
- `JwtStrategy.sign()` uses the `secretOrKey` option when no key is given
- `AuthService.getAuthProviders()`, `MemoryUserProvider.removeUser()`, the `DEFAULT_NAMESPACE` constant, the `AuthUserPayload`, `JwtStrategyOptions`, `MemoryUserCredentials`, `AuthModuleOptions` and `AuthModuleAsyncOptions` types
- `AuthProvider` and `IAuthProvider` have a second type parameter for the data given to `loadUser()`
- `UserSerializer` is exported
- Documentation: TSDoc on the public API (kept in the published typings), a new README, guides in the [wiki](https://github.com/Pop-Code/nestjs-authentication/wiki)
- Tests for the service, the serializer, the providers, the guard, the module options and the failure cases

### Changed

- Update dev dependencies (TypeScript 6, Jest 30, ESLint 10 with flat config, Prettier 3, typedoc 0.28, express 5 through @nestjs/platform-express 12) and switch to yarn v1
- CI: tests on Node 24 and 26, and a smoke test on Node 22; bump all GitHub Actions; CodeQL and GitHub Pages (API reference) workflows
- Release workflow: create the GitHub release with the `gh` CLI and stage the npm release (trusted publishing with provenance), see `RELEASING.md`
- Dependabot: weekly, grouped updates for npm and GitHub Actions, keeping the supported ranges
- Define package contents with the `files` field in `package.json` (replaces `.npmignore`)
- Security reports go through GitHub private vulnerability reporting (`SECURITY.md`)
