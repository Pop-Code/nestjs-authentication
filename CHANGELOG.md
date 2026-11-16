# Changelog

All notable changes to this project will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - 2026-11-15

### BREAKING CHANGE

- Drop NestJS v8 and v9, support NestJS v10, v11 and v12 (peer dependencies `@nestjs/common`, `@nestjs/core` and `@nestjs/passport` `^10 || ^11 || ^12`)
- Require passport `^0.6.0 || ^0.7.0` (0.5 is affected by a session fixation vulnerability, CVE-2022-25896). Since passport 0.6, `req.logIn()` regenerates the session (pass `keepSessionInfo: true` in the strategy options to keep its data), and `req.logOut()` requires a callback
- Node engine is now `>= 22.12.0` (required to load the ESM-only NestJS v12 packages with `require(esm)`)
- jsonwebtoken v9 (used by `JwtStrategy.sign()`): see its [migration notes](https://github.com/auth0/node-jsonwebtoken/wiki/Migration-Notes:-v8-to-v9)
- `AuthGuard` with `fromSession: true` fails (500) when there is no session middleware, instead of silently ignoring the session
- `UserSerializer.deserializeUser()`: a session whose user or provider does not exist anymore is not authenticated (passport removes the user from the session), and the other errors are passed to passport. It no longer returns `'pass'`
- The `jwt` option is typed `JwtStrategyOptions`: `passReqToCallback` is not accepted (it broke `JwtStrategy.validate()`)
- `AuthService.loadUser()` is typed `Promise<U | undefined>`
- `Encryptor` throws if the key is not 32 bytes or the iv is not 16 bytes (it threw on the first `encrypt()`)
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
- `AuthGuard.getRequestResponse()` (`getRequestReponse()` is deprecated), `AuthService.getAuthProviders()`, `MemoryUserProvider.removeUser()`, the `DEFAULT_NAMESPACE` constant, the `AuthUserPayload`, `JwtStrategyOptions`, `MemoryUserCredentials`, `AuthModuleOptions` and `AuthModuleAsyncOptions` types
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
