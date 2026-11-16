import { SetMetadata } from '@nestjs/common';

import type { AuthGuardOptions } from '../guard';

/** Metadata of {@link Auth}. */
export const AUTH_OPTIONS_METADATA = 'nestjs-authentication:auth';
/** Metadata of {@link Public}. */
export const AUTH_PUBLIC_METADATA = 'nestjs-authentication:public';
/** Metadata of {@link RequireScopes} and {@link RequireAnyScope}. */
export const AUTH_SCOPES_METADATA = 'nestjs-authentication:scopes';

/** The scopes required by a route: all of them, or any of them. */
export interface ScopesRequirement {
    scopes: string[];
    mode: 'all' | 'any';
}

/**
 * Authenticates a controller, a resolver, a gateway or a route with the global {@link AuthGuard}
 * (registered by the {@link AuthModule}, no `@UseGuards()` needed). The options of a method override the ones of
 * its class, which override the `defaults` of the module.
 *
 * ```ts
 * @Auth({ strategies: { jwt: {} }, required: true })
 * @Controller('orders')
 * export class OrderController {}
 * ```
 */
export const Auth = (options: Partial<AuthGuardOptions> = {}) => SetMetadata(AUTH_OPTIONS_METADATA, options);

/**
 * Makes a route public: the global guard still authenticates the request when it has credentials
 * (so {@link CurrentUser} works), but never rejects it.
 */
export const Public = () => SetMetadata(AUTH_PUBLIC_METADATA, true);

const scopesMetadata = (mode: 'all' | 'any', scopes: string[]) =>
    SetMetadata(AUTH_SCOPES_METADATA, { scopes, mode } satisfies ScopesRequirement);

/**
 * Requires all the scopes (and an authenticated request). On a class and a method, both are required.
 * A granted scope `orders:*` matches `orders:read`, `*` matches all.
 *
 * ```ts
 * @RequireScopes('orders:write')
 * ```
 */
export const RequireScopes = (...scopes: string[]) => scopesMetadata('all', scopes);

/** Requires at least one of the scopes (and an authenticated request). */
export const RequireAnyScope = (...scopes: string[]) => scopesMetadata('any', scopes);
