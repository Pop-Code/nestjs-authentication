import { Injectable, UnauthorizedException } from '@nestjs/common';

import { AuthContext, getAuthContext } from './auth.context';

/**
 * Reads the {@link AuthContext} of the current request in any service (no request scope needed).
 */
@Injectable()
export class AuthContextService<User = any> {
    /** Returns the auth context, or `undefined` if the request is not authenticated. */
    get(): AuthContext<User> | undefined {
        return getAuthContext<User>();
    }

    /** Returns the authenticated user, or `undefined`. */
    getUser(): User | undefined {
        return this.get()?.user;
    }

    /**
     * Returns the authenticated user.
     *
     * @throws UnauthorizedException if the request is not authenticated
     */
    getUserOrFail(): User {
        const auth = this.get();
        if (auth === undefined) {
            throw new UnauthorizedException();
        }
        return auth.user;
    }

    isAuthenticated(): boolean {
        return this.get() !== undefined;
    }
}
