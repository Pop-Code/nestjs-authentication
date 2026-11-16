import { Injectable, NotFoundException } from '@nestjs/common';
import { PassportSerializer } from '@nestjs/passport';

import { AuthUserPayload, IAuthUser } from './interfaces/auth.user';
import { AuthService } from './service';

/**
 * Stores the users in the session with {@link IAuthUser.authSerialize} and loads them back with the {@link AuthService}.
 *
 * The constructor of PassportSerializer registers this instance in passport.
 */
@Injectable()
export class UserSerializer<User extends IAuthUser = any> extends PassportSerializer {
    constructor(protected readonly authService: AuthService) {
        super();
    }

    serializeUser(user: User, done: (err: any, payload?: AuthUserPayload) => void): void {
        if (user === undefined || user === null) {
            return done(null);
        }
        done(null, user.authSerialize());
    }

    /**
     * Loads the user of the session. If the user or its provider does not exist anymore, the user is removed
     * from the session (the request is not authenticated). Other errors (database down...) are passed to passport.
     */
    async deserializeUser(payload: AuthUserPayload, done: (err: any, user?: User | false) => void): Promise<void> {
        let user: User | undefined;
        try {
            user = await this.authService.loadUser<User>(payload);
        } catch (e) {
            if (e instanceof NotFoundException) {
                return done(null, false);
            }
            return done(e);
        }
        done(null, user ?? false);
    }
}
