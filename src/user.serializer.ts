import { Injectable } from '@nestjs/common';
import { PassportSerializer } from '@nestjs/passport';

import { IAuthUser } from './interfaces/auth.user';
import { AuthService } from './service';

/**
 * The constructor of PassportSerializer will register this instance against passport
 */
@Injectable()
export class UserSerializer<User extends IAuthUser = any> extends PassportSerializer {
    constructor(protected readonly authService: AuthService) {
        super();
    }

    serializeUser(user: User, done: (e?: Error, payload?: any) => void): void {
        if (user === undefined || user === null) {
            return done();
        }
        done(undefined, user.authSerialize());
    }

    async deserializeUser(
        payload: Record<string, unknown>,
        done: (e?: Error | 'pass', user?: any) => void
    ): Promise<void> {
        try {
            const user = await this.authService.loadUser(payload);
            done(undefined, user);
        } catch (e) {
            // pass is a special use case of passport to allow multiple Serializers to work
            done('pass');
        }
    }
}
