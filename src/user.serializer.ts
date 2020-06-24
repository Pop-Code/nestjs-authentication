import { Injectable } from '@nestjs/common';
import { PassportSerializer } from '@nestjs/passport';

import { AuthService } from './service';

/**
 * The constructor of PassportSerializer will register this instance against passport
 */
@Injectable()
export class UserSerializer extends PassportSerializer {
    constructor(protected readonly authService: AuthService) {
        super();
    }

    serializeUser(user: any, done: (e?: Error, payload?: any) => void) {
        if (user === undefined || user === null) {
            return done();
        }
        done(null, {
            // TODO let the user provide a id/user serializer ?
            _id: user._id.toString(),
            namespace: user.namespace
        });
    }

    async deserializeUser(payload: { _id: string; namespace: string }, done: (e?: Error, user?: any) => void) {
        if (payload._id === undefined || payload.namespace === undefined) {
            done();
        }
        try {
            const user = await this.authService.loadUser({
                _id: payload._id,
                namespace: payload.namespace
            });
            done(null, user);
        } catch (e) {
            done(e);
        }
    }
}
