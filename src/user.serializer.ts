import { PassportSerializer } from '@nestjs/passport';
import { Injectable, Inject } from '@nestjs/common';
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
        if (!user) {
            return done();
        }
        done(null, {
            _id: user._id.toString(),
            namespace: user.namespace
        });
    }
    async deserializeUser(payload: { _id: string; namespace: string }, done: (e?: Error, user?: any) => void) {
        if (!payload._id || !payload.namespace) {
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
