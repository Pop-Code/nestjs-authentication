import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-local';

import { AuthService } from '../service';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy, 'local') {
    constructor(private readonly authService: AuthService) {
        super({
            usernameField: 'email',
            passwordField: 'password',
            session: true,
            passReqToCallback: true
        });
    }

    async validate(req: any, email: string, password: string): Promise<any> {
        const namespace = req.body.namespace || req.query.namespace;
        const user = await this.authService.loadUser({ email, password, namespace });
        return user;
    }
}
