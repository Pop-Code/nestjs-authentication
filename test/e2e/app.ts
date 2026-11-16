import { Controller, Get, Injectable, Module, Post, UseGuards } from '@nestjs/common';

import { AuthContext, AuthContextService, AuthGuard, CurrentAuth, CurrentUser, unauthorized } from '../../src';
import { authImports, User } from '../fixtures';

/** A service that reads the user without a request: the AuthContextInterceptor makes it available. */
@Injectable()
export class ProfileService {
    constructor(private readonly auth: AuthContextService<User>) {}

    async describe() {
        await new Promise((r) => setTimeout(r, 1)); // still available after an await
        const auth = this.auth.get();
        return auth ? { email: auth.user.email, strategy: auth.strategy, namespace: auth.namespace } : null;
    }
}

const ApiGuard = AuthGuard.withDefaults({ required: true, exceptionFactory: unauthorized({ challenge: 'Bearer' }) });

@Controller('http')
export class HttpController {
    constructor(private readonly profile: ProfileService) {}

    @Get('me')
    @UseGuards(new AuthGuard({ strategies: { jwt: {} }, required: true }))
    me(@CurrentUser() user: User, @CurrentUser('email') email: string, @CurrentAuth() auth: AuthContext<User>) {
        return { id: user._id, email, strategy: auth.strategy, namespace: auth.namespace, transport: auth.transport };
    }

    @Get('optional')
    @UseGuards(new AuthGuard({ strategies: { jwt: {} } }))
    optional(@CurrentUser() user?: User) {
        return { authenticated: user !== undefined };
    }

    @Get('api')
    @UseGuards(new ApiGuard({ strategies: { jwt: {} } }))
    api(@CurrentUser('email') email: string) {
        return { email };
    }

    @Post('login')
    @UseGuards(new AuthGuard({ strategies: { emailpassword: {} }, required: true }))
    login(@CurrentAuth() auth: AuthContext<User>) {
        return { email: auth.user.email, strategy: auth.strategy, namespace: auth.namespace };
    }

    @Get('profile')
    @UseGuards(new AuthGuard({ strategies: { jwt: {} } }))
    async profileAction() {
        return { profile: await this.profile.describe() };
    }
}

@Module({ imports: authImports(), controllers: [HttpController], providers: [ProfileService] })
export class HttpAppModule {}
