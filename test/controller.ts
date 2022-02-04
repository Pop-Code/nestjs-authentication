import { Controller, Get, HttpCode, Post, Req, UseGuards } from '@nestjs/common';
import { Request } from 'express';

import { AuthGuard } from '../src';

@Controller('/test')
export class TestAuthController {
    protected authUrl = '/test/login';

    @Post('login_check')
    @UseGuards(new AuthGuard({ local: { session: true } }, true))
    async loginCheckAction(@Req() req: Request) {
        return { success: req.user !== undefined };
    }

    @Post('logout')
    @UseGuards(new AuthGuard({ local: { session: true } }))
    async logoutAction(@Req() req: Request) {
        if (req.isAuthenticated()) {
            req.logOut();
        }
        return { success: true };
    }

    @Get('authenticated')
    @UseGuards(new AuthGuard({ local: { session: true }, jwt: { session: false } }))
    async authenticated(@Req() req: Request) {
        return { user: req.user };
    }

    @Get('protected')
    @UseGuards(new AuthGuard({ local: { session: true }, jwt: { session: false } }, true))
    async protected(@Req() req: Request) {
        return { user: req.user };
    }

    @Get('jwt-session')
    @HttpCode(200)
    @UseGuards(new AuthGuard({ jwt: { session: true } }))
    jwtSession(@Req() req: Request) {
        return { user: req.user };
    }
}
