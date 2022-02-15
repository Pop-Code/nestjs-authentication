import { Controller, Get, HttpCode, Post, Req, UseGuards } from '@nestjs/common';
import { Request } from 'express';

import { AuthGuard } from '../src';

@Controller('emailpassword')
export class EmailPaswordController {
    /**
     * A method protected by emailpassword
     * - required, AuthGuard will fail if request is not authenticated
     * - do not get user from session
     * - save the user in the session
     */
    @Post('login_check')
    @UseGuards(new AuthGuard({ strategies: { emailpassword: { session: true } }, required: true }))
    async loginCheckAction(@Req() req: Request) {
        return { success: req.user !== undefined };
    }

    /**
     * A method protected by emailpassword
     * - required, AuthGuard will fail if request is not authenticated
     * - get user from session
     * - logout the user
     */
    @Post('logout')
    @HttpCode(200)
    @UseGuards(new AuthGuard({ strategies: { emailpassword: {} }, fromSession: true, required: true }))
    async logoutAction(@Req() req: Request) {
        if (req.isAuthenticated()) {
            req.logOut();
        }
        return { success: true };
    }

    /**
     * A method protected by emailpassword
     * - not required, AuthGuard will succeed if request is not authenticated
     * - get user from session
     */
    @Get('authenticated')
    @UseGuards(new AuthGuard({ strategies: { emailpassword: {} }, fromSession: true }))
    async authenticated(@Req() req: Request) {
        return { user: req.user };
    }

    /**
     * A method protected by emailpassword
     * - required, AuthGuard will fail if request is not authenticated
     * - get user from session
     */
    @Get('protected')
    @UseGuards(new AuthGuard({ strategies: { emailpassword: {} }, fromSession: true, required: true }))
    async protected(@Req() req: Request) {
        return { user: req.user };
    }

    /**
     * A method protected by emailpassword
     * - not required, AuthGuard will succeed if request is not authenticated
     * - do not get user from session
     * Warning: This method will always return an empty object ! because user is not loaded from session
     */
    @Get('session')
    @UseGuards(new AuthGuard({ strategies: { emailpassword: {} } }))
    async noSession(@Req() req: Request) {
        return { user: req.user };
    }
}
