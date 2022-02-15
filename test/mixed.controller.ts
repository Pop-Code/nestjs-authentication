import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { Request } from 'express';

import { AuthGuard } from '../src';

@Controller('mixed')
export class MixedController {
    /**
     * A method protected by emailpassword, jwt
     * - not required, AuthGuard will succeed if request is not authenticated
     * - get user from session
     */
    @Get('authenticated')
    @UseGuards(new AuthGuard({ strategies: { emailpassword: {}, jwt: {} }, fromSession: true }))
    async authenticated(@Req() req: Request) {
        return { user: req.user };
    }

    /**
     * A method protected by emailpassword, jwt
     * - required, AuthGuard will fail if request is not authenticated
     * - get user from session
     */
    @Get('protected')
    @UseGuards(new AuthGuard({ strategies: { emailpassword: {}, jwt: {} }, fromSession: true, required: true }))
    async protected(@Req() req: Request) {
        return { user: req.user };
    }

    /**
     * A method protected by emailpassword, jwt
     * - not required, AuthGuard will succeed if request is not authenticated
     * - do not get user from session
     * Warning: This method will always return an empty object for emailpassword. if no token provided for jwt
     */
    @Get('session')
    @UseGuards(new AuthGuard({ strategies: { emailpassword: {}, jwt: {} } }))
    async noSession(@Req() req: Request) {
        return { user: req.user };
    }
}
