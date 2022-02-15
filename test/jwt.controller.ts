import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { Request } from 'express';

import { AuthGuard } from '../src';

@Controller('jwt')
export class JwtController {
    /**
     * A method protected by jwt
     * - not required, AuthGuard will succeed if request is not authenticated
     */
    @Get('authenticated')
    @UseGuards(new AuthGuard({ strategies: { jwt: {} } }))
    async authenticated(@Req() req: Request) {
        return { user: req.user };
    }

    /**
     * A method protected by jwt
     * - required, AuthGuard will fail if request is not authenticated
     */
    @Get('protected')
    @UseGuards(new AuthGuard({ strategies: { jwt: {} }, required: true }))
    async protected(@Req() req: Request) {
        return { user: req.user };
    }

    /**
     * A method protected by jwt
     * - required, AuthGuard will fail if request is not authenticated
     * - will persist the user in session
     */
    @Get('session')
    @UseGuards(new AuthGuard({ strategies: { jwt: { session: true } }, required: true }))
    async session(@Req() req: Request) {
        return { user: req.user };
    }

    /**
     * A method protected by jwt
     * - required, AuthGuard will fail if request is not authenticated
     * - get the user from session
     */
    @Get('from-session')
    @UseGuards(new AuthGuard({ strategies: { jwt: {} }, fromSession: true, required: true }))
    async fromSession(@Req() req: Request) {
        return { user: req.user };
    }
}
