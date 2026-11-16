/**
 * The code of the wiki "Passport strategies" page, tested as is (HTTP Basic auth with passport-http).
 * Keep it in sync with https://github.com/Pop-Code/nestjs-authentication/wiki/Passport-Strategies
 */
import { Controller, Get, INestApplication, Injectable, Module } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Test } from '@nestjs/testing';
import { BasicStrategy } from 'passport-http';
import request from 'supertest';

import { Auth, CurrentUser, IEncryptor, InjectEncryptor } from '../../src';
import { appAuthImports } from './app/auth';
import { User } from './app/user';
import { UsersModule } from './app/users.module';
import { UsersService } from './app/users.service';

// basic.strategy.ts: a passport strategy, registered in passport by @nestjs/passport
@Injectable()
export class HttpBasicStrategy extends PassportStrategy(BasicStrategy, 'basic') {
    constructor(
        private readonly users: UsersService,
        @InjectEncryptor() private readonly encryptor: IEncryptor
    ) {
        super();
    }

    // passport calls it with the credentials of the Authorization: Basic header
    async validate(email: string, password: string): Promise<User | false> {
        const user = await this.users.findByEmail(email);
        if (user === undefined || !(await this.encryptor.compare?.(password, user.passwordHash))) {
            return false;
        }
        return user;
    }
}

// status.controller.ts
@Controller('status')
export class StatusController {
    @Get()
    @Auth({ strategies: { basic: {} } }) // the name given to PassportStrategy()
    status(@CurrentUser() user: User) {
        return { email: user.email };
    }
}

describe('Passport strategies page', () => {
    let app: INestApplication;

    beforeAll(async () => {
        @Module({
            imports: [...appAuthImports(), UsersModule],
            controllers: [StatusController],
            providers: [HttpBasicStrategy]
        })
        class AppModule {}
        const module = await Test.createTestingModule({ imports: [AppModule] }).compile();
        app = await module.createNestApplication().init();
        await app.get(UsersService).register('john@example.com', 'secret');
    });
    afterAll(async () => await app.close());

    test('HTTP Basic auth with passport-http', async () => {
        await request(app.getHttpServer())
            .get('/status')
            .auth('john@example.com', 'secret')
            .expect(200)
            .expect({ email: 'john@example.com' });
        await request(app.getHttpServer()).get('/status').auth('john@example.com', 'wrong').expect(401);
        await request(app.getHttpServer()).get('/status').expect(401);
    });
});
