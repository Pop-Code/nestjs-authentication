/**
 * The code of the wiki "Passwords" page, tested as is.
 * Keep it in sync with https://github.com/Pop-Code/nestjs-authentication/wiki/Encryptor
 */
import { Controller, Module, Post } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';

import { Auth, Encryptor, IEncryptor, MigratingEncryptor, ScryptEncryptor } from '../../src';
import { appAuthImports } from './app/auth';
import { UsersService } from './app/users.service';

// a custom encryptor: here a fake one, to show the interface (use bcrypt, argon2...)
export class ReversedEncryptor implements IEncryptor {
    encrypt(password: string) {
        return `rev:${[...password].reverse().join('')}`;
    }

    compare(password: string, hash: string) {
        return hash === this.encrypt(password);
    }
}

@Controller('auth')
class AuthController {
    @Post('login')
    @Auth({ strategies: { emailpassword: {} } })
    login() {
        return { ok: true };
    }
}

const key = '77c0c891a5a062694a5ef1fdcf3719fe460d9c6e7ad5bda8715e44fdb2c8ae85';
const iv = 'f62456b5e1604435e3a548002d8b8944';

describe('Passwords page', () => {
    const create = async (encryptor: IEncryptor) => {
        @Module({ imports: appAuthImports({ encryptor }), controllers: [AuthController] })
        class AppModule {}
        const module = await Test.createTestingModule({ imports: [AppModule] }).compile();
        return await module.createNestApplication().init();
    };

    test('ScryptEncryptor: the hash stores its parameters', async () => {
        const app = await create(new ScryptEncryptor({ cost: 2 ** 10 }));
        const user = await app.get(UsersService).register('john@example.com', 'secret');
        expect(user.passwordHash).toMatch(/^\$scrypt\$ln=10,r=8,p=1\$/);
        await request(app.getHttpServer())
            .post('/auth/login')
            .send({ email: user.email, password: 'secret' })
            .expect(201);
        await app.close();
    });

    test('a custom encryptor', async () => {
        const app = await create(new ReversedEncryptor());
        const user = await app.get(UsersService).register('john@example.com', 'secret');
        expect(user.passwordHash).toBe('rev:terces');
        await request(app.getHttpServer())
            .post('/auth/login')
            .send({ email: user.email, password: 'secret' })
            .expect(201);
        await request(app.getHttpServer())
            .post('/auth/login')
            .send({ email: user.email, password: 'nope' })
            .expect(401);
        await app.close();
    });

    test('MigratingEncryptor: an old hash is replaced on login', async () => {
        const legacy = new Encryptor({ key, iv });
        const app = await create(new MigratingEncryptor(new ScryptEncryptor({ cost: 2 ** 10 }), [legacy]));
        const user = await app.get(UsersService).register('john@example.com', 'secret');
        user.passwordHash = legacy.encrypt('secret'); // a hash of the old encryptor
        await request(app.getHttpServer())
            .post('/auth/login')
            .send({ email: user.email, password: 'secret' })
            .expect(201);
        expect(user.passwordHash).toMatch(/^\$scrypt\$/);
        await app.close();
    });
});
