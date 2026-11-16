import { Global, Inject, Injectable, Module } from '@nestjs/common';
import { Test } from '@nestjs/testing';

import {
    ExtractJwt,
    AuthMemoryUserProvider,
    AuthModule,
    AuthService,
    ENCRYPTOR,
    Encryptor,
    IAuthProvider,
    IEncryptor,
    InjectEncryptor,
    JwtStrategy,
    MemoryUserProvider,
    MODULE_OPTIONS_TOKEN
} from '../src';

const key = '77c0c891a5a062694a5ef1fdcf3719fe460d9c6e7ad5bda8715e44fdb2c8ae85';
const iv = 'f62456b5e1604435e3a548002d8b8944';

const CONFIG = 'CONFIG';
@Module({ providers: [{ provide: CONFIG, useValue: { secret: 'from-config', prefix: 'hash:' } }], exports: [CONFIG] })
class ConfigModule {}

@Global()
@Module({ providers: [{ provide: CONFIG, useValue: { prefix: 'global:' } }], exports: [CONFIG] })
class GlobalConfigModule {}

@Injectable()
class PrefixEncryptor implements IEncryptor {
    constructor(@Inject(CONFIG) private readonly config: { prefix: string }) {}
    encrypt(value: string) {
        return `${this.config.prefix}${value}`;
    }
}

@Injectable()
class ServiceWithEncryptor {
    constructor(@InjectEncryptor() readonly encryptor: IEncryptor) {}
}

const create = async (imports: any[], providers: any[] = []) => {
    const module = await Test.createTestingModule({ imports, providers }).compile();
    return await module.init();
};

describe('AuthModule options', () => {
    test('forRoot() without options: no encryptor and no jwt strategy', async () => {
        const app = await create([AuthModule.forRoot({})]);
        expect(app.get(Encryptor)).toBeUndefined();
        expect(app.get(ENCRYPTOR)).toBeUndefined();
        expect(app.get(JwtStrategy)).toBeUndefined();
        expect(app.get(AuthService)).toBeInstanceOf(AuthService);
        await app.close();
    });

    test('forRoot() with encrypt: the default Encryptor is the ENCRYPTOR', async () => {
        const app = await create([AuthModule.forRoot({ encrypt: { key, iv } })], [ServiceWithEncryptor]);
        expect(app.get(Encryptor)).toBeInstanceOf(Encryptor);
        expect(app.get(ENCRYPTOR)).toBe(app.get(Encryptor));
        expect(app.get(ServiceWithEncryptor).encryptor).toBe(app.get(Encryptor));
        await app.close();
    });

    test('forRoot() with an encryptor instance', async () => {
        const encryptor: IEncryptor = { encrypt: (v) => v };
        const app = await create([AuthModule.forRoot({ encrypt: { key, iv }, encryptor })], [ServiceWithEncryptor]);
        expect(app.get(ENCRYPTOR)).toBe(encryptor);
        expect(app.get(ServiceWithEncryptor).encryptor).toBe(encryptor);
        // the default implementation is still provided with its class
        expect(app.get(Encryptor)).toBeInstanceOf(Encryptor);
        await app.close();
    });

    test('forRoot() with an encryptor class: its (global) dependencies are injected', async () => {
        const app = await create([GlobalConfigModule, AuthModule.forRoot({ encryptor: PrefixEncryptor })]);
        const encryptor = app.get<IEncryptor>(ENCRYPTOR);
        expect(encryptor).toBeInstanceOf(PrefixEncryptor);
        expect(encryptor.encrypt('secret')).toBe('global:secret');
        await app.close();
    });

    test('forRootAsync() injects the providers of its imports', async () => {
        const app = await create([
            AuthModule.forRootAsync({
                imports: [ConfigModule],
                inject: [CONFIG],
                useFactory: (config: { secret: string }) => ({
                    encrypt: { key, iv },
                    jwt: { secretOrKey: config.secret, jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken() }
                })
            })
        ]);
        expect(app.get(MODULE_OPTIONS_TOKEN)).toHaveProperty('jwt.secretOrKey', 'from-config');
        expect(app.get(JwtStrategy)).toBeInstanceOf(JwtStrategy);
        expect(app.get(ENCRYPTOR)).toBeInstanceOf(Encryptor);
        await app.close();
    });

    test('forRootAsync() with an encryptor class: its dependencies are injected', async () => {
        const app = await create([
            AuthModule.forRootAsync({
                imports: [ConfigModule],
                useFactory: async () => ({ encryptor: PrefixEncryptor })
            })
        ]);
        const encryptor = app.get<IEncryptor>(ENCRYPTOR);
        expect(encryptor).toBeInstanceOf(PrefixEncryptor);
        expect(encryptor.encrypt('a')).toBe('hash:a');
        await app.close();
    });

    test('registerAuthProviders() with imports: the dependencies of the providers', async () => {
        @Injectable()
        class ConfiguredProvider implements IAuthProvider {
            constructor(@Inject(CONFIG) private readonly config: { prefix: string }) {}
            getName = () => 'configured';
            loadUser = async () => ({ prefix: this.config.prefix });
        }
        const app = await create([
            AuthModule.forRoot({}),
            AuthModule.registerAuthProviders([ConfiguredProvider], [ConfigModule])
        ]);
        await expect(app.get(AuthService).loadUser({ namespace: 'configured' })).resolves.toEqual({ prefix: 'hash:' });
        await app.close();
    });

    test('registerAuthProviders() registers class, value and factory providers', async () => {
        @Injectable()
        class AdminProvider implements IAuthProvider {
            getName = () => 'admin';
            loadUser = async () => ({ admin: true });
        }
        const value: IAuthProvider = { getName: () => 'value', loadUser: () => undefined };
        const app = await create([
            AuthModule.forRoot({ encrypt: { key, iv } }),
            AuthModule.registerAuthProviders([
                AdminProvider,
                { provide: 'VALUE', useValue: value },
                {
                    provide: 'FACTORY',
                    inject: [ENCRYPTOR],
                    useFactory: (encryptor: IEncryptor) =>
                        new AuthMemoryUserProvider('default', new MemoryUserProvider(), encryptor)
                }
            ])
        ]);
        const service = app.get(AuthService);
        expect(service.getAuthProvider('admin')).toBeInstanceOf(AdminProvider);
        expect(service.getAuthProvider('value')).toBe(value);
        expect(service.getAuthProvider('default')).toBeInstanceOf(AuthMemoryUserProvider);
        await expect(service.loadUser({ namespace: 'admin' })).resolves.toEqual({ admin: true });
        await app.close();
    });
});

describe('JwtStrategy', () => {
    const options = { secretOrKey: 'secret', jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken() };

    test('sign() uses the secretOrKey option by default', async () => {
        const strategy = new JwtStrategy(new AuthService(), options);
        const token = strategy.sign({ _id: '1' }, undefined, { expiresIn: 60 });
        const [, payload] = token.split('.');
        expect(JSON.parse(Buffer.from(payload, 'base64url').toString())).toMatchObject({ _id: '1' });
        expect(strategy.sign({ _id: '1' }, 'other')).not.toBe(strategy.sign({ _id: '1' }));
    });

    test('sign() throws without a key', () => {
        const strategy = new JwtStrategy(new AuthService(), {
            secretOrKeyProvider: (_req, _token, done) => done(null, 'secret'),
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken()
        });
        expect(() => strategy.sign({ _id: '1' })).toThrow('a secretOrPrivateKey is required');
    });
});
