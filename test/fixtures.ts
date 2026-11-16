import { ExtractJwt } from 'passport-jwt';

import {
    AuthMemoryUserProvider,
    AuthModule,
    ENCRYPTOR,
    Encryptor,
    IEncryptor,
    MemoryUser,
    MemoryUserProvider
} from '../src';

export class User implements MemoryUser {
    constructor(
        public _id: string,
        public email: string,
        public passwordEncrypted: string,
        public namespace = 'default'
    ) {}

    authSerialize() {
        return { _id: this._id, namespace: this.namespace };
    }
}

export const key = '77c0c891a5a062694a5ef1fdcf3719fe460d9c6e7ad5bda8715e44fdb2c8ae85';
export const iv = 'f62456b5e1604435e3a548002d8b8944';
export const jwtSecret = 'nestjs-authentication-transports';
export const password = 'password';

const encryptor = new Encryptor({ key, iv });
export const john = new User('1', 'john@example.com', encryptor.encrypt(password));
export const admin = new User('2', 'admin@example.com', encryptor.encrypt(password), 'admin');

/** The AuthModule with a jwt strategy and two namespaces: default (john) and admin. */
export const authImports = () => [
    AuthModule.forRoot({
        encrypt: { key, iv },
        jwt: { secretOrKey: jwtSecret, jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken() }
    }),
    AuthModule.registerAuthProviders([
        {
            provide: 'DEFAULT_PROVIDER',
            inject: [ENCRYPTOR],
            useFactory: (e: IEncryptor) =>
                new AuthMemoryUserProvider('default', new MemoryUserProvider<User>().registerUser(john), e)
        },
        {
            provide: 'ADMIN_PROVIDER',
            inject: [ENCRYPTOR],
            useFactory: (e: IEncryptor) =>
                new AuthMemoryUserProvider('admin', new MemoryUserProvider<User>().registerUser(admin), e)
        }
    ])
];
