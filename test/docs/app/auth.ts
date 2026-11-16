// The AuthModule configuration of the Getting started app, shared by the examples of the other pages.
import {
    AuthModule,
    AuthModuleOptions,
    EmailPasswordAuthProvider,
    ENCRYPTOR,
    IEncryptor,
    ScryptEncryptor,
    unauthorized
} from '../../../src';
import { User } from './user';
import { UsersModule } from './users.module';
import { UsersService } from './users.service';

export const JWT_SECRET = 'a-test-secret-of-at-least-32-characters';

/** A fast scrypt for the tests (the default cost is 2 ** 16). */
export const testEncryptor = new ScryptEncryptor({ cost: 2 ** 10 });

export const usersAuthProvider = {
    provide: 'USERS_AUTH_PROVIDER',
    inject: [ENCRYPTOR, UsersService],
    useFactory: (encryptor: IEncryptor, users: UsersService) =>
        new EmailPasswordAuthProvider<User>({
            encryptor,
            findById: (id) => users.findById(id),
            findByEmail: (email) => users.findByEmail(email),
            getId: (user) => user.id,
            getPasswordHash: (user) => user.passwordHash,
            updatePasswordHash: (user, hash) => users.updatePasswordHash(user, hash)
        })
};

/** The imports of the app: AuthModule (with options) + the users. */
export const appAuthImports = (options: Partial<AuthModuleOptions> = {}) => [
    AuthModule.forRoot({
        encryptor: testEncryptor,
        jwt: { secretOrKey: JWT_SECRET, algorithms: ['HS256'] },
        defaults: { strategies: { jwt: {} }, required: true, exceptionFactory: unauthorized({ challenge: 'Bearer' }) },
        ...options
    }),
    AuthModule.registerAuthProviders([usersAuthProvider], [UsersModule]),
    UsersModule
];
