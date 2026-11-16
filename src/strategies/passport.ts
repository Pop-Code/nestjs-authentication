import { AuthStrategy, AuthStrategyContext, AuthStrategyResult } from './interfaces';

let passportModule: any;

/** Returns the passport instance, or `undefined` if passport is not installed. */
export function loadPassport(): any {
    if (passportModule === undefined) {
        try {
            // eslint-disable-next-line @typescript-eslint/no-require-imports
            const loaded = require('passport');
            passportModule = loaded?.default ?? loaded;
        } catch {
            passportModule = null;
        }
    }
    return passportModule ?? undefined;
}

/**
 * Uses a passport strategy (any of the passport ecosystem: OAuth providers, SAML, LDAP...) as an {@link AuthStrategy}.
 *
 * passport is an optional dependency: install it to use passport strategies. Register them in passport as usual
 * (`passport.use()`, or a `@nestjs/passport` `PassportStrategy` class), then name them in the guards:
 * a strategy name that is not registered in the {@link AuthStrategyRegistry} is looked up in passport.
 *
 * The user given by passport is logged in by the guard (no passport serializer needed for the sessions).
 * A strategy that sends the response (OAuth redirect) ends the request: the handler is not called.
 */
export class PassportAuthStrategy implements AuthStrategy {
    constructor(
        readonly name: string,
        protected readonly passport: any = loadPassport()
    ) {
        if (this.passport === undefined) {
            throw new Error(`The passport strategy "${name}" needs passport: npm install passport`);
        }
    }

    /** Returns the adapter of a passport strategy, or `undefined` if passport is missing or has no such strategy. */
    static find(name: string): PassportAuthStrategy | undefined {
        const passport = loadPassport();
        if (passport === undefined || typeof passport._strategy !== 'function' || !passport._strategy(name)) {
            return undefined;
        }
        return new PassportAuthStrategy(name, passport);
    }

    async authenticate({ request, response, options }: AuthStrategyContext): Promise<AuthStrategyResult | undefined> {
        // passport writes to a node response (redirects): fastify gives a reply, its node response is reply.raw
        const res = response?.raw ?? response;
        return await new Promise<AuthStrategyResult | undefined>((resolve, reject) => {
            let settled = false;
            const settle = (fn: () => void) => {
                if (!settled) {
                    settled = true;
                    fn();
                }
            };
            // a strategy that redirects ends the response without calling the callback
            res?.once?.('finish', () => settle(() => resolve({ user: undefined, handled: true })));
            const callback = (err: any, user: unknown, info: unknown) =>
                settle(() => {
                    if (err !== undefined && err !== null) {
                        return reject(err);
                    }
                    if (typeof user !== 'object' || user === null) {
                        return resolve(undefined);
                    }
                    const namespace = (info as { namespace?: unknown } | undefined)?.namespace;
                    resolve({ user, info, namespace: typeof namespace === 'string' ? namespace : undefined });
                });
            const next = (err?: any) => settle(() => (err ? reject(err) : resolve(undefined)));
            // the guard logs the user in: passport must not use its own session
            this.passport.authenticate(this.name, { ...options, session: false }, callback)(request, res, next);
        });
    }
}
