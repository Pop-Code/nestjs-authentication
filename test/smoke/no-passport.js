/* eslint-disable @typescript-eslint/no-require-imports */
/* global require, process, console */
// Smoke test of the built package without passport: node test/smoke/no-passport.js ./dist
const Module = require('module');
const original = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
    if (/^(passport|@nestjs\/passport|passport-.*)$/.test(request)) {
        const err = new Error(`Cannot find module '${request}'`);
        err.code = 'MODULE_NOT_FOUND';
        throw err;
    }
    return original.call(this, request, ...rest);
};
require('reflect-metadata');
const m = require(require('path').resolve(process.argv[2]));
(async () => {
    const auth = new m.AuthService().registerAuthProvider({
        getName: () => 'default',
        loadUser: async (d) => (d._id === '1' ? { id: 1 } : undefined)
    });
    const jwt = new m.JwtStrategy(auth, { secretOrKey: 's' });
    const token = jwt.sign({ _id: '1' });
    const registry = new m.AuthStrategyRegistry().register(jwt);
    const guard = new m.AuthGuard({ strategies: { jwt: {} }, required: true }, registry);
    const req = { headers: { authorization: `Bearer ${token}` } };
    const ctx = {
        getType: () => 'http',
        switchToHttp: () => ({ getRequest: () => req, getResponse: () => ({}), getNext: () => undefined })
    };
    const ok = await guard.canActivate(ctx);
    let unknown;
    try {
        registry.get('google');
    } catch (e) {
        unknown = e.message;
    }
    if (ok !== true || req.user?.id !== 1 || !unknown.includes('Unknown authentication strategy')) {
        throw new Error(JSON.stringify({ ok, user: req.user, unknown }));
    }
    console.log('smoke without passport: ok');
})().catch((e) => {
    console.error('FAILED', e);
    process.exit(1);
});
