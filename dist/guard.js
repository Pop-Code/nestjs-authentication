"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const common_1 = require("@nestjs/common");
const passport_1 = require("passport");
exports.scopes = new Map();
class AuthGuard {
    constructor(options) {
        this.options = Object.assign(Object.assign({}, options), { authInfo: true });
        if (typeof this.options.scope === 'string') {
            this.options.scope = [this.options.scope];
        }
        if (this.options.scope) {
            for (const scope of this.options.scope) {
                exports.scopes.set(scope, scope);
            }
        }
        if (typeof this.options.strategy === 'string') {
            this.options.strategy = [this.options.strategy];
        }
    }
    canActivate(context) {
        return __awaiter(this, void 0, void 0, function* () {
            const httpCtx = context.switchToHttp();
            let [request, response, next] = [httpCtx.getRequest(), httpCtx.getResponse(), httpCtx.getNext()];
            if (!request) {
                request = context.getArgByIndex(2).request;
                response = request.res;
                next = (err) => {
                    throw err;
                };
            }
            for (const strategy of this.options.strategy) {
                if (strategy === 'local' && request.isAuthenticated()) {
                    return true;
                }
                else {
                    yield new Promise((ok, fail) => passport_1.default.authenticate(strategy, this.options, (err, user, info) => __awaiter(this, void 0, void 0, function* () {
                        request.authInfo = info;
                        try {
                            if (!user && this.options.isAuth) {
                                throw new Error('User not found');
                            }
                            if (err) {
                                throw err;
                            }
                            if (user) {
                                yield this.login(user, request);
                            }
                            ok();
                        }
                        catch (e) {
                            fail(new common_1.UnauthorizedException(e.message.message || e.message || 'Uncaught error'));
                        }
                    }))(request, response, next));
                }
            }
            return true;
        });
    }
    login(user, request) {
        return __awaiter(this, void 0, void 0, function* () {
            request.oauth2Scope = this.options.scope;
            yield new Promise((ok, fail) => {
                request.logIn(user, (loginErr) => {
                    if (loginErr) {
                        return fail(loginErr);
                    }
                    ok();
                });
            });
            return user;
        });
    }
}
exports.AuthGuard = AuthGuard;
//# sourceMappingURL=guard.js.map