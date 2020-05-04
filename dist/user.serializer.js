"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
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
const passport_1 = require("@nestjs/passport");
const common_1 = require("@nestjs/common");
const service_1 = require("./service");
let UserSerializer = class UserSerializer extends passport_1.PassportSerializer {
    constructor(authService) {
        super();
        this.authService = authService;
    }
    serializeUser(user, done) {
        if (!user) {
            return done();
        }
        done(null, {
            _id: user._id.toString(),
            namespace: user.namespace
        });
    }
    deserializeUser(payload, done) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!payload._id || !payload.namespace) {
                done();
            }
            try {
                const user = yield this.authService.loadUser({
                    _id: payload._id,
                    namespace: payload.namespace
                });
                done(null, user);
            }
            catch (e) {
                done(e);
            }
        });
    }
};
UserSerializer = __decorate([
    common_1.Injectable(),
    __metadata("design:paramtypes", [service_1.AuthService])
], UserSerializer);
exports.UserSerializer = UserSerializer;
//# sourceMappingURL=user.serializer.js.map