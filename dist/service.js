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
const common_1 = require("@nestjs/common");
const crypto_1 = require("crypto");
const nestjs_console_1 = require("nestjs-console");
let AuthService = class AuthService {
    constructor(options) {
        this.options = options;
        this.authProviders = new Map();
    }
    encryptCli(value) {
        const encrypted = this.encrypt(value);
        console.log(encrypted);
        return encrypted;
    }
    encrypt(value) {
        const cipher = crypto_1.createCipheriv('aes-256-ctr', Buffer.from(this.options.key, 'hex'), Buffer.from(this.options.iv, 'hex'));
        let crypted = cipher.update(value, 'utf8', 'hex');
        crypted += cipher.final('hex');
        return crypted;
    }
    registerAuthProvider(provider) {
        this.authProviders.set(provider.getName(), provider);
        return this;
    }
    getAuthProvider(namespace) {
        return this.authProviders.get(namespace);
    }
    loadUser(data) {
        return __awaiter(this, void 0, void 0, function* () {
            const provider = this.getAuthProvider(data.namespace);
            if (!provider) {
                throw new common_1.NotFoundException(`Invalid namespace: Provider "${data.namespace}" not found`);
            }
            const user = yield provider.loadUser(data);
            return user;
        });
    }
    validateUser(payload) {
        return this.loadUser({ _id: payload._id, namespace: payload.namespace });
    }
};
__decorate([
    nestjs_console_1.Command({
        command: 'password <password>',
        description: 'Encrypt a password'
    }),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String]),
    __metadata("design:returntype", String)
], AuthService.prototype, "encryptCli", null);
AuthService = __decorate([
    common_1.Injectable(),
    nestjs_console_1.Console(),
    __metadata("design:paramtypes", [Object])
], AuthService);
exports.AuthService = AuthService;
//# sourceMappingURL=service.js.map