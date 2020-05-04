"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var AuthModule_1;
Object.defineProperty(exports, "__esModule", { value: true });
const common_1 = require("@nestjs/common");
const nestjs_console_1 = require("nestjs-console");
const service_1 = require("./service");
const local_1 = require("./strategies/local");
const user_serializer_1 = require("./user.serializer");
const passport_1 = require("passport");
let AuthModule = AuthModule_1 = class AuthModule {
    configure(consumer) {
        consumer.apply(passport_1.default.initialize()).forRoutes('*');
        consumer.apply(passport_1.default.session()).forRoutes('*');
    }
    static createAuthService(opts) {
        return new service_1.AuthService(opts.encrypt);
    }
    static register(options) {
        const optionsToken = 'AuthModuleOptions';
        const optionsProvider = {
            provide: optionsToken,
            useValue: options
        };
        const authServiceProvider = {
            provide: service_1.AuthService,
            useValue: this.createAuthService(options)
        };
        return {
            module: AuthModule_1,
            imports: [nestjs_console_1.ConsoleModule],
            providers: [optionsProvider, authServiceProvider, user_serializer_1.UserSerializer, local_1.LocalStrategy],
            exports: [authServiceProvider, user_serializer_1.UserSerializer, local_1.LocalStrategy]
        };
    }
    static registerAsync(options) {
        const optionsToken = 'AuthModuleOptions';
        const optionsProvider = Object.assign({ provide: optionsToken }, options);
        const authServiceProvider = {
            provide: service_1.AuthService,
            useFactory: this.createAuthService,
            inject: [optionsToken]
        };
        return {
            module: AuthModule_1,
            imports: [nestjs_console_1.ConsoleModule],
            providers: [optionsProvider, authServiceProvider, user_serializer_1.UserSerializer, local_1.LocalStrategy],
            exports: [authServiceProvider, user_serializer_1.UserSerializer, local_1.LocalStrategy]
        };
    }
};
AuthModule = AuthModule_1 = __decorate([
    common_1.Global(),
    common_1.Module({})
], AuthModule);
exports.AuthModule = AuthModule;
//# sourceMappingURL=module.js.map