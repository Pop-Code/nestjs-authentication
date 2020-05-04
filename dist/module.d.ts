import { NestModule, MiddlewareConsumer, DynamicModule } from '@nestjs/common';
import { AuthService } from './service';
import { IAuthModuleOptions, IAuthModuleAsyncOptions } from './interfaces/options';
export declare class AuthModule implements NestModule {
    configure(consumer: MiddlewareConsumer): void;
    protected static createAuthService(opts: IAuthModuleOptions): AuthService;
    static register(options: IAuthModuleOptions): DynamicModule;
    static registerAsync(options: IAuthModuleAsyncOptions): DynamicModule;
}
//# sourceMappingURL=module.d.ts.map