import { CanActivate, ExecutionContext } from '@nestjs/common';
import { AuthenticateOptions } from 'passport';
export declare const scopes: Map<any, any>;
export interface IAuthGuardOptions extends AuthenticateOptions {
    isAuth?: boolean;
    strategy: string | string[];
}
export declare class AuthGuard implements CanActivate {
    protected readonly options: IAuthGuardOptions;
    constructor(options: any);
    canActivate(context: ExecutionContext): Promise<boolean>;
    login<User>(user: any, request: any): Promise<User>;
}
//# sourceMappingURL=guard.d.ts.map