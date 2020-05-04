import { ILoginRequest } from './interfaces/login.request';
export declare abstract class AuthController<LoginRequest extends ILoginRequest> {
    loginAction(req: any, namespace?: string, redirect?: string): any;
    loginCheckAction(data: LoginRequest, request: any): any;
    logoutAction(req: any): any;
}
//# sourceMappingURL=controller.d.ts.map