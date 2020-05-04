import { AuthService } from '../service';
declare const LocalStrategy_base: new (...args: any[]) => any;
export declare class LocalStrategy extends LocalStrategy_base {
    private readonly authService;
    constructor(authService: AuthService);
    validate(req: any, email: string, password: string): Promise<any>;
}
export {};
//# sourceMappingURL=local.d.ts.map