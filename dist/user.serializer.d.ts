import { PassportSerializer } from '@nestjs/passport';
import { AuthService } from './service';
export declare class UserSerializer extends PassportSerializer {
    protected readonly authService: AuthService;
    constructor(authService: AuthService);
    serializeUser(user: any, done: (e?: Error, payload?: any) => void): void;
    deserializeUser(payload: {
        _id: string;
        namespace: string;
    }, done: (e?: Error, user?: any) => void): Promise<void>;
}
//# sourceMappingURL=user.serializer.d.ts.map