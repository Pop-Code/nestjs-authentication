import { IEmailPassword } from '../interfaces/emailpassword';

export class User implements IEmailPassword {
    _id: any;
    email: string;
    namespace?: string;
    passwordEncrypted: string;
}
