import { User } from './user';

export class MemoryUser extends User {
    _id: any;
    firstName: string;
    lastName: string;
    roles: string[];
}
