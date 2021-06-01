export interface IUserProvider<U = any> {
    findOne: (data: any) => Promise<U | undefined>;
}

export interface IAuthProvider<U = any> {
    loadUser: (data: any) => (U | undefined) | Promise<U | undefined>;
    getName: () => string;
}
