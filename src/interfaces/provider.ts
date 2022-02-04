export interface IUserProvider<User = any> {
    findOne: (data: Record<string, unknown>) => Promise<User | undefined>;
}

export interface IAuthProvider<User = any> {
    loadUser: (data: Record<string, unknown>) => (User | undefined) | Promise<User | undefined>;
    getName: () => string;
}
