export interface IUserProvider<U = any> {
    findOne(data: any): Promise<U>;
}
export interface IAuthProvider<U = any> {
    loadUser(data: any): U | Promise<U>;
    getName(): string;
}
//# sourceMappingURL=provider.d.ts.map