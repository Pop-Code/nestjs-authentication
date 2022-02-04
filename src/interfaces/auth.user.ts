export interface IAuthUser {
    authSerialize(): Record<string, unknown> & { namespace?: string };
}
