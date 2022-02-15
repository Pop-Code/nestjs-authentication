export interface IAuthUser {
    authSerialize(): { [key: string]: any } & { namespace?: string };
}
