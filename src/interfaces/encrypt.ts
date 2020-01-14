export interface IEncrypt {
    encrypt(value: string): string;
}
export interface IEncryptOptions {
    iv: string;
    key: string;
}
