export interface IEncryptor {
    encrypt: (value: string) => string;
}
export interface IEncryptorOptions {
    iv: string;
    key: string;
}
