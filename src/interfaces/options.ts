import { IEncryptOptions } from './encrypt';
import { ModuleMetadata } from '@nestjs/common/interfaces';
import { IAuthProvider } from './provider';

export interface IAuthModuleOptions {
    encrypt: IEncryptOptions;
}

export interface IAuthModuleAsyncOptions extends Pick<ModuleMetadata, 'imports'> {
    useFactory: (...args: any[]) => Promise<IAuthModuleOptions> | IAuthModuleOptions;
    inject?: any[];
}
