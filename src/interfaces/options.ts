import { ModuleMetadata } from '@nestjs/common/interfaces';
import { StrategyOptions as JWTOptions } from 'passport-jwt';

import { IEncryptorOptions } from './encrypt';

export interface IAuthModuleOptions {
    encrypt?: IEncryptorOptions;
    jwt?: JWTOptions;
}

export interface IAuthModuleAsyncOptions extends Pick<ModuleMetadata, 'imports'> {
    useFactory: (...args: any[]) => Promise<IAuthModuleOptions> | IAuthModuleOptions;
    inject?: any[];
}
