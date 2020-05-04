import { ModuleMetadata } from '@nestjs/common/interfaces';
import { IEncryptOptions } from './encrypt';
export interface IAuthModuleOptions {
    encrypt: IEncryptOptions;
}
export interface IAuthModuleAsyncOptions extends Pick<ModuleMetadata, 'imports'> {
    useFactory: (...args: any[]) => Promise<IAuthModuleOptions> | IAuthModuleOptions;
    inject?: any[];
}
//# sourceMappingURL=options.d.ts.map