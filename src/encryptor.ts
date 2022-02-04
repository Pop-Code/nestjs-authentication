import { Injectable } from '@nestjs/common';
import { createCipheriv } from 'crypto';

import { IEncryptor, IEncryptorOptions } from './interfaces/encrypt';

@Injectable()
export class Encryptor implements IEncryptor {
    constructor(protected options: IEncryptorOptions) {}

    encrypt(value: string): string {
        const cipher = createCipheriv(
            'aes-256-ctr',
            Buffer.from(this.options.key, 'hex'),
            Buffer.from(this.options.iv, 'hex')
        );
        let crypted = cipher.update(value, 'utf8', 'hex');
        crypted += cipher.final('hex');
        return crypted;
    }
}
