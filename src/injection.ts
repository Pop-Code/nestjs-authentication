import { Inject } from '@nestjs/common';

import { ENCRYPTOR } from './constants';

/** Injects the {@link IEncryptor} of the module (the {@link ENCRYPTOR} token). */
export const InjectEncryptor = (): PropertyDecorator & ParameterDecorator => Inject(ENCRYPTOR);
