import { Injectable, NotFoundException } from '@nestjs/common';

import { IAuthProvider } from './interfaces/provider';

@Injectable()
export class AuthService {
    protected readonly authProviders = new Map<string, IAuthProvider<any>>();

    registerAuthProvider<U = any>(provider: IAuthProvider<U>): this {
        this.authProviders.set(provider.getName(), provider);
        return this;
    }

    getAuthProvider<U = any>(namespace: string): IAuthProvider<U> | undefined {
        return this.authProviders.get(namespace);
    }

    async loadUser<U = any>(data: Record<string, unknown> & { namespace?: string }): Promise<U> {
        const namespace: string = typeof data.namespace === 'string' ? data.namespace : 'default';
        const provider = this.getAuthProvider(namespace);
        if (provider === undefined) {
            throw new NotFoundException(`Invalid namespace: Provider ${namespace} not found`);
        }
        const user = await provider.loadUser(data);
        return user;
    }
}
