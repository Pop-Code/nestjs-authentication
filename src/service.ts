import { Injectable, NotFoundException } from '@nestjs/common';

import { DEFAULT_NAMESPACE } from './constants';
import { AuthUserPayload } from './interfaces/auth.user';
import { IAuthProvider } from './interfaces/provider';

/**
 * Holds the auth providers (one per namespace) and loads the users with them.
 */
@Injectable()
export class AuthService {
    protected readonly authProviders = new Map<string, IAuthProvider<any, any>>();

    /** Registers a provider under its name. A provider with the same name is replaced. */
    registerAuthProvider<U = any>(provider: IAuthProvider<U, any>): this {
        this.authProviders.set(provider.getName(), provider);
        return this;
    }

    /** Returns the provider of a namespace. */
    getAuthProvider<U = any>(namespace: string): IAuthProvider<U, any> | undefined {
        return this.authProviders.get(namespace);
    }

    /** Returns the registered providers by namespace. */
    getAuthProviders(): ReadonlyMap<string, IAuthProvider<any, any>> {
        return this.authProviders;
    }

    /**
     * Loads a user with the provider of `data.namespace` (`default` if not set).
     *
     * @returns the user, or `undefined` if the provider does not find it
     * @throws NotFoundException if there is no provider for the namespace
     */
    async loadUser<U = any>(data: AuthUserPayload): Promise<U | undefined> {
        const namespace = typeof data.namespace === 'string' ? data.namespace : DEFAULT_NAMESPACE;
        const provider = this.getAuthProvider<U>(namespace);
        if (provider === undefined) {
            throw new NotFoundException(`Invalid namespace: Provider ${namespace} not found`);
        }
        return await provider.loadUser(data);
    }
}
