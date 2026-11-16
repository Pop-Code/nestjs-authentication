import { Injectable, OnApplicationBootstrap } from '@nestjs/common';
import { DiscoveryService, MetadataScanner, Reflector } from '@nestjs/core';

import { AUTH_OPTIONS_METADATA, AUTH_SCOPES_METADATA, ScopesRequirement } from './decorators';
import { normalizeScopes } from './utils';

/** A scope declared in the application, and where. */
export interface DeclaredScope {
    scope: string;
    /** `required`: by {@link RequireScopes} / {@link RequireAnyScope}; `requested`: in a strategy `scope` option. */
    kind: 'required' | 'requested';
    /** `ClassName` or `ClassName.method`. */
    source: string;
}

/**
 * Lists the scopes declared in the application: required by {@link RequireScopes} / {@link RequireAnyScope}, and
 * requested in the `scope` option of the strategies in {@link Auth} (e.g. OAuth scopes), on the controllers,
 * resolvers and gateways. Filled when the application starts.
 */
@Injectable()
export class AuthScopes implements OnApplicationBootstrap {
    protected declared: DeclaredScope[] = [];

    constructor(
        protected readonly discovery: DiscoveryService,
        protected readonly scanner: MetadataScanner,
        protected readonly reflector: Reflector
    ) {}

    onApplicationBootstrap(): void {
        this.declared = this.explore();
    }

    /** Adds a scope (e.g. from a guard created with `new AuthGuard()`). */
    add(scope: DeclaredScope): void {
        if (!this.declared.some((d) => d.scope === scope.scope && d.kind === scope.kind && d.source === scope.source)) {
            this.declared.push(scope);
        }
    }

    /** Returns the declared scopes, sorted and without duplicates. */
    all(kind?: DeclaredScope['kind']): string[] {
        const scopes = this.declared.filter((d) => kind === undefined || d.kind === kind).map((d) => d.scope);
        return [...new Set(scopes)].sort();
    }

    /** Returns where each scope is declared. */
    getDeclarations(): readonly DeclaredScope[] {
        return this.declared;
    }

    protected explore(): DeclaredScope[] {
        const result: DeclaredScope[] = [];
        const wrappers = [...this.discovery.getControllers(), ...this.discovery.getProviders()];
        const seen = new Set<unknown>();
        for (const wrapper of wrappers) {
            const instance = wrapper.instance;
            if (instance === undefined || instance === null || typeof instance !== 'object' || seen.has(instance)) {
                continue;
            }
            seen.add(instance);
            const type = instance.constructor;
            this.collect(type, type.name, result);
            const prototype = Object.getPrototypeOf(instance);
            for (const method of this.scanner.getAllMethodNames(prototype)) {
                this.collect(prototype[method], `${type.name}.${method}`, result);
            }
        }
        return result;
    }

    protected collect(target: any, source: string, result: DeclaredScope[]): void {
        if (typeof target !== 'function') {
            return;
        }
        const required = this.reflector.get<ScopesRequirement | undefined>(AUTH_SCOPES_METADATA, target);
        for (const scope of required?.scopes ?? []) {
            result.push({ scope, kind: 'required', source });
        }
        const auth = this.reflector.get<{ strategies?: Record<string, { scope?: string | string[] }> } | undefined>(
            AUTH_OPTIONS_METADATA,
            target
        );
        for (const options of Object.values(auth?.strategies ?? {})) {
            for (const scope of normalizeScopes(options?.scope)) {
                result.push({ scope, kind: 'requested', source });
            }
        }
    }
}
