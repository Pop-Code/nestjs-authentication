import { ScopesRequirement } from './decorators';

/** Returns `true` if a granted scope covers a scope: equal, `*`, or a prefix wildcard (`orders:*`). */
export function scopeMatches(granted: string, scope: string): boolean {
    if (granted === scope || granted === '*') {
        return true;
    }
    if (granted.endsWith('*')) {
        return scope.startsWith(granted.slice(0, -1));
    }
    return false;
}

/** Returns `true` if the granted scopes satisfy the requirement. */
export function hasScopes(granted: string[], requirement: ScopesRequirement): boolean {
    if (requirement.scopes.length === 0) {
        return true;
    }
    const covered = (scope: string) => granted.some((g) => scopeMatches(g, scope));
    return requirement.mode === 'any' ? requirement.scopes.some(covered) : requirement.scopes.every(covered);
}

/** Returns the scopes as an array: splits a space separated string, removes the empty and duplicate ones. */
export function normalizeScopes(scopes: string | string[] | undefined | null): string[] {
    const list = Array.isArray(scopes) ? scopes : typeof scopes === 'string' ? scopes.split(' ') : [];
    return [...new Set(list.filter((s) => typeof s === 'string' && s !== ''))];
}
