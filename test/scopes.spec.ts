import { hasScopes, normalizeScopes, scopeMatches } from '../src';

describe('scopes', () => {
    test('scopeMatches()', () => {
        expect(scopeMatches('orders:read', 'orders:read')).toBe(true);
        expect(scopeMatches('orders:*', 'orders:read')).toBe(true);
        expect(scopeMatches('*', 'anything')).toBe(true);
        expect(scopeMatches('orders:read', 'orders:write')).toBe(false);
        expect(scopeMatches('orders:*', 'users:read')).toBe(false);
    });

    test('hasScopes()', () => {
        expect(hasScopes(['a', 'b'], { scopes: ['a', 'b'], mode: 'all' })).toBe(true);
        expect(hasScopes(['a'], { scopes: ['a', 'b'], mode: 'all' })).toBe(false);
        expect(hasScopes(['a'], { scopes: ['a', 'b'], mode: 'any' })).toBe(true);
        expect(hasScopes([], { scopes: ['a'], mode: 'any' })).toBe(false);
        expect(hasScopes([], { scopes: [], mode: 'all' })).toBe(true);
    });

    test('normalizeScopes()', () => {
        expect(normalizeScopes('a  b a')).toEqual(['a', 'b']);
        expect(normalizeScopes(['a', '', 'a', 'c'])).toEqual(['a', 'c']);
        expect(normalizeScopes(undefined)).toEqual([]);
        expect(normalizeScopes(null)).toEqual([]);
    });
});
