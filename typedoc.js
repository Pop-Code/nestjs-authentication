module.exports = {
    out: 'docs',
    entryPoints: './src/index.ts',
    exclude: ['**/test/**', '**/apollo-server-*/**'],
    theme: 'default',
    name: 'Nestjs-authentication Documentation',
    excludeExternals: true,
    excludePrivate: false,
    hideGenerator: true
};
