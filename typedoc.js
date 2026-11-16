module.exports = {
    out: 'docs',
    exclude: ['**/test/**/*'],
    theme: 'default',
    name: 'NestJS Authentication',
    readme: 'README.md',
    excludePrivate: true,
    hideGenerator: true,
    entryPoints: ['src/index.ts'],
    navigationLinks: {
        Wiki: 'https://github.com/Pop-Code/nestjs-authentication/wiki',
        GitHub: 'https://github.com/Pop-Code/nestjs-authentication',
        npm: 'https://www.npmjs.com/package/nestjs-authentication'
    },
    includeVersion: true
};
