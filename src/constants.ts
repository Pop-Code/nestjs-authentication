/** Injection token of the {@link AuthModuleOptions} given to `AuthModule.forRoot()` / `forRootAsync()`. */
export const MODULE_OPTIONS_TOKEN = 'nestjs-authentication:options';

/** Injection token of the internal provider that registers the auth providers given to `AuthModule.registerAuthProviders()`. */
export const MODULE_PROVIDER_REGISTER = 'nestjs-authentication:provider.register';

/** Name of the auth provider used when a request, a session or a token has no namespace. */
export const DEFAULT_NAMESPACE = 'default';

/**
 * Injection token of the {@link IEncryptor} of the module: the `encryptor` option,
 * or the default {@link Encryptor} when only the `encrypt` option is set. Inject it with {@link InjectEncryptor}.
 */
export const ENCRYPTOR = 'nestjs-authentication:encryptor';

/** Injection token of the internal provider that registers the `transports` option. */
export const MODULE_TRANSPORTS_REGISTER = 'nestjs-authentication:transports.register';
