import { Inject, Injectable, OnModuleInit, Optional } from '@nestjs/common';

import { MODULE_OPTIONS_TOKEN } from '../constants';
import type { IAuthModuleOptions } from '../interfaces/options';
import { AuthService } from '../service';

import { AuthStrategy } from './interfaces';
import { PassportAuthStrategy } from './passport';

/**
 * The strategies of the application, by name. Provided by the {@link AuthModule}.
 *
 * A name that is not registered is looked up in passport (if it is installed): any passport strategy works with
 * the guard through {@link PassportAuthStrategy}.
 */
@Injectable()
export class AuthStrategyRegistry implements OnModuleInit {
    /**
     * The registry of the last initialized application, used by the guards created with `new AuthGuard()`
     * (they are not created by the dependency injection).
     */
    static current: AuthStrategyRegistry | undefined;

    protected readonly strategies = new Map<string, AuthStrategy>();

    constructor(
        @Optional() @Inject(MODULE_OPTIONS_TOKEN) readonly moduleOptions?: IAuthModuleOptions,
        @Optional() readonly authService?: AuthService
    ) {}

    onModuleInit(): void {
        AuthStrategyRegistry.current = this;
    }

    /** Registers a strategy under its name. A strategy with the same name is replaced. */
    register(strategy: AuthStrategy): this {
        this.strategies.set(strategy.name, strategy);
        return this;
    }

    /** Returns the registered strategies by name. */
    getStrategies(): ReadonlyMap<string, AuthStrategy> {
        return this.strategies;
    }

    /**
     * Returns the strategy of a name: a registered one, else the passport strategy of this name.
     *
     * @throws Error if there is none
     */
    get(name: string): AuthStrategy {
        const strategy = this.strategies.get(name) ?? PassportAuthStrategy.find(name);
        if (strategy === undefined) {
            throw new Error(
                `Unknown authentication strategy "${name}": register it with AuthModule.registerStrategies() (or in passport)`
            );
        }
        return strategy;
    }
}
