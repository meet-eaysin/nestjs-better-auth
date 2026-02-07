import { Inject, Logger, Module } from "@nestjs/common";
import type {
  DynamicModule,
  MiddlewareConsumer,
  NestModule,
  OnModuleInit,
} from "@nestjs/common";
import {
  DiscoveryModule,
  DiscoveryService,
  HttpAdapterHost,
  MetadataScanner,
} from "@nestjs/core";
import { toNodeHandler } from "better-auth/node";
import { createAuthMiddleware } from "better-auth/plugins";
import type { Request, Response } from "express";
import {
  type ASYNC_OPTIONS_TYPE,
  type AuthModuleOptions,
  ConfigurableModuleClass,
  MODULE_OPTIONS_TOKEN,
  type OPTIONS_TYPE,
} from "./auth-module-definition.js";
import { AuthService } from "./auth-service.js";
import { SkipBodyParsingMiddleware } from "./middlewares.js";
import { AFTER_HOOK_KEY, BEFORE_HOOK_KEY, HOOK_KEY } from "./symbols.js";
import { AuthGuard } from "./auth-guard.js";
import { APP_GUARD } from "@nestjs/core";

const HOOKS = [
  { metadataKey: BEFORE_HOOK_KEY, hookType: "before" as const },
  { metadataKey: AFTER_HOOK_KEY, hookType: "after" as const },
];

import type { Auth } from "better-auth";

/**
 * NestJS module that integrates the Auth library with NestJS applications.
 * Provides authentication middleware, hooks, and exception handling.
 */
@Module({
  imports: [DiscoveryModule],
  providers: [AuthService],
  exports: [AuthService],
})
export class AuthModule
  extends ConfigurableModuleClass
  implements NestModule, OnModuleInit
{
  private readonly logger = new Logger(AuthModule.name);
  constructor(
    @Inject(DiscoveryService)
    private readonly discoveryService: DiscoveryService,
    @Inject(MetadataScanner)
    private readonly metadataScanner: MetadataScanner,
    @Inject(HttpAdapterHost)
    private readonly adapter: HttpAdapterHost,
    @Inject(MODULE_OPTIONS_TOKEN)
    private readonly options: AuthModuleOptions,
  ) {
    super();
  }

  async onModuleInit() {
    await this.syncDatabase();
    await this.initializeHooks();
  }

  private async syncDatabase() {
    const auth = this.options.auth as Auth & {
      db?: { sync?: () => Promise<void> };
    };
    try {
      if (auth.db?.sync && typeof auth.db.sync === "function") {
        await auth.db.sync();
      }
    } catch (dbError) {
      this.logger.error("Failed to sync database schema:", dbError);
    }
  }

  private async initializeHooks() {
    const { discoveryService, metadataScanner } = this;
    const providers = discoveryService
      .getProviders()
      .filter(
        ({ metatype }) => metatype && Reflect.getMetadata(HOOK_KEY, metatype),
      );

    if (
      providers.length > 0 &&
      typeof this.options.auth?.options?.hooks !== "object"
    ) {
      throw new Error(
        "Detected @Hook providers but Better Auth 'hooks' are not configured. Add 'hooks: {}' to your betterAuth(...) options.",
      );
    }

    if (typeof this.options.auth?.options?.hooks !== "object") return;

    for (const provider of providers) {
      const providerPrototype = Object.getPrototypeOf(provider.instance);
      const methods = metadataScanner.getAllMethodNames(providerPrototype);

      for (const method of methods) {
        const providerMethod = providerPrototype[method];
        this.setupHooks(providerMethod, provider.instance);
      }
    }
  }

  configure(consumer: MiddlewareConsumer): void {
    this.setupCors();

    const basePath = this.normalizeBasePath(
      this.options.auth.options.basePath ?? "/api/auth",
    );

    if (!this.options.disableBodyParser) {
      consumer.apply(SkipBodyParsingMiddleware(basePath)).forRoutes("*");
    }

    this.setupAuthMiddleware(basePath);
  }

  private setupCors() {
    const trustedOrigins = this.options.auth.options.trustedOrigins;
    const isArrayBased = Array.isArray(trustedOrigins);

    if (!this.options.disableTrustedOriginsCors && isArrayBased) {
      this.adapter.httpAdapter.enableCors({
        origin: trustedOrigins as string[],
        methods: ["GET", "POST", "PUT", "DELETE"],
        credentials: true,
      });
    } else if (
      trustedOrigins &&
      !this.options.disableTrustedOriginsCors &&
      !isArrayBased
    ) {
      throw new Error(
        "Function-based trustedOrigins not supported in NestJS. Use string array or disable CORS with disableTrustedOriginsCors: true.",
      );
    }
  }

  private normalizeBasePath(path: string): string {
    let normalized = path.startsWith("/") ? path : `/${path}`;
    if (normalized.endsWith("/") && normalized.length > 1) {
      normalized = normalized.slice(0, -1);
    }
    return normalized;
  }

  private setupAuthMiddleware(basePath: string) {
    const handler = toNodeHandler(this.options.auth);
    this.adapter.httpAdapter
      .getInstance()
      .use(
        async (req: Request, res: Response, next: (err?: unknown) => void) => {
          const isAuthPath =
            req.url.startsWith(basePath) ||
            req.originalUrl.startsWith(basePath);

          if (!isAuthPath) {
            return next();
          }

          try {
            if (this.options.middleware) {
              await this.options.middleware(req, res, () => handler(req, res));
            } else {
              await handler(req, res);
            }
          } catch (error) {
            this.logger.error("Better Auth Handler Exception:", error);
            next(error);
          }
        },
      );

    this.logger.log(`AuthModule initialized BetterAuth on '${basePath}'`);
  }

  private setupHooks(
    providerMethod: (...args: unknown[]) => unknown,
    providerClass: { new (...args: unknown[]): unknown },
  ) {
    if (!this.options.auth.options.hooks) return;

    for (const { metadataKey, hookType } of HOOKS) {
      const hasHook = Reflect.hasMetadata(metadataKey, providerMethod);
      if (!hasHook) continue;

      const hookPath = Reflect.getMetadata(metadataKey, providerMethod);

      const originalHook = this.options.auth.options.hooks[hookType];
      this.options.auth.options.hooks[hookType] = createAuthMiddleware(
        async (ctx) => {
          if (originalHook) {
            await originalHook(ctx);
          }

          if (hookPath && hookPath !== ctx.path) return;

          await providerMethod.apply(providerClass, [ctx]);
        },
      );
    }
  }

  static forRootAsync(options: typeof ASYNC_OPTIONS_TYPE): DynamicModule {
    const forRootAsyncResult = super.forRootAsync(options);
    const { module } = forRootAsyncResult;

    return {
      ...forRootAsyncResult,
      module: options.disableControllers
        ? AuthModuleWithoutControllers
        : module,
      controllers: options.disableControllers
        ? []
        : forRootAsyncResult.controllers,
      providers: [
        ...(forRootAsyncResult.providers ?? []),
        ...(!options.disableGlobalAuthGuard
          ? [
              {
                provide: APP_GUARD,
                useClass: AuthGuard,
              },
            ]
          : []),
      ],
    };
  }

  static forRoot(options: typeof OPTIONS_TYPE): DynamicModule;
  /**
   * @deprecated Use the object-based signature: AuthModule.forRoot({ auth, ...options })
   */
  static forRoot(
    auth: Auth,
    options?: Omit<typeof OPTIONS_TYPE, "auth">,
  ): DynamicModule;
  static forRoot(
    arg1: Auth | typeof OPTIONS_TYPE,
    arg2?: Omit<typeof OPTIONS_TYPE, "auth">,
  ): DynamicModule {
    const normalizedOptions: typeof OPTIONS_TYPE =
      typeof arg1 === "object" && arg1 !== null && "auth" in (arg1 as object)
        ? (arg1 as typeof OPTIONS_TYPE)
        : ({ ...(arg2 ?? {}), auth: arg1 as Auth } as typeof OPTIONS_TYPE);

    const forRootResult = super.forRoot(normalizedOptions);
    const { module } = forRootResult;

    return {
      ...forRootResult,
      module: normalizedOptions.disableControllers
        ? AuthModuleWithoutControllers
        : module,
      controllers: normalizedOptions.disableControllers
        ? []
        : forRootResult.controllers,
      providers: [
        ...(forRootResult.providers ?? []),
        ...(!normalizedOptions.disableGlobalAuthGuard
          ? [
              {
                provide: APP_GUARD,
                useClass: AuthGuard,
              },
            ]
          : []),
      ],
    };
  }
}

class AuthModuleWithoutControllers extends AuthModule {
  configure(): void {
    return;
  }
}
