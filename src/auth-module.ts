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

// biome-ignore lint/suspicious/noExplicitAny: i don't want to cause issues/breaking changes between different ways of setting up better-auth and even versions
export type Auth = any;

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
		this.logger.log(`[DEBUG] Initializing AuthModule. basePath: ${this.options.auth.options.basePath || '/api/auth'}, baseURL: ${this.options.auth.options.baseURL}`);
		
		try {
			// Log configuration to verify it's what we expect in production
			this.logger.log(`[DEBUG] Auth Config - baseURL: ${this.options.auth.options.baseURL}, basePath: ${this.options.auth.options.basePath}`);
			this.logger.log(`[DEBUG] Auth Config - trustHost: ${this.options.auth.options.advanced?.trustHost}, secret: ${!!this.options.auth.options.secret}`);
			
			// Inspect internal API structure - Log ALL routes to be absolutely sure
			const apiKeys = Object.keys(this.options.auth.api || {});
			this.logger.log(`[DEBUG] Registered Internal API Routes (${apiKeys.length}): ${apiKeys.join(', ')}`);
			
			if (this.options.auth.db && typeof this.options.auth.db.sync === 'function') {
				this.logger.log('[DEBUG] Syncing database schema...');
				await this.options.auth.db.sync();
				this.logger.log('[DEBUG] Database schema synced successfully.');
			}
		} catch (dbError) {
			this.logger.error('[ERROR] Failed to sync database schema:', dbError);
		}

		const { discoveryService, metadataScanner } = this;
		const providers = this.discoveryService
			.getProviders()
			.filter(
				({ metatype }) => metatype && Reflect.getMetadata(HOOK_KEY, metatype),
			);

		const hasHookProviders = providers.length > 0;
		const hooksConfigured =
			typeof this.options.auth?.options?.hooks === "object";

		if (hasHookProviders && !hooksConfigured)
			throw new Error(
				"Detected @Hook providers but Better Auth 'hooks' are not configured. Add 'hooks: {}' to your betterAuth(...) options.",
			);

		if (!hooksConfigured) return;

		for (const provider of providers) {
			const providerPrototype = Object.getPrototypeOf(provider.instance);
			const methods = this.metadataScanner.getAllMethodNames(providerPrototype);

			for (const method of methods) {
				const providerMethod = providerPrototype[method];
				this.setupHooks(providerMethod, provider.instance);
			}
		}
	}

	configure(consumer: MiddlewareConsumer): void {
		const trustedOrigins = this.options.auth.options.trustedOrigins;
		// function-based trustedOrigins requires a Request (from web-apis) object to evaluate, which is not available in NestJS (we only have a express Request object)
		// if we ever need this, take a look at better-call which show an implementation for this
		const isNotFunctionBased = trustedOrigins && Array.isArray(trustedOrigins);

		if (!this.options.disableTrustedOriginsCors && isNotFunctionBased) {
			this.adapter.httpAdapter.enableCors({
				origin: trustedOrigins,
				methods: ["GET", "POST", "PUT", "DELETE"],
				credentials: true,
			});
		} else if (
			trustedOrigins &&
			!this.options.disableTrustedOriginsCors &&
			!isNotFunctionBased
		)
			throw new Error(
				"Function-based trustedOrigins not supported in NestJS. Use string array or disable CORS with disableTrustedOriginsCors: true.",
			);

		// Get basePath from options or use default
		let basePath = this.options.auth.options.basePath ?? "/api/auth";

		// Ensure basePath starts with /
		if (!basePath.startsWith("/")) {
			basePath = `/${basePath}`;
		}

		// Ensure basePath doesn't end with /
		if (basePath.endsWith("/")) {
			basePath = basePath.slice(0, -1);
		}

		if (!this.options.disableBodyParser) {
			consumer.apply(SkipBodyParsingMiddleware(basePath)).forRoutes("*");
		}

		const handler = toNodeHandler(this.options.auth);
		this.adapter.httpAdapter
			.getInstance()
			.use(async (req: Request, res: Response, next: () => void) => {
				const isAuthPath = req.url.startsWith(basePath) || req.originalUrl.startsWith(basePath);
				
				if (!isAuthPath) {
					return next();
				}

				this.logger.log(`[DEBUG] Incoming Request - Method: ${req.method}, Path: ${req.url}, Original: ${req.originalUrl}`);
				this.logger.log(`[DEBUG] Protocol: ${req.protocol}, Secure: ${req.secure}, X-Proto: ${req.headers['x-forwarded-proto']}`);
				
				const originalPath = req.url;
				
				// Ensure req.url starts with basePath for Better Auth matching
				if (!req.url.startsWith(basePath) && req.originalUrl.startsWith(basePath)) {
					req.url = req.originalUrl;
					this.logger.log(`[DEBUG] Normalized req.url to: ${req.url}`);
				}
				
				try {
					this.logger.log(`[DEBUG] Executing Better Auth handler...`);
					if (this.options.middleware) {
						await this.options.middleware(req, res, () => handler(req, res));
					} else {
						await handler(req, res);
					}
					
					this.logger.log(`[DEBUG] Better Auth Status: ${res.statusCode}, Ended: ${res.writableEnded}`);
					
					// If still 404, troubleshoot why
					if (res.statusCode === 404 && !res.writableEnded) {
						this.logger.warn(`[DEBUG] Request for ${req.url} returned 404. Checking for common pitfalls...`);
						if (this.options.auth.options.baseURL.endsWith('/') && !req.url.startsWith('/')) {
							this.logger.warn('[DEBUG] Potential slash mismatch between baseURL and req.url');
						}
					}
				} catch (error) {
					this.logger.error('[ERROR] Better Auth Handler Exception:', error);
					req.url = originalPath;
					next();
				}
			});
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
