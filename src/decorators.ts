import { SetMetadata, createParamDecorator } from "@nestjs/common";
import type { CustomDecorator, ExecutionContext } from "@nestjs/common";
import type { createAuthMiddleware } from "better-auth/api";
import { AFTER_HOOK_KEY, BEFORE_HOOK_KEY, HOOK_KEY } from "./symbols.js";
import { getRequestFromContext } from "./utils.js";

/**
 * Allows unauthenticated access to a route.
 */
export const AllowAnonymous = (): CustomDecorator<string> =>
  SetMetadata("PUBLIC", true);

/**
 * Allows the request to proceed even if no session is present.
 */
export const OptionalAuth = (): CustomDecorator<string> =>
  SetMetadata("OPTIONAL", true);

/**
 * Specifies required roles for a route.
 */
export const Roles = (roles: string[]): CustomDecorator =>
  SetMetadata("ROLES", roles);

/**
 * @deprecated Use AllowAnonymous() instead.
 */
export const Public = AllowAnonymous;

/**
 * @deprecated Use OptionalAuth() instead.
 */
export const Optional = OptionalAuth;

/**
 * Extracts the user session from the request.
 * Works with HTTP, GraphQL, and WebSocket.
 */
export const Session: ReturnType<typeof createParamDecorator> =
  createParamDecorator((_data: unknown, context: ExecutionContext) => {
    const request = getRequestFromContext(context);
    return request.session;
  });
/**
 * Context object passed to hooks.
 */
export type AuthHookContext = Parameters<
  Parameters<typeof createAuthMiddleware>[0]
>[0];

/**
 * Registers a method to execute before an auth route.
 */
export const BeforeHook = (path?: `/${string}`): CustomDecorator<symbol> =>
  SetMetadata(BEFORE_HOOK_KEY, path);

/**
 * Registers a method to execute after an auth route.
 */
export const AfterHook = (path?: `/${string}`): CustomDecorator<symbol> =>
  SetMetadata(AFTER_HOOK_KEY, path);

/**
 * Marks a provider as containing hook methods.
 */
export const Hook = (): ClassDecorator => SetMetadata(HOOK_KEY, true);
