import {
  ForbiddenException,
  Inject,
  Injectable,
  UnauthorizedException,
} from "@nestjs/common";
import type {
  CanActivate,
  ContextType,
  ExecutionContext,
} from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import type { getSession } from "better-auth/api";
import { fromNodeHeaders } from "better-auth/node";
import {
  type AuthModuleOptions,
  MODULE_OPTIONS_TOKEN,
} from "./auth-module-definition.js";
import { getRequestFromContext } from "./utils.js";
import { GraphQLError, GraphQLErrorOptions } from "graphql";

export type BaseUserSession = NonNullable<
  Awaited<ReturnType<ReturnType<typeof getSession>>>
>;

export type UserSession = BaseUserSession & {
  user: BaseUserSession["user"] & {
    role?: string | string[];
  };
};

const AuthErrorType = {
  UNAUTHORIZED: "UNAUTHORIZED",
  FORBIDDEN: "FORBIDDEN",
} as const;

let WsException: any;
function getWsException() {
  if (!WsException) {
    try {
      WsException = require("@nestjs/websockets").WsException;
    } catch {
      throw new Error("@nestjs/websockets is required for WebSocket support.");
    }
  }
  return WsException;
}

const AuthContextErrorMap: Record<
  ContextType | "graphql",
  Record<keyof typeof AuthErrorType, (args?: unknown) => Error>
> = {
  http: {
    UNAUTHORIZED: (args) =>
      new UnauthorizedException(
        args ?? {
          code: "UNAUTHORIZED",
          message: "Unauthorized",
        },
      ),
    FORBIDDEN: (args) =>
      new ForbiddenException(
        args ?? {
          code: "FORBIDDEN",
          message: "Insufficient permissions",
        },
      ),
  },
  graphql: {
    UNAUTHORIZED: (args) => {
      if (typeof args === "string") return new GraphQLError(args);
      if (typeof args === "object" && args) {
        return new GraphQLError(
          (args as Record<string, any>).message ?? "Unauthorized",
          args as GraphQLErrorOptions,
        );
      }
      return new GraphQLError("Unauthorized");
    },
    FORBIDDEN: (args) => {
      if (typeof args === "string") return new GraphQLError(args);
      if (typeof args === "object" && args) {
        return new GraphQLError(
          (args as Record<string, any>).message ?? "Forbidden",
          args as GraphQLErrorOptions,
        );
      }
      return new GraphQLError("Forbidden");
    },
  },
  ws: {
    UNAUTHORIZED: (args) => {
      const WsExceptionClass = getWsException();
      return new WsExceptionClass(args ?? "UNAUTHORIZED");
    },
    FORBIDDEN: (args) => {
      const WsExceptionClass = getWsException();
      return new WsExceptionClass(args ?? "FORBIDDEN");
    },
  },
  rpc: {
    UNAUTHORIZED: () => new Error("UNAUTHORIZED"),
    FORBIDDEN: () => new Error("FORBIDDEN"),
  },
};

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    @Inject(Reflector) private readonly reflector: Reflector,
    @Inject(MODULE_OPTIONS_TOKEN) private readonly options: AuthModuleOptions,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = getRequestFromContext(context);
    const session: UserSession | null = await this.options.auth.api.getSession({
      headers: fromNodeHeaders(
        request.headers || request?.handshake?.headers || [],
      ),
    });

    request.session = session;
    request.user = session?.user ?? null; // useful for observability tools like Sentry

    const isPublic = this.reflector.getAllAndOverride<boolean>("PUBLIC", [
      context.getHandler(),
      context.getClass(),
    ]);

    if (isPublic) return true;

    const isOptional = this.reflector.getAllAndOverride<boolean>("OPTIONAL", [
      context.getHandler(),
      context.getClass(),
    ]);

    if (!session && isOptional) return true;

    const ctxType = context.getType();
    if (!session) throw AuthContextErrorMap[ctxType].UNAUTHORIZED();

    const requiredRoles = this.reflector.getAllAndOverride<string[]>("ROLES", [
      context.getHandler(),
      context.getClass(),
    ]);

    if (requiredRoles && requiredRoles.length > 0) {
      const userRole = session.user.role;
      let hasRole = false;
      if (Array.isArray(userRole)) {
        hasRole = userRole.some((role) => requiredRoles.includes(role));
      } else if (typeof userRole === "string") {
        hasRole = userRole
          .split(",")
          .some((role) => requiredRoles.includes(role));
      }

      if (!hasRole) throw AuthContextErrorMap[ctxType].FORBIDDEN();
    }

    return true;
  }
}
