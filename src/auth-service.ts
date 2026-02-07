import { Inject, Injectable } from "@nestjs/common";
import type { Auth } from "better-auth";
import {
  type AuthModuleOptions,
  MODULE_OPTIONS_TOKEN,
} from "./auth-module-definition.js";

@Injectable()
export class AuthService<T extends Auth = Auth> {
  constructor(
    @Inject(MODULE_OPTIONS_TOKEN)
    private readonly options: AuthModuleOptions<T>,
  ) {}

  get api(): T["api"] {
    return this.options.auth.api;
  }

  get instance(): T {
    return this.options.auth;
  }
}
