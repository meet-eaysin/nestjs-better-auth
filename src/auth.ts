import { betterAuth } from "better-auth";
import Database from "better-sqlite3";
import { bearer } from "better-auth/plugins/bearer";
import { admin } from "better-auth/plugins/admin";

import type { Auth } from "better-auth";

const baseURL =
  process.env.BETTER_AUTH_URL ||
  (process.env.VERCEL_PROJECT_PRODUCTION_URL
    ? `https://${process.env.VERCEL_PROJECT_PRODUCTION_URL}`
    : process.env.VERCEL_URL
      ? `https://${process.env.VERCEL_URL}`
      : "http://localhost:3000");

export const auth: Auth = betterAuth({
  database: new Database(":memory:"),
  secret: process.env.BETTER_AUTH_SECRET,
  emailAndPassword: {
    enabled: true,
  },
  trustedOrigins: ["*"],
  baseURL,
  basePath: "/api/auth",
  advanced: {
    trustHost: true,
    useSecureCookies: process.env.NODE_ENV === "production",
  },
  plugins: [bearer(), admin()],
});
