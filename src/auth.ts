import { betterAuth } from "better-auth";
import Database from "better-sqlite3";
import { bearer } from "better-auth/plugins/bearer";
import { admin } from "better-auth/plugins/admin";

export const auth: any = betterAuth({
    database: new Database("auth.db"),
    emailAndPassword: {
        enabled: true
    },
    trustedOrigins: ["*"],
    baseURL: process.env.BETTER_AUTH_URL || "http://localhost:3000",
    basePath: "/api/auth",
    plugins: [
        bearer(),
        admin()
    ]
});
