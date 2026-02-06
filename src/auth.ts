import { betterAuth } from "better-auth";
import Database from "better-sqlite3";
import { bearer } from "better-auth/plugins/bearer";
import { admin } from "better-auth/plugins/admin";

// Hardcoded for testing production 404 issue
const baseURL = "https://nestjs-better-auth.vercel.app";

export const auth: any = betterAuth({
    database: new Database(":memory:"),
    secret: process.env.BETTER_AUTH_SECRET,
    emailAndPassword: {
        enabled: true
    },
    trustedOrigins: ["*"],
    baseURL,
    basePath: "/api/auth",
    advanced: {
        trustHost: true,
        useSecureCookies: process.env.NODE_ENV === "production"
    },
    plugins: [
        bearer(),
        admin()
    ]
});
