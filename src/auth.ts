import { betterAuth } from "better-auth";
import Database from "better-sqlite3";
import { bearer } from "better-auth/plugins/bearer";
import { admin } from "better-auth/plugins/admin";

// Fallback to VERCEL_URL for deployment portability
const baseURL = process.env.BETTER_AUTH_URL || 
                (process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : "http://localhost:3000");

export const auth: any = betterAuth({
    database: new Database(":memory:"),
    emailAndPassword: {
        enabled: true
    },
    trustedOrigins: ["*"],
    baseURL,
    basePath: "/api/auth",
    plugins: [
        bearer(),
        admin()
    ]
});
