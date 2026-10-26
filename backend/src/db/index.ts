import postgres from "postgres";
import { drizzle } from "drizzle-orm/postgres-js";
import * as schema from "./schema";

const connectionString = process.env.DATABASE_URL;

if (!connectionString) {
  throw new Error("DATABASE_URL is not configured.");
}

const client = postgres(connectionString, { max: 10, ssl: false });
export const db = drizzle(client, { schema });
export * as schema from "./schema";
