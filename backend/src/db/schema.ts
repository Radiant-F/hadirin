import { pgTable, text, timestamp, uniqueIndex } from "drizzle-orm/pg-core";

export const userRoleEnum = ["user", "admin"] as const;
export type UserRole = (typeof userRoleEnum)[number];

export const users = pgTable(
  "users",
  {
    id: text("id").primaryKey(),
    username: text("username").notNull(),
    passwordHash: text("password_hash").notNull(),
    role: text("role", { enum: userRoleEnum }).notNull().default("user"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [{ usernameIdx: uniqueIndex("users_username_unique").on(table.username) }],
);

export const refreshTokens = pgTable("refresh_tokens", {
  id: text("id").primaryKey(),
  userId: text("user_id")
    .notNull()
    .references(() => users.id, { onDelete: "cascade" }),
  tokenHash: text("token_hash").notNull(),
  expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
  replacedByTokenHash: text("replaced_by_token_hash"),
  revokedAt: timestamp("revoked_at", { withTimezone: true }),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export type UserInsert = typeof users.$inferInsert;
export type UserSelect = typeof users.$inferSelect;
export type RefreshTokenInsert = typeof refreshTokens.$inferInsert;
export type RefreshTokenSelect = typeof refreshTokens.$inferSelect;
