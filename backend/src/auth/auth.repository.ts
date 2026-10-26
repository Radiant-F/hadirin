import { and, eq, isNull } from "drizzle-orm";
import { randomUUID } from "node:crypto";
import { db } from "../db";
import { refreshTokens, users, type UserRole } from "../db/schema";
import type { AuthRepository, AuthUserRecord, RefreshTokenRecord } from "./auth.service";

export const authRepository: AuthRepository = {
  async findByUsername(username: string) {
    const [user] = await db.select().from(users).where(eq(users.username, username)).limit(1);
    if (!user) return null;

    return {
      id: user.id,
      username: user.username,
      passwordHash: user.passwordHash,
      role: user.role as UserRole,
      createdAt: user.createdAt ?? new Date(),
      updatedAt: user.updatedAt ?? new Date(),
    } satisfies AuthUserRecord;
  },

  async findById(id: string) {
    const [user] = await db.select().from(users).where(eq(users.id, id)).limit(1);
    if (!user) return null;

    return {
      id: user.id,
      username: user.username,
      passwordHash: user.passwordHash,
      role: user.role as UserRole,
      createdAt: user.createdAt ?? new Date(),
      updatedAt: user.updatedAt ?? new Date(),
    } satisfies AuthUserRecord;
  },

  async createUser(input) {
    const id = randomUUID();
    const [user] = await db
      .insert(users)
      .values({
        id,
        username: input.username,
        passwordHash: input.passwordHash,
        role: input.role ?? "user",
      })
      .returning();

    return {
      id: user.id,
      username: user.username,
      passwordHash: user.passwordHash,
      role: user.role as UserRole,
      createdAt: user.createdAt ?? new Date(),
      updatedAt: user.updatedAt ?? new Date(),
    } satisfies AuthUserRecord;
  },

  async listUsers() {
    const rows = await db.select().from(users);
    return rows.map((user) => ({
      id: user.id,
      username: user.username,
      passwordHash: user.passwordHash,
      role: user.role as UserRole,
      createdAt: user.createdAt ?? new Date(),
      updatedAt: user.updatedAt ?? new Date(),
    }));
  },

  async updateUser(id, update) {
    const [updated] = await db
      .update(users)
      .set({
        ...update,
        updatedAt: new Date(),
      })
      .where(eq(users.id, id))
      .returning();

    if (!updated) return null;

    return {
      id: updated.id,
      username: updated.username,
      passwordHash: updated.passwordHash,
      role: updated.role as UserRole,
      createdAt: updated.createdAt ?? new Date(),
      updatedAt: updated.updatedAt ?? new Date(),
    } satisfies AuthUserRecord;
  },

  async deleteUser(id: string) {
    const [deleted] = await db.delete(users).where(eq(users.id, id)).returning({ id: users.id });
    return Boolean(deleted);
  },

  async findRefreshToken(userId: string, tokenHash: string) {
    const [token] = await db
      .select()
      .from(refreshTokens)
      .where(and(eq(refreshTokens.userId, userId), eq(refreshTokens.tokenHash, tokenHash), isNull(refreshTokens.revokedAt)))
      .limit(1);

    if (!token) return null;

    return {
      id: token.id,
      userId: token.userId,
      tokenHash: token.tokenHash,
      expiresAt: token.expiresAt ?? new Date(),
      replacedByTokenHash: token.replacedByTokenHash ?? null,
      revokedAt: token.revokedAt ?? null,
      createdAt: token.createdAt ?? new Date(),
    } satisfies RefreshTokenRecord;
  },

  async saveRefreshToken(input) {
    const [created] = await db
      .insert(refreshTokens)
      .values({
        id: randomUUID(),
        userId: input.userId,
        tokenHash: input.tokenHash,
        expiresAt: input.expiresAt,
        replacedByTokenHash: input.replacedByTokenHash ?? null,
      })
      .returning({ id: refreshTokens.id });

    return Boolean(created);
  },

  async revokeRefreshToken(userId: string, tokenHash: string) {
    const [updated] = await db
      .update(refreshTokens)
      .set({ revokedAt: new Date() })
      .where(and(eq(refreshTokens.userId, userId), eq(refreshTokens.tokenHash, tokenHash)))
      .returning({ id: refreshTokens.id });

    return Boolean(updated);
  },

  async listRefreshTokens(userId: string) {
    const rows = await db.select().from(refreshTokens).where(eq(refreshTokens.userId, userId));
    return rows.map((token) => ({
      id: token.id,
      userId: token.userId,
      tokenHash: token.tokenHash,
      expiresAt: token.expiresAt ?? new Date(),
      replacedByTokenHash: token.replacedByTokenHash ?? null,
      revokedAt: token.revokedAt ?? null,
      createdAt: token.createdAt ?? new Date(),
    }));
  },
};
