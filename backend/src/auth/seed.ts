import { randomUUID } from "node:crypto";
import bcrypt from "bcryptjs";
import { eq } from "drizzle-orm";
import { db } from "../db";
import { users } from "../db/schema";
import type { UserRole } from "./auth.service";

export const seedDefaultUsers = async () => {
  const adminUsername = process.env.DEFAULT_ADMIN_USERNAME;
  const adminPassword = process.env.DEFAULT_ADMIN_PASSWORD;
  const userUsername = process.env.DEFAULT_USER_USERNAME;
  const userPassword = process.env.DEFAULT_USER_PASSWORD;

  const defaultUsers: Array<{ username: string; passwordHash: string; role: UserRole }> = [];

  if (adminUsername && adminPassword) {
    defaultUsers.push({
      username: adminUsername,
      passwordHash: await bcrypt.hash(adminPassword, 10),
      role: "admin",
    });
  }

  if (userUsername && userPassword) {
    defaultUsers.push({
      username: userUsername,
      passwordHash: await bcrypt.hash(userPassword, 10),
      role: "user",
    });
  }

  for (const entry of defaultUsers) {
    const existing = await db.select().from(users).where(eq(users.username, entry.username)).limit(1);

    if (existing.length === 0) {
      await db.insert(users).values({
        id: randomUUID(),
        username: entry.username,
        passwordHash: entry.passwordHash,
        role: entry.role,
      });
      continue;
    }

    const current = existing[0];
    const needsRepair = current.passwordHash !== entry.passwordHash || current.role !== entry.role;

    if (needsRepair) {
      await db
        .update(users)
        .set({
          passwordHash: entry.passwordHash,
          role: entry.role,
          updatedAt: new Date(),
        })
        .where(eq(users.id, current.id));
    }
  }
};
