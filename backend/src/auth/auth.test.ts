import { describe, expect, it } from "bun:test";
import {
  validateUsername,
  validatePassword,
  createAuthService,
  type AuthUserRecord,
} from "./auth.service";

describe("auth validation", () => {
  it("rejects username shorter than 4 characters", () => {
    expect(() => validateUsername("abc")).toThrow("Username must be at least 4 characters");
  });

  it("rejects password without a number and a letter", () => {
    expect(() => validatePassword("abcdef")).toThrow(
      "Password must be at least 6 characters and include both letters and numbers",
    );
  });

  it("accepts valid credentials", () => {
    expect(() => validateUsername("admin")).not.toThrow();
    expect(() => validatePassword("pass123")).not.toThrow();
  });
});

describe("auth service", () => {
  const userRecord: AuthUserRecord = {
    id: "u-1",
    username: "alice",
    passwordHash: "hashed-pass",
    role: "user",
    createdAt: new Date("2024-01-01T00:00:00Z"),
    updatedAt: new Date("2024-01-01T00:00:00Z"),
  };

  it("registers a new user and hashes the password", async () => {
    const repo = {
      findByUsername: async () => null,
      createUser: async (input: { username: string; passwordHash: string; role?: "user" | "admin" }) => ({
        id: "u-2",
        username: input.username,
        passwordHash: input.passwordHash,
        role: input.role ?? "user",
        createdAt: new Date(),
        updatedAt: new Date(),
      }),
      listUsers: async () => [],
      findById: async () => null,
      updateUser: async () => null,
      deleteUser: async () => false,
      findRefreshToken: async () => null,
      saveRefreshToken: async () => true,
      revokeRefreshToken: async () => true,
      listRefreshTokens: async () => [],
    };

    const service = createAuthService({
      repo,
      accessSecret: "access-secret",
      refreshSecret: "refresh-secret",
      accessTokenTtl: 60,
      refreshTokenTtl: 7 * 24 * 60 * 60,
      hashPassword: async (password: string) => `hashed:${password}`,
      comparePassword: async (password: string, hash: string) => password === hash.replace("hashed:", ""),
      signJwt: async (payload: unknown, secret: string) => `${secret}:${JSON.stringify(payload)}`,
      verifyJwt: async (token: string, secret: string) => JSON.parse(token.replace(`${secret}:`, "")),
    });

    const result = await service.register({ username: "alice", password: "pass123" });
    expect(result.user.username).toBe("alice");
    expect("passwordHash" in result.user).toBe(false);
    expect(result.tokens.accessToken).toContain("access-secret:");
  });

  it("allows a user to update their own profile", async () => {
    const repo = {
      findByUsername: async () => null,
      createUser: async () => userRecord,
      listUsers: async () => [userRecord],
      findById: async (id: string) => (id === "u-1" ? userRecord : null),
      updateUser: async (id: string, payload: Partial<AuthUserRecord>) => ({
        ...userRecord,
        ...payload,
        id,
      }),
      deleteUser: async () => true,
      findRefreshToken: async () => null,
      saveRefreshToken: async () => true,
      revokeRefreshToken: async () => true,
      listRefreshTokens: async () => [],
    };

    const service = createAuthService({
      repo,
      accessSecret: "access-secret",
      refreshSecret: "refresh-secret",
      accessTokenTtl: 60,
      refreshTokenTtl: 7 * 24 * 60 * 60,
      hashPassword: async (password: string) => `hashed:${password}`,
      comparePassword: async () => true,
      signJwt: async (payload: unknown, secret: string) => `${secret}:${JSON.stringify(payload)}`,
      verifyJwt: async (token: string, secret: string) => JSON.parse(token.replace(`${secret}:`, "")),
    });

    const result = await service.updateUserProfile("u-1", { username: "alice-updated" });
    expect(result.username).toBe("alice-updated");
  });

  it("blocks non-admin access to admin user listing", async () => {
    const repo = {
      findByUsername: async () => null,
      createUser: async () => userRecord,
      listUsers: async () => [userRecord],
      findById: async () => userRecord,
      updateUser: async () => userRecord,
      deleteUser: async () => true,
      findRefreshToken: async () => null,
      saveRefreshToken: async () => true,
      revokeRefreshToken: async () => true,
      listRefreshTokens: async () => [],
    };

    const service = createAuthService({
      repo,
      accessSecret: "access-secret",
      refreshSecret: "refresh-secret",
      accessTokenTtl: 60,
      refreshTokenTtl: 7 * 24 * 60 * 60,
      hashPassword: async (password: string) => `hashed:${password}`,
      comparePassword: async () => true,
      signJwt: async (payload: unknown, secret: string) => `${secret}:${JSON.stringify(payload)}`,
      verifyJwt: async (token: string, secret: string) => JSON.parse(token.replace(`${secret}:`, "")),
    });

    await expect(service.listUsers({ userId: "u-1", role: "user" })).rejects.toThrow("Forbidden");
  });
});
