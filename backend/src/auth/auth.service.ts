import crypto from "node:crypto";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

export type UserRole = "user" | "admin";

export interface AuthUserRecord {
  id: string;
  username: string;
  passwordHash: string;
  role: UserRole;
  createdAt: Date;
  updatedAt: Date;
}

export type SafeAuthUser = Omit<AuthUserRecord, "passwordHash">;

export interface RefreshTokenRecord {
  id: string;
  userId: string;
  tokenHash: string;
  expiresAt: Date;
  replacedByTokenHash: string | null;
  revokedAt: Date | null;
  createdAt: Date;
}

export interface AuthRepository {
  findByUsername: (username: string) => Promise<AuthUserRecord | null>;
  findById: (id: string) => Promise<AuthUserRecord | null>;
  createUser: (input: {
    username: string;
    passwordHash: string;
    role?: UserRole;
  }) => Promise<AuthUserRecord>;
  listUsers: () => Promise<AuthUserRecord[]>;
  updateUser: (
    id: string,
    update: Partial<Pick<AuthUserRecord, "username" | "passwordHash" | "role">>,
  ) => Promise<AuthUserRecord | null>;
  deleteUser: (id: string) => Promise<boolean>;
  findRefreshToken: (userId: string, tokenHash: string) => Promise<RefreshTokenRecord | null>;
  saveRefreshToken: (input: {
    userId: string;
    tokenHash: string;
    expiresAt: Date;
    replacedByTokenHash?: string | null;
  }) => Promise<boolean>;
  revokeRefreshToken: (userId: string, tokenHash: string) => Promise<boolean>;
  listRefreshTokens: (userId: string) => Promise<RefreshTokenRecord[]>;
}

export interface AuthServiceDependencies {
  repo: AuthRepository;
  accessSecret: string;
  refreshSecret: string;
  accessTokenTtl: number;
  refreshTokenTtl: number;
  hashPassword?: (password: string) => Promise<string> | string;
  comparePassword?: (password: string, hash: string) => Promise<boolean> | boolean;
  signJwt?: (payload: Record<string, unknown>, secret: string, expiresIn: number) => Promise<string> | string;
  verifyJwt?: (token: string, secret: string) => Promise<unknown> | unknown;
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

export const validateUsername = (username: string): string => {
  const trimmed = username?.trim();

  if (!trimmed || trimmed.length < 4) {
    throw new Error("Username must be at least 4 characters");
  }

  return trimmed;
};

export const validatePassword = (password: string): string => {
  if (!password || password.length < 6 || !/[A-Za-z]/.test(password) || !/\d/.test(password)) {
    throw new Error("Password must be at least 6 characters and include both letters and numbers");
  }

  return password;
};

const sanitizeUser = (user: AuthUserRecord): SafeAuthUser => {
  const { passwordHash, ...rest } = user;
  return rest;
};

const hashToken = (token: string): string =>
  crypto.createHash("sha256").update(token).digest("hex");

export function createAuthService(deps: AuthServiceDependencies) {
  const hashPassword = deps.hashPassword ?? ((password: string) => bcrypt.hash(password, 10));
  const comparePassword = deps.comparePassword ?? ((password: string, hash: string) => bcrypt.compare(password, hash));
  const signJwt =
    deps.signJwt ??
    ((payload: Record<string, unknown>, secret: string, expiresIn: number) =>
      jwt.sign(payload, secret, { expiresIn }));
  const verifyJwt = deps.verifyJwt ?? ((token: string, secret: string) => jwt.verify(token, secret));

  const createTokenPair = async (user: AuthUserRecord): Promise<TokenPair> => {
    const accessPayload = {
      sub: user.id,
      username: user.username,
      role: user.role,
      type: "access",
    };

    const refreshPayload = {
      sub: user.id,
      role: user.role,
      type: "refresh",
    };

    const accessToken = await signJwt(accessPayload, deps.accessSecret, deps.accessTokenTtl);
    const refreshToken = await signJwt(refreshPayload, deps.refreshSecret, deps.refreshTokenTtl);
    const refreshHash = hashToken(refreshToken);

    await deps.repo.saveRefreshToken({
      userId: user.id,
      tokenHash: refreshHash,
      expiresAt: new Date(Date.now() + deps.refreshTokenTtl * 1000),
    });

    return { accessToken, refreshToken };
  };

  return {
    async register(input: { username: string; password: string }) {
      const username = validateUsername(input.username);
      validatePassword(input.password);

      const existingUser = await deps.repo.findByUsername(username);
      if (existingUser) {
        throw new Error("User already exists");
      }

      const user = await deps.repo.createUser({
        username,
        passwordHash: await hashPassword(input.password),
        role: "user",
      });

      const tokens = await createTokenPair(user);

      return {
        user: sanitizeUser(user),
        tokens,
      };
    },

    async login(input: { username: string; password: string }) {
      const username = input.username.trim();
      const user = await deps.repo.findByUsername(username);

      if (!user) {
        throw new Error("Invalid credentials");
      }

      const validPassword = await comparePassword(input.password, user.passwordHash);
      if (!validPassword) {
        throw new Error("Invalid credentials");
      }

      const tokens = await createTokenPair(user);

      return {
        user: sanitizeUser(user),
        tokens,
      };
    },

    async refresh(input: { refreshToken: string }) {
      const refreshToken = input.refreshToken;

      if (!refreshToken) {
        throw new Error("Refresh token is required");
      }

      const claims = (await verifyJwt(refreshToken, deps.refreshSecret)) as {
        sub?: string;
        role?: UserRole;
        type?: string;
      };

      if (!claims || claims.type !== "refresh" || !claims.sub) {
        throw new Error("Invalid refresh token");
      }

      const tokenHash = hashToken(refreshToken);
      const storedToken = await deps.repo.findRefreshToken(claims.sub, tokenHash);
      if (!storedToken || new Date(storedToken.expiresAt) < new Date()) {
        throw new Error("Refresh token expired or revoked");
      }

      const user = await deps.repo.findById(claims.sub);
      if (!user) {
        throw new Error("User not found");
      }

      await deps.repo.revokeRefreshToken(user.id, tokenHash);
      const tokens = await createTokenPair(user);

      return {
        user: sanitizeUser(user),
        tokens,
      };
    },

    async logout(userId: string, refreshToken: string) {
      if (!refreshToken) {
        return { success: true };
      }

      const tokenHash = hashToken(refreshToken);
      await deps.repo.revokeRefreshToken(userId, tokenHash);
      return { success: true };
    },

    async me(userId: string) {
      const user = await deps.repo.findById(userId);
      if (!user) {
        throw new Error("User not found");
      }

      return sanitizeUser(user);
    },

    async listUsers(actor: { userId: string; role: UserRole }) {
      if (actor.role !== "admin") {
        throw new Error("Forbidden");
      }

      const users = await deps.repo.listUsers();
      return users.map(sanitizeUser);
    },

    async getUserById(actor: { userId: string; role: UserRole }, userId: string) {
      if (actor.role !== "admin" && actor.userId !== userId) {
        throw new Error("Forbidden");
      }

      const user = await deps.repo.findById(userId);
      if (!user) {
        throw new Error("User not found");
      }

      return sanitizeUser(user);
    },

    async updateUserProfile(userId: string, input: { username?: string; password?: string }) {
      const current = await deps.repo.findById(userId);
      if (!current) {
        throw new Error("User not found");
      }

      const update: Partial<Pick<AuthUserRecord, "username" | "passwordHash" | "role">> = {};

      if (input.username) {
        update.username = validateUsername(input.username);
      }

      if (input.password) {
        validatePassword(input.password);
        update.passwordHash = await hashPassword(input.password);
      }

      const updated = await deps.repo.updateUser(userId, update);
      if (!updated) {
        throw new Error("User not found");
      }

      return sanitizeUser(updated);
    },

    async updateUserById(
      actor: { userId: string; role: UserRole },
      userId: string,
      input: { username?: string; password?: string; role?: UserRole },
    ) {
      if (actor.role !== "admin") {
        throw new Error("Forbidden");
      }

      const update: Partial<Pick<AuthUserRecord, "username" | "passwordHash" | "role">> = {};

      if (input.username) {
        update.username = validateUsername(input.username);
      }

      if (input.password) {
        validatePassword(input.password);
        update.passwordHash = await hashPassword(input.password);
      }

      if (input.role) {
        if (input.role !== "user" && input.role !== "admin") {
          throw new Error("Invalid role");
        }
        update.role = input.role;
      }

      const updated = await deps.repo.updateUser(userId, update);
      if (!updated) {
        throw new Error("User not found");
      }

      return sanitizeUser(updated);
    },

    async deleteUser(actor: { userId: string; role: UserRole }, userId: string) {
      if (actor.role !== "admin") {
        throw new Error("Forbidden");
      }

      const deleted = await deps.repo.deleteUser(userId);
      if (!deleted) {
        throw new Error("User not found");
      }

      return { success: true };
    },
  };
}
