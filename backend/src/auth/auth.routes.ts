import { Elysia, t } from "elysia";
import jwt from "jsonwebtoken";
import { authRepository } from "./auth.repository";
import { createAuthService, type UserRole } from "./auth.service";

const accessSecret = process.env.JWT_ACCESS_SECRET ?? "development-access-secret";
const refreshSecret = process.env.JWT_REFRESH_SECRET ?? "development-refresh-secret";

const authService = createAuthService({
  repo: authRepository,
  accessSecret,
  refreshSecret,
  accessTokenTtl: 60 * 15,
  refreshTokenTtl: 60 * 60 * 24 * 7,
});

const resolveActor = (request: Request) => {
  const authorization = request.headers.get("authorization");

  if (!authorization || !authorization.startsWith("Bearer ")) {
    throw new Error("Unauthorized");
  }

  const token = authorization.replace("Bearer ", "");
  const claims = jwt.verify(token, accessSecret) as {
    sub: string;
    role: UserRole;
    type?: string;
  };

  if (!claims || claims.type !== "access") {
    throw new Error("Unauthorized");
  }

  return { userId: claims.sub, role: claims.role };
};

export const authRoutes = new Elysia({ name: "auth-routes" })
  .post(
    "/auth/register",
    async ({ body }) => authService.register(body),
    {
      body: t.Object({
        username: t.String({ minLength: 4 }),
        password: t.String({ minLength: 6 }),
      }),
    },
  )
  .post(
    "/auth/login",
    async ({ body }) => authService.login(body),
    {
      body: t.Object({
        username: t.String({ minLength: 1 }),
        password: t.String({ minLength: 1 }),
      }),
    },
  )
  .post(
    "/auth/refresh",
    async ({ body }) => authService.refresh(body),
    {
      body: t.Object({
        refreshToken: t.String(),
      }),
    },
  )
  .get("/auth/me", async ({ request }) => {
    const actor = resolveActor(request);
    return authService.me(actor.userId);
  })
  .post("/auth/logout", async ({ request, body }) => {
    const actor = resolveActor(request);
    const payload = body as { refreshToken?: string };
    return authService.logout(actor.userId, payload?.refreshToken ?? "");
  }, {
    body: t.Object({
      refreshToken: t.Optional(t.String()),
    }),
  })
  .get("/users", async ({ request }) => {
    const actor = resolveActor(request);
    return authService.listUsers(actor);
  })
  .get("/users/:id", async ({ request, params }) => {
    const actor = resolveActor(request);
    return authService.getUserById(actor, params.id);
  })
  .patch("/users/:id", async ({ request, params, body }) => {
    const actor = resolveActor(request);
    if (actor.role !== "admin" && actor.userId !== params.id) {
      throw new Error("Forbidden");
    }

    const update = body as { username?: string; password?: string; role?: UserRole };

    if (actor.role !== "admin") {
      return authService.updateUserProfile(params.id, {
        username: update.username,
        password: update.password,
      });
    }

    return authService.updateUserById(actor, params.id, update);
  }, {
    body: t.Object({
      username: t.Optional(t.String({ minLength: 4 })),
      password: t.Optional(t.String({ minLength: 6 })),
      role: t.Optional(t.Union([t.Literal("user"), t.Literal("admin")])),
    }),
  })
  .delete("/users/:id", async ({ request, params }) => {
    const actor = resolveActor(request);
    return authService.deleteUser(actor, params.id);
  });
