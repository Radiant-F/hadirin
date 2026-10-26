import { Elysia } from "elysia";
import { swagger } from "@elysiajs/swagger";
import { authRoutes } from "./auth/auth.routes";
import { seedDefaultUsers } from "./auth/seed";

const app = new Elysia()
  .use(
    swagger({
      documentation: {
        info: {
          title: "Hadirin API",
          version: "1.0.0",
          description:
            "Authentication and user management API for the Hadirin QR presence application.",
        },
      },
    }),
  )
  .use(authRoutes)
  .onStart(async () => {
    await seedDefaultUsers();
    console.log("Default users seeded from environment variables.");
  })
  .get("/", () => ({
    name: "Hadirin API",
    status: "running",
  }))
  .listen(3000);

console.log(`🦊 Hadiin API is running at ${app.server?.hostname}:${app.server?.port}`);
