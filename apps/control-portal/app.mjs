import express from "express";
import helmet from "helmet";
import { rateLimit } from "express-rate-limit";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import { Sessions, equalSecret } from "./auth.mjs";
import { runLabTest, tests } from "./lab.mjs";
import { story, reportHtml } from "../../shared/report.mjs";

export function createApp({
  config,
  store,
  reportProvider,
  preview = false,
  fetcher = fetch,
}) {
  if (
    !preview &&
    (config.adminPassword?.length < 43 ||
      config.sessionKey?.length < 43 ||
      !config.adminPassword ||
      !config.sessionKey ||
      config.adminPassword.startsWith("@Microsoft.KeyVault") ||
      config.sessionKey.startsWith("@Microsoft.KeyVault"))
  )
    throw new Error("Resolved Key Vault credentials are required");
  const app = express();
  const sessions = new Sessions(
    config.sessionKey || "preview-no-session",
    store,
  );
  app.disable("x-powered-by");
  app.set("trust proxy", false);
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"],
          styleSrc: ["'self'"],
          imgSrc: ["'self'", "data:"],
          connectSrc: ["'self'"],
          objectSrc: ["'none'"],
          frameAncestors: ["'none'"],
          upgradeInsecureRequests: preview ? null : [],
        },
      },
    }),
  );
  app.use((_request, response, next) => {
    response.setHeader("Cache-Control", "no-store");
    next();
  });
  app.use(express.json({ limit: "2kb" }));
  app.get("/health", (_request, response) =>
    response.json({
      status: "running",
      mode: preview ? "read-only-preview" : "configured",
      securityEfficacy: "not-attested",
    }),
  );
  app.use(
    "/api",
    rateLimit({
      windowMs: 60000,
      limit: 120,
      standardHeaders: "draft-8",
      legacyHeaders: false,
      validate: { xForwardedForHeader: false },
    }),
  );
  app.use("/api", async (request, _response, next) => {
    request.session = preview
      ? null
      : await sessions.read(request.headers.cookie);
    next();
  });
  app.use("/api", (request, response, next) => {
    if (!["GET", "HEAD"].includes(request.method)) {
      if (preview)
        return response.status(403).json({
          error: "Read-only preview: no credentials or Azure operations",
        });
      if (
        request.headers.origin !== config.origin ||
        !request.is("application/json")
      )
        return response
          .status(403)
          .json({ error: "Same-origin JSON required" });
      if (
        request.path !== "/login" &&
        (!request.session ||
          !equalSecret(
            request.headers["x-csrf-token"] || "",
            request.session.csrf,
          ))
      )
        return response
          .status(403)
          .json({ error: "Valid session and CSRF token required" });
    }
    next();
  });
  app.post(
    "/api/login",
    rateLimit({
      windowMs: 15 * 60000,
      limit: 10,
      standardHeaders: "draft-8",
      legacyHeaders: false,
      validate: { xForwardedForHeader: false },
    }),
    async (request, response) => {
      const valid =
        request.body?.username === "admin" &&
        typeof request.body?.password === "string" &&
        equalSecret(request.body.password, config.adminPassword);
      await store.put(
        `audit/${new Date().toISOString()}-${randomUUID()}.json`,
        {
          event: valid ? "login-succeeded" : "login-failed",
          at: new Date().toISOString(),
        },
      );
      if (!valid)
        return response.status(401).json({ error: "Invalid credentials" });
      const { token, session } = await sessions.create();
      response.cookie("dojo_session", token, {
        httpOnly: true,
        secure: config.origin.startsWith("https:"),
        sameSite: "strict",
        path: "/",
        maxAge: 3600000,
      });
      response.json({ user: "admin", csrf: session.csrf });
    },
  );
  app.get("/api/session", (request, response) =>
    response.json({
      user: request.session ? "admin" : null,
      csrf: request.session?.csrf,
      preview,
    }),
  );
  app.use("/api", (request, response, next) => {
    if (!preview && !request.session)
      return response.status(401).json({ error: "Admin sign-in required" });
    next();
  });
  app.post("/api/logout", async (request, response) => {
    await sessions.revoke(request.session);
    response.clearCookie("dojo_session", {
      httpOnly: true,
      secure: config.origin.startsWith("https:"),
      sameSite: "strict",
      path: "/",
    });
    response.json({ signedOut: true });
  });
  let reportCache;
  let collecting;
  const report = async () => {
    if (reportCache && Date.now() - reportCache.time < 30000)
      return reportCache.value;
    if (collecting) return collecting;
    collecting = (async () => {
      const value = await reportProvider(await store.list("runs/"));
      value.release = {
        ...value.release,
        dojoDigest: config.dojoDigest,
        portalDigest: config.portalDigest,
        drowsyDragonDigest: config.drowsyDragonDigest,
        nginxProxyDigest: config.nginxProxyDigest,
      };
      if (!preview) await store.put(`reports/${value.generatedAt}.json`, value);
      reportCache = { time: Date.now(), value };
      return value;
    })();
    try {
      return await collecting;
    } finally {
      collecting = null;
    }
  };
  app.get("/api/story", (_request, response) => response.json(story));
  app.get("/api/tests", (_request, response) =>
    response.json(tests.map(({ path: _path, ...test }) => test)),
  );
  app.get("/api/report", async (_request, response) =>
    response.json(await report()),
  );
  app.get("/api/report.json", async (_request, response) =>
    response
      .attachment("code-to-cloud-security-dojo-report.json")
      .json(await report()),
  );
  app.get("/api/report.html", async (_request, response) =>
    response
      .setHeader(
        "Content-Security-Policy",
        "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'",
      )
      .type("html")
      .send(reportHtml(await report())),
  );
  app.post("/api/tests/:id", async (request, response) => {
    if (
      request.body?.confirm !== "authorized-training" ||
      Object.keys(request.body).some((key) => key !== "confirm")
    )
      return response.status(400).json({
        error:
          "Explicit training consent required; custom payloads are not accepted",
      });
    const result = await runLabTest({
      id: request.params.id,
      config,
      store,
      fetcher,
    });
    reportCache = null;
    response.json(result);
  });
  app.use("/api", (_request, response) =>
    response.status(404).json({ error: "Unknown operation" }),
  );
  app.get("/icons.js", (_request, response) =>
    response.sendFile(
      fileURLToPath(
        new URL(
          "../../node_modules/lucide/dist/umd/lucide.js",
          import.meta.url,
        ),
      ),
    ),
  );
  app.use(
    express.static(fileURLToPath(new URL("./public/", import.meta.url)), {
      etag: false,
    }),
  );
  app.use((error, _request, response, _next) => {
    const messages = {
      400: "Invalid request.",
      403: "Request denied.",
      409: "Another test is active.",
      413: "Request body is too large.",
      429: "Request limit reached; retry later.",
    };
    const status = Object.hasOwn(messages, error.status) ? error.status : 503;
    response.status(status).json({
      error:
        status === 503
          ? "Evidence service unavailable; operation not confirmed. Retry after checking Azure access and service health."
          : messages[status],
    });
  });
  return app;
}
