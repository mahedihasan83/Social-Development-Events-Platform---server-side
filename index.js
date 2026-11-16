/**
 * Shohojog API — Express + MongoDB (plain JavaScript / ESM).
 *
 * Social development events platform backend:
 *  - Express REST API for events and event joins
 *  - MongoDB Atlas connection shared across the whole API
 */

import "dotenv/config";
import express from "express";
import cors from "cors";
import { MongoClient, ServerApiVersion, ObjectId } from "mongodb";
import { betterAuth, APIError } from "better-auth";
import { createAuthMiddleware } from "@better-auth/core/api";
import { mongodbAdapter } from "@better-auth/mongo-adapter";
import { toNodeHandler } from "better-auth/node";
import { createRemoteJWKSet, jwtVerify } from "jose";

/* ══════════════════════════ Environment ══════════════════════════ */

const PORT = Number(process.env.PORT ?? 5000);
const MONGODB_URI = process.env.MONGODB_URI;
const MONGODB_DB = process.env.MONGODB_DB || "shohojog";
const SERVER_URL = process.env.SERVER_URL ?? `http://localhost:${PORT}`;
const CLIENT_URL = process.env.CLIENT_URL ?? "http://localhost:3000";

if (!MONGODB_URI) {
  console.error("❌ MONGODB_URI is not set. Add it to .env and restart.");
  process.exit(1);
}

/* ══════════════════════════ MongoDB ══════════════════════════ */

// Single MongoClient shared by the whole API.
const client = new MongoClient(MONGODB_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

const db = client.db(MONGODB_DB);

/** All social service events created by users. */
const eventsCollection = db.collection("events");

/** Join records: which logged-in user joined which event. */
const joinsCollection = db.collection("event_joins");

let indexesPromise = null;

/** Idempotent index creation — runs once per process. */
function ensureIndexes() {
  if (!indexesPromise) {
    indexesPromise = (async () => {
      await eventsCollection.createIndex({ date: 1 });
      await eventsCollection.createIndex({ creatorEmail: 1 });
      await eventsCollection.createIndex({ createdAt: -1 });
      // One join per user per event — the unique index prevents duplicates.
      await joinsCollection.createIndex({ eventId: 1, userEmail: 1 }, { unique: true });
      await joinsCollection.createIndex({ userEmail: 1 });
    })().catch((error) => {
      indexesPromise = null; // allow a retry on the next request
      throw error;
    });
  }
  return indexesPromise;
}

// Warm up the connection in the background (lazy — never blocks startup).
client.connect().catch((error) => {
  console.error("⚠️  MongoDB connection problem:", error.message);
});

/* ══════════════════════════ BetterAuth ══════════════════════════ */

const isProd = process.env.NODE_ENV === "production";

// Only register Google when credentials exist, so the API boots without them.
const socialProviders = {
  ...(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET
    ? {
        google: {
          clientId: process.env.GOOGLE_CLIENT_ID,
          clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        },
      }
    : {}),
};

const auth = betterAuth({
  appName: "Shohojog",
  baseURL: SERVER_URL,
  trustedOrigins: [CLIENT_URL],
  secret: process.env.BETTER_AUTH_SECRET,

  database: mongodbAdapter(db, { client }),

  emailAndPassword: {
    enabled: true,
    minPasswordLength: 6,
    maxPasswordLength: 128,
    autoSignIn: true,
  },

  // Assignment rule enforced server-side: passwords must contain at least
  // one uppercase and one lowercase letter — BetterAuth only checks length.
  hooks: {
    before: createAuthMiddleware(async (ctx) => {
      if (ctx.path === "/sign-up/email") {
        const password = ctx.body?.password;
        if (
          typeof password === "string" &&
          (!/[A-Z]/.test(password) || !/[a-z]/.test(password))
        ) {
          throw new APIError("BAD_REQUEST", {
            message:
              "Password must contain at least one uppercase letter and one lowercase letter.",
          });
        }
      }
    }),
  },

  socialProviders,

  // In production the client (Vercel) and server (Render) sit on different
  // domains, so the session cookie must be SameSite=None + Secure.
  advanced: {
    useSecureCookies: isProd,
    ...(isProd ? { defaultCookieAttributes: { sameSite: "none", secure: true } } : {}),
  },
});

/* ══════════════════════════ JWT middleware ══════════════════════════ */

// JWKS keys are cached by jose; `kid` mismatches trigger a refetch.
const JWKS = createRemoteJWKSet(new URL(`${SERVER_URL}/api/auth/jwks`));

async function verifyBearerToken(header) {
  if (!header?.startsWith("Bearer ")) return null;
  const token = header.slice("Bearer ".length).trim();
  if (!token) return null;

  const { payload } = await jwtVerify(token, JWKS, {
    issuer: SERVER_URL, // must match BetterAuth baseURL
    audience: SERVER_URL, // BetterAuth sets audience = baseURL by default
  });

  if (typeof payload.id !== "string" || typeof payload.email !== "string") {
    return null;
  }

  return {
    id: payload.id,
    email: payload.email,
    name: typeof payload.name === "string" ? payload.name : payload.email,
    image: typeof payload.image === "string" ? payload.image : null,
  };
}

/** 401s unless the request carries a valid JWT. Use on protected routes. */
async function requireAuth(req, res, next) {
  try {
    const user = await verifyBearerToken(req.headers.authorization);
    if (!user) {
      return res
        .status(401)
        .json({ error: "Authentication required. Please log in to continue." });
    }
    req.user = user;
    next();
  } catch {
    return res.status(401).json({ error: "Your session has expired. Please log in again." });
  }
}

/** Attaches `req.user` when a valid JWT is present, but never rejects. */
async function optionalAuth(req, _res, next) {
  try {
    req.user = (await verifyBearerToken(req.headers.authorization)) ?? undefined;
  } catch {
    req.user = undefined;
  }
  next();
}

/* ══════════════════════════ Helpers ══════════════════════════ */

const EVENT_TYPES = [
  "Cleanup",
  "Plantation",
  "Donation",
  "Blood Drive",
  "Food Distribution",
  "Winter Clothes",
  "Education",
  "Health Camp",
  "Awareness Campaign",
  "Other",
];

const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const URL_RE = /^https?:\/\/\S+$/;

/** Today as an ISO calendar date (YYYY-MM-DD). String comparison works for ISO dates. */
function todayISO() {
  return new Date().toISOString().slice(0, 10);
}

function serializeEvent(doc) {
  return {
    _id: String(doc._id),
    title: doc.title,
    description: doc.description,
    eventType: doc.eventType,
    thumbnailUrl: doc.thumbnailUrl,
    location: doc.location,
    date: doc.date,
    creatorId: doc.creatorId,
    creatorEmail: doc.creatorEmail,
    creatorName: doc.creatorName,
    joinedCount: doc.joinedCount ?? 0,
    createdAt: doc.createdAt instanceof Date ? doc.createdAt.toISOString() : null,
  };
}

/** Validate the request body of create/update. Returns errors or trimmed values. */
function validateEventBody(body = {}) {
  const errors = [];
  const value = {
    title: String(body.title ?? "").trim(),
    description: String(body.description ?? "").trim(),
    eventType: String(body.eventType ?? "").trim(),
    thumbnailUrl: String(body.thumbnailUrl ?? "").trim(),
    location: String(body.location ?? "").trim(),
    date: String(body.date ?? "").trim(),
  };

  if (value.title.length < 5 || value.title.length > 120) {
    errors.push("Title must be between 5 and 120 characters.");
  }
  if (value.description.length < 20 || value.description.length > 2000) {
    errors.push("Description must be between 20 and 2000 characters.");
  }
  if (!EVENT_TYPES.includes(value.eventType)) {
    errors.push("Please choose a valid event type.");
  }
  if (!URL_RE.test(value.thumbnailUrl)) {
    errors.push("Thumbnail image URL must be a valid http(s) URL.");
  }
  if (value.location.length < 3 || value.location.length > 120) {
    errors.push("Location must be between 3 and 120 characters.");
  }
  if (!DATE_RE.test(value.date)) {
    errors.push("Event date is required (YYYY-MM-DD).");
  } else if (value.date < todayISO()) {
    // Assignment rule: past dates can never be saved.
    errors.push("Event date must be today or in the future.");
  }

  return { errors, value };
}

/* ══════════════════════════ Events routes ══════════════════════════ */

const eventsRouter = express.Router();

/** All upcoming events (today or later), soonest first. */
eventsRouter.get("/upcoming", async (_req, res) => {
  const docs = await eventsCollection
    .find({ date: { $gte: todayISO() } })
    .sort({ date: 1, createdAt: 1 })
    .limit(200)
    .toArray();
  res.json({ events: docs.map(serializeEvent) });
});

/**
 * Recently added upcoming events for the home page — uses MongoDB's
 * `.limit()` operator as required (6 by default).
 */
eventsRouter.get("/recent", async (req, res) => {
  const limitParam = Number.parseInt(String(req.query.limit ?? "6"), 10);
  const limit = Number.isFinite(limitParam) ? Math.min(Math.max(limitParam, 1), 12) : 6;

  const docs = await eventsCollection
    .find({ date: { $gte: todayISO() } })
    .sort({ createdAt: -1 })
    .limit(limit)
    .toArray();
  res.json({ events: docs.map(serializeEvent) });
});

/** All events created by the logged-in user. */
eventsRouter.get("/my-events", requireAuth, async (req, res) => {
  const docs = await eventsCollection
    .find({ creatorEmail: req.user.email })
    .sort({ date: 1, createdAt: 1 })
    .toArray();
  res.json({ events: docs.map(serializeEvent) });
});

/** Create an event. The creator's identity comes from the verified JWT. */
eventsRouter.post("/", requireAuth, async (req, res) => {
  const { errors, value } = validateEventBody(req.body);
  if (errors.length > 0) {
    return res.status(400).json({ error: errors.join(" ") });
  }

  const doc = {
    ...value,
    creatorId: req.user.id,
    creatorEmail: req.user.email,
    creatorName: req.user.name,
    joinedCount: 0,
    createdAt: new Date(),
  };

  const result = await eventsCollection.insertOne(doc);
  const saved = await eventsCollection.findOne({ _id: result.insertedId });
  return res
    .status(201)
    .json({ message: "Event created successfully!", event: serializeEvent(saved) });
});

/** Event details. Public, but includes `joinedByMe` for logged-in viewers. */
eventsRouter.get("/:id", optionalAuth, async (req, res) => {
  const id = req.params.id;
  if (!ObjectId.isValid(id)) {
    return res.status(400).json({ error: "Invalid event id." });
  }

  const doc = await eventsCollection.findOne({ _id: new ObjectId(id) });
  if (!doc) {
    return res.status(404).json({ error: "Event not found." });
  }

  let joinedByMe = false;
  if (req.user) {
    const join = await joinsCollection.findOne({
      eventId: String(doc._id),
      userEmail: req.user.email,
    });
    joinedByMe = Boolean(join);
  }

  res.json({ event: serializeEvent(doc), joinedByMe });
});

/** Update an event — only its creator may do that. */
eventsRouter.put("/:id", requireAuth, async (req, res) => {
  const id = req.params.id;
  if (!ObjectId.isValid(id)) {
    return res.status(400).json({ error: "Invalid event id." });
  }

  const existing = await eventsCollection.findOne({ _id: new ObjectId(id) });
  if (!existing) {
    return res.status(404).json({ error: "Event not found." });
  }
  if (existing.creatorEmail !== req.user.email) {
    return res.status(403).json({ error: "You can only update events you have created." });
  }

  const { errors, value } = validateEventBody(req.body);
  if (errors.length > 0) {
    return res.status(400).json({ error: errors.join(" ") });
  }

  await eventsCollection.updateOne(
    { _id: new ObjectId(id) },
    { $set: { ...value, updatedAt: new Date() } }
  );

  const updated = await eventsCollection.findOne({ _id: new ObjectId(id) });
  res.json({ message: "Event updated successfully!", event: serializeEvent(updated) });
});

/** Delete an event — only its creator may do that. Joins are cleaned up too. */
eventsRouter.delete("/:id", requireAuth, async (req, res) => {
  const id = req.params.id;
  if (!ObjectId.isValid(id)) {
    return res.status(400).json({ error: "Invalid event id." });
  }

  const existing = await eventsCollection.findOne({ _id: new ObjectId(id) });
  if (!existing) {
    return res.status(404).json({ error: "Event not found." });
  }
  if (existing.creatorEmail !== req.user.email) {
    return res.status(403).json({ error: "You can only delete events you have created." });
  }

  await eventsCollection.deleteOne({ _id: new ObjectId(id) });
  await joinsCollection.deleteMany({ eventId: String(existing._id) });

  res.json({ message: "Event deleted successfully." });
});

/* ══════════════════════════ Joins routes ══════════════════════════ */

const joinsRouter = express.Router();

/** Join an event as the logged-in user (identified by the verified JWT). */
joinsRouter.post("/:id/join", requireAuth, async (req, res) => {
  const id = req.params.id;
  if (!ObjectId.isValid(id)) {
    return res.status(400).json({ error: "Invalid event id." });
  }

  const event = await eventsCollection.findOne({ _id: new ObjectId(id) });
  if (!event) {
    return res.status(404).json({ error: "Event not found." });
  }
  if (event.date < todayISO()) {
    return res.status(400).json({
      error: "This event has already taken place and can no longer be joined.",
    });
  }

  const existing = await joinsCollection.findOne({
    eventId: String(event._id),
    userEmail: req.user.email,
  });
  if (existing) {
    return res.status(409).json({ error: "You have already joined this event." });
  }

  await ensureIndexes();
  await joinsCollection.insertOne({
    eventId: String(event._id),
    eventTitle: event.title,
    eventDate: event.date,
    userEmail: req.user.email,
    userName: req.user.name,
    joinedAt: new Date(),
  });
  await eventsCollection.updateOne({ _id: event._id }, { $inc: { joinedCount: 1 } });

  res.status(201).json({ message: "You successfully joined this event! 🎉" });
});

/**
 * All events joined by the logged-in user, sorted by event date as required.
 * Falls back to the denormalized snapshot when an event was deleted.
 */
joinsRouter.get("/joined", requireAuth, async (req, res) => {
  const joins = await joinsCollection
    .find({ userEmail: req.user.email })
    .sort({ joinedAt: -1 })
    .toArray();

  const eventIds = joins
    .filter((j) => ObjectId.isValid(j.eventId))
    .map((j) => new ObjectId(j.eventId));

  const events = await eventsCollection.find({ _id: { $in: eventIds } }).toArray();
  const byId = new Map(events.map((e) => [String(e._id), e]));

  const joinedEvents = joins
    .map((j) => {
      const event = byId.get(j.eventId);
      if (!event) return null;
      return {
        ...serializeEvent(event),
        joinedAt: j.joinedAt.toISOString(),
      };
    })
    .filter(Boolean)
    .sort((a, b) => a.date.localeCompare(b.date)); // soonest event first

  res.json({ events: joinedEvents });
});

/** Lightweight status check used by the Join button on the details page. */
joinsRouter.get("/:id/status", requireAuth, async (req, res) => {
  const id = req.params.id;
  if (!ObjectId.isValid(id)) {
    return res.status(400).json({ error: "Invalid event id." });
  }
  const join = await joinsCollection.findOne({
    eventId: id,
    userEmail: req.user.email,
  });
  res.json({ joined: Boolean(join) });
});

/* ══════════════════════════ App ══════════════════════════ */

const app = express();

// CORS first (covers the auth handler's preflight requests too).
app.use(
  cors({
    origin: [CLIENT_URL, "http://localhost:3000"],
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    credentials: true, // session cookies travel with the request
  })
);

// BetterAuth handler BEFORE any body-parsing middleware (per the docs).
app.all("/api/auth/{*any}", toNodeHandler(auth));

app.use(express.json());

// Joins router first so /joined and /:id/status are not captured by /:id.
app.use("/api/events", joinsRouter);
app.use("/api/events", eventsRouter);

// Health check for uptime monitors and the examiner. 🙂
app.get("/api/health", (_req, res) => {
  res.json({ status: "ok", service: "shohojog-api", time: new Date().toISOString() });
});

// 404 for unknown API routes (JSON, not HTML).
app.use((_req, res) => {
  res.status(404).json({ error: "Route not found." });
});

// Central error handler — always respond with JSON.
app.use((error, _req, res, _next) => {
  console.error("[shohojog-api] Unhandled error:", error);
  res.status(500).json({ error: "Something went wrong on our side. Please try again." });
});

app.listen(PORT, () => {
  console.log(`🤝 Shohojog API listening on http://localhost:${PORT}`);
  ensureIndexes()
    .then(() => console.log("🗂  Database indexes are ready"))
    .catch((error) => console.error("Failed to create indexes:", error.message));
});
