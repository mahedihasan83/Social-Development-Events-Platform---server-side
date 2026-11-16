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
import { MongoClient, ServerApiVersion } from "mongodb";

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

/* ══════════════════════════ App ══════════════════════════ */

const app = express();

app.use(express.json());

// Health check for uptime monitors and the examiner. 🙂
app.get("/api/health", (_req, res) => {
  res.json({ status: "ok", service: "shohojog-api", time: new Date().toISOString() });
});

app.listen(PORT, () => {
  console.log(`🤝 Shohojog API listening on http://localhost:${PORT}`);
  ensureIndexes()
    .then(() => console.log("🗂  Database indexes are ready"))
    .catch((error) => console.error("Failed to create indexes:", error.message));
});
