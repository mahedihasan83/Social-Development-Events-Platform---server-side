# 🤝 Shohojog API — Social Development Events Platform (Server)

Express.js REST API for **Shohojog (সহযোগ)** — a community-driven platform where
anyone can create, join and track social service events in their local area —
winter clothes distributions, neighborhood cleanups, tree plantations, blood
drives and more.

Built with **Express 5, MongoDB (Atlas), BetterAuth (MongoDB adapter) and JWT**.

## ✨ Features

- 🔐 **Complete authentication** — email/password + Google social login via
  BetterAuth, with a server-enforced password policy (≥ 6 chars, uppercase +
  lowercase) and JWT plugin for token-based API access.
- 🛡️ **JWT-protected REST API** — protected endpoints verify the Bearer token
  against BetterAuth's JWKS endpoint (no database lookup), exactly like the
  BetterAuth docs describe.
- 🙋 **Events API** — create, read, update and delete social service events.
  Validation covers title, description, event type, thumbnail URL, location
  and a future-only date. Update/delete are restricted to the creator.
- 🧾 **Join system** — logged-in users join events; duplicate joins are
  prevented with a unique MongoDB index, and `joinedCount` is incremented
  atomically with `$inc`.
- 🗂️ **MongoDB indexes** — date, creator and join indexes are created
  idempotently on startup for fast queries.

## ⚙️ Getting started

```bash
npm install
cp .env.example .env    # add your MongoDB Atlas URI, secrets and Google creds
npm run dev             # → http://localhost:5000
```

## 🔑 Environment variables (`.env`)

| Variable | Description |
| --- | --- |
| `PORT` | Port the API listens on (default `5000`) |
| `MONGODB_URI` | MongoDB Atlas connection string |
| `MONGODB_DB` | Database name (default `shohojog`) |
| `BETTER_AUTH_SECRET` | Long random secret for BetterAuth |
| `SERVER_URL` | Public URL of this API (used for JWT issuer/JWKS) |
| `CLIENT_URL` | Frontend URL (used for CORS + trusted origins) |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | Google OAuth credentials (optional) |

## 🛣️ API endpoints

### Auth (BetterAuth) — `/api/auth/*`
| Method | Path | Description |
| --- | --- | --- |
| POST | `/sign-up/email` | Register (password policy enforced) |
| POST | `/sign-in/email` | Login |
| GET | `/token` | Get a JWT for the current session |
| GET | `/jwks` | Public keys used to verify JWTs |
| GET | `/callback/google` | Google OAuth flow |

### Events — `/api/events`
| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| GET | `/upcoming` | Public | All upcoming events, soonest first |
| GET | `/recent?limit=6` | Public | Latest upcoming events (MongoDB `.limit()`) |
| GET | `/:id` | Public | Event details (+ `joinedByMe` when logged in) |
| POST | `/` | JWT | Create an event (creator email saved) |
| PUT | `/:id` | JWT | Update — creator only |
| DELETE | `/:id` | JWT | Delete — creator only (joins cleaned up) |
| GET | `/my-events` | JWT | Events created by the logged-in user |

### Joins — `/api/events`
| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| POST | `/:id/join` | JWT | Join an event (once per user, future events only) |
| GET | `/joined` | JWT | Joined events, sorted by event date |
| GET | `/:id/status` | JWT | Has the logged-in user joined this event? |

### Utility
| Method | Path | Description |
| --- | --- | --- |
| GET | `/api/health` | Health check for uptime monitors |

## 🚀 Deployment

Deploy on **Render** (or any Node host): start command `npm start`, and set all
environment variables from `.env.example` — with `SERVER_URL` = the deployed
API URL and `CLIENT_URL` = the deployed frontend URL.
