import "dotenv/config";
import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import cookieParser from "cookie-parser";
import crypto from "node:crypto";

const app = express();
const PORT = process.env.PORT || 5000;
const SERVER_URL = process.env.SERVER_URL || `http://localhost:${PORT}`;
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "7d";


if (process.env.NODE_ENV === "production") app.set("trust proxy", 1);


const isWeakSecret = (value) => {
  if (!value || value.length < 32) return true; 
  return /^(change[_-]?me|your[_-]|secret|password|jwt[_-]?secret|12345)/i.test(value.trim());
};

if (!JWT_SECRET) {
  console.error(
    "❌ FATAL: JWT_SECRET is missing! Add JWT_SECRET=your_random_string in your .env file."
  );
  process.exit(1);
}
if (isWeakSecret(JWT_SECRET)) {
  console.error(
    "❌ FATAL: JWT_SECRET is too weak (must be at least 32 characters of random text).\n" +
      "   Generate one with:  node -e \"console.log(require('crypto').randomBytes(48).toString('hex'))\""
  );
  process.exit(1);
}


const allowedOrigins = (process.env.CLIENT_URL || "")
  .split(",")
  .map((o) => o.trim())
  .filter(Boolean);

if (allowedOrigins.length === 0) {
  allowedOrigins.push("http://localhost:3000");
  console.warn(
    "⚠️  CLIENT_URL is not set — CORS restricted to http://localhost:3000. " +
      "Add CLIENT_URL=... to .env before deploying."
  );
}

app.use(cors({
    origin: allowedOrigins, 
    credentials: true, 
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    maxAge: 600,
  })
);
app.use(cookieParser());
app.use(express.json({ limit: "1mb" })); 


mongoose
  .connect(process.env.MONGODB_URI, {
    serverSelectionTimeoutMS: 10000, 
  })
  .then(() => console.log("✅ MongoDB connected successfully"))
  .catch((err) => {
    console.error("❌ MongoDB connection failed:", err.message);
    console.error(
      "👉 Check MONGODB_URI in .env and make sure your IP is whitelisted in Atlas (Network Access)."
    );
    process.exit(1);
  });

const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    photoURL: { type: String, required: true, trim: true },
    password: { type: String, required: true, select: false },
  },
  { timestamps: true }
);
const User = mongoose.model("User", userSchema);


const eventSchema = new mongoose.Schema(
  {
    title: { type: String, required: true, trim: true },
    description: { type: String, required: true, trim: true },
    eventType: { type: String, required: true, trim: true }, 
    thumbnailUrl: { type: String, required: true, trim: true }, 
    location: { type: String, required: true, trim: true }, 
    date: { type: String, required: true }, 
    creatorId: { type: String, required: true, index: true },
    creatorEmail: { type: String, required: true, lowercase: true, trim: true, index: true },
    creatorName: { type: String, required: true, trim: true },
    joinedCount: { type: Number, default: 0 }, 
  },
  { timestamps: true }
);
const Event = mongoose.model("Event", eventSchema);


const joinSchema = new mongoose.Schema(
  {
    eventId: { type: mongoose.Schema.Types.ObjectId, ref: "Event", required: true, index: true },
    userEmail: { type: String, required: true, lowercase: true, trim: true, index: true },
    
    eventTitle: { type: String, required: true },
    eventThumbnail: { type: String, required: true },
    eventLocation: { type: String, required: true },
    eventDate: { type: String, required: true }, 
  },
  { timestamps: true }
);

joinSchema.index({ eventId: 1, userEmail: 1 }, { unique: true });
const Join = mongoose.model("Join", joinSchema);


const SESSION_COOKIE_NAME = "better-auth.session_token";
const isProd = process.env.NODE_ENV === "production";

function setAuthCookie(res, token) {
  res.cookie(SESSION_COOKIE_NAME, token, {
    httpOnly: true,
    secure: isProd, 
    sameSite: isProd ? "none" : "lax", 
    path: "/",
    maxAge: 7 * 24 * 60 * 60 * 1000, 
  });
}

function clearAuthCookie(res) {
  res.clearCookie(SESSION_COOKIE_NAME, {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? "none" : "lax",
    path: "/",
  });
}


const JWT_ALGORITHMS = ["HS256"];

function signToken(user) {
  return jwt.sign(
    { id: String(user._id), email: user.email, name: user.name, photoURL: user.photoURL },
    JWT_SECRET,
    { algorithm: "HS256", expiresIn: JWT_EXPIRES_IN }
  );
}


function verifyJwt(token) {
  return jwt.verify(token, JWT_SECRET, { algorithms: JWT_ALGORITHMS });
}


function unusablePassword() {
  return crypto.randomBytes(32).toString("hex");
}



function signState(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = crypto.createHmac("sha256", JWT_SECRET).update(body).digest("base64url");
  return `${body}.${sig}`;
}

function readState(state) {
  const raw = String(state || "");
  const dot = raw.lastIndexOf(".");
  if (dot === -1) return null;

  const body = raw.slice(0, dot);
  const given = Buffer.from(raw.slice(dot + 1));
  const expected = Buffer.from(
    crypto.createHmac("sha256", JWT_SECRET).update(body).digest("base64url")
  );

  if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) return null;

  try {
    return JSON.parse(Buffer.from(body, "base64url").toString());
  } catch {
    return null;
  }
}


function isTrustedClientUrl(value) {
  const raw = String(value || "");
  if (!/^https?:\/\//i.test(raw)) return false;
  let url;
  try {
    url = new URL(raw);
  } catch {
    return false;
  }
  return allowedOrigins.some((origin) => {
    try {
      return new URL(origin).origin === url.origin;
    } catch {
      return false;
    }
  });
}

const defaultClientUrl = () => process.env.CLIENT_URL || allowedOrigins[0] || "/";

function appendQuery(url, params) {
  const sep = String(url).includes("?") ? "&" : "?";
  return `${url}${sep}${new URLSearchParams(params).toString()}`;
}



const rateBuckets = new Map();
const AUTH_MAX_ATTEMPTS = Number(process.env.AUTH_RATE_LIMIT || 20);
const AUTH_WINDOW_MS = 15 * 60 * 1000; 

function rateLimit(name, max = AUTH_MAX_ATTEMPTS, windowMs = AUTH_WINDOW_MS) {
  return (req, res, next) => {
    const now = Date.now();
    const id = `${name}:${req.ip}`;

    let bucket = rateBuckets.get(id);
    if (!bucket || now - bucket.start >= windowMs) {
      bucket = { start: now, count: 0 };
      rateBuckets.set(id, bucket);
    }
    bucket.count += 1;


    if (rateBuckets.size > 5000) {
      for (const [key, value] of rateBuckets) {
        if (now - value.start >= windowMs) rateBuckets.delete(key);
      }
    }

    if (bucket.count > max) {
      const retryAfter = Math.max(1, Math.ceil((bucket.start + windowMs - now) / 1000));
      res.set("Retry-After", String(retryAfter));
      const message = "Too many attempts. Please wait a few minutes and try again.";
      return res.status(429).json({ success: false, error: message, message });
    }
    next();
  };
}


async function registerUser({ name, email, photoURL, password }) {
  const errors = [];
  if (!name || !String(name).trim()) errors.push("Name is required");
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) errors.push("Valid email is required");
  if (!photoURL || !/^https?:\/\/.+/i.test(photoURL)) errors.push("Valid photo URL is required");
  if (!password) errors.push("Password is required");
  else {
    if (String(password).length < 6) errors.push("Password must be at least 6 characters");
    if (!/[A-Z]/.test(password)) errors.push("Password must contain an uppercase letter");
    if (!/[a-z]/.test(password)) errors.push("Password must contain a lowercase letter");
  }
  if (errors.length) throw new ApiError(400, errors.join(" | "));

  const normalizedEmail = String(email).toLowerCase().trim();
  const existing = await User.findOne({ email: normalizedEmail });
  if (existing) throw new ApiError(409, "An account with this email already exists");

  const user = await User.create({
    name: String(name).trim(),
    email: normalizedEmail,
    photoURL,
    password: await bcrypt.hash(String(password), 10),
  });
  return { user, token: signToken(user) };
}


function toAuthUser(user) {
  return {
    id: String(user._id),
    name: user.name,
    email: user.email,
    image: user.photoURL,
    photoURL: user.photoURL,
    emailVerified: false,
    createdAt: user.createdAt || new Date(),
  };
}

async function loginUser({ email, password }) {
  if (!email || !password) throw new ApiError(400, "Email and password are required");
  const user = await User.findOne({ email: String(email).toLowerCase().trim() }).select("+password");
  if (!user) throw new ApiError(401, "Invalid email or password");
  const isMatch = await bcrypt.compare(String(password), user.password);
  if (!isMatch) throw new ApiError(401, "Invalid email or password");
  return { user, token: signToken(user) };
}



function verifyToken(req, res, next) {
  let token = null;

  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith("Bearer ")) {
    token = authHeader.split(" ")[1];
  } else if (req.cookies && req.cookies[SESSION_COOKIE_NAME]) {
    token = req.cookies[SESSION_COOKIE_NAME];
  }

  if (!token) {
    return res.status(401).json({
      success: false,
      error: "Unauthorized access. Please log in.",
      message: "Unauthorized access. Please log in.",
    });
  }

  try {
    req.decoded = verifyJwt(token); 
    next();
  } catch {
    return res.status(401).json({
      success: false,
      error: "Invalid or expired token. Please log in again.",
      message: "Invalid or expired token. Please log in again.",
    });
  }
}

const asyncHandler = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.statusCode = status;
  }
}


function todayISO() {
  return new Date().toISOString().slice(0, 10);
}


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


function normalizeEventBody(body = {}) {
  const out = {};
  if (body.title !== undefined) out.title = String(body.title).trim();
  if (body.description !== undefined) out.description = String(body.description).trim();
  if (body.eventType !== undefined) out.eventType = String(body.eventType).trim();
  if (body.thumbnailUrl !== undefined || body.thumbnail !== undefined) {
    out.thumbnailUrl = String(body.thumbnailUrl ?? body.thumbnail).trim();
  }
  if (body.location !== undefined) out.location = String(body.location).trim();
  if (body.date !== undefined || body.eventDate !== undefined) {
    
    out.date = String(body.date ?? body.eventDate).trim().slice(0, 10);
  }
  return out;
}


function hasDateField(body = {}) {
  return body.date !== undefined || body.eventDate !== undefined;
}


function validateEventPayload(value, options = {}) {
  const errors = [];
  const title = String(value.title ?? "");
  const description = String(value.description ?? "");
  const eventType = String(value.eventType ?? "");
  const thumbnailUrl = String(value.thumbnailUrl ?? "");
  const location = String(value.location ?? "");
  const date = String(value.date ?? "");

  if (title.length < 5 || title.length > 120) {
    errors.push("Title must be between 5 and 120 characters.");
  }
  if (description.length < 20 || description.length > 2000) {
    errors.push("Description must be between 20 and 2000 characters.");
  }
  if (!EVENT_TYPES.includes(eventType)) {
    errors.push("Please choose a valid event type.");
  }
  if (!URL_RE.test(thumbnailUrl)) {
    errors.push("Thumbnail image URL must be a valid http(s) URL.");
  }
  if (location.length < 3 || location.length > 120) {
    errors.push("Location must be between 3 and 120 characters.");
  }
  if (!options.skipDate) {
    if (!DATE_RE.test(date)) {
      errors.push("Event date is required (YYYY-MM-DD).");
    } else if (date < todayISO()) {
     
      errors.push("Event date must be today or in the future.");
    }
  }
  return errors;
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
    creatorId: doc.creatorId ?? doc.creatorEmail ?? "",
    creatorEmail: doc.creatorEmail ?? "",
    creatorName: doc.creatorName ?? "",
    joinedCount: doc.joinedCount ?? 0,
    createdAt: doc.createdAt ? new Date(doc.createdAt).toISOString() : null,
  };
}


function optionalAuth(req, _res, next) {
  const header = req.headers.authorization;
  const token =
    (header && header.startsWith("Bearer ") ? header.split(" ")[1] : null) ||
    req.cookies?.[SESSION_COOKIE_NAME] ||
    null;
  if (!token) {
    req.decoded = null;
    return next();
  }
  try {
    req.decoded = verifyJwt(token);
  } catch {
    req.decoded = null;
  }
  next();
}


app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "Welcome to the Social Development Events Platform API 🌱",
    docs: "See index.js top comment for the full API guide.",
  });
});


app.get("/api/health", (req, res) => {
  const dbStates = {
    0: "disconnected ❌ (.env এর MONGODB_URI check করো)",
    1: "connected ✅",
    2: "connecting... (একটু অপেক্ষা করো)",
    3: "disconnecting...",
  };
  const isPlaceholder = (v) => !v || /your_|here|change_me/i.test(v);
  const googleOk =
    !isPlaceholder(process.env.GOOGLE_CLIENT_ID) &&
    !isPlaceholder(process.env.GOOGLE_CLIENT_SECRET);

  res.json({
    server: "running ✅",
    database: dbStates[mongoose.connection.readyState] || "unknown",
    googleLogin: googleOk
      ? "configured ✅"
      : "NOT configured ❌ — .env এ আসল GOOGLE_CLIENT_ID ও GOOGLE_CLIENT_SECRET বসাও (placeholder এখনো আছে)",
    jwtSecret: isPlaceholder(process.env.JWT_SECRET)
      ? "placeholder ❌ — .env এ আসল JWT_SECRET বসাও"
      : "set ✅",
    tip: "Registration failed দেখালে browser DevTools → Network এ 'sign-up' বা 'register' request এর Response দেখো — আসল error message সেখানে থাকে।",
  });
});


app.post(
  "/api/auth/register",
  rateLimit("register"),
  asyncHandler(async (req, res) => {
    const { name, email, photoURL, password } = req.body || {};

    const { user, token } = await registerUser({ name, email, photoURL, password });
    setAuthCookie(res, token);

    res.status(201).json({
      success: true,
      message: "Registration successful",
      token,
      user: { name: user.name, email: user.email, photoURL: user.photoURL },
    });
  })
);


app.post(
  "/api/auth/login",
  rateLimit("login"),
  asyncHandler(async (req, res) => {
    const { email, password } = req.body || {};

    const { user, token } = await loginUser({ email, password });
    setAuthCookie(res, token);

    res.json({
      success: true,
      message: "Login successful",
      token,
      user: { name: user.name, email: user.email, photoURL: user.photoURL },
    });
  })
);

app.post(
  "/api/auth/google",
  rateLimit("google"),
  asyncHandler(async (req, res) => {
    const body = req.body || {};
    const idToken = body.id_token || body.credential || body.token;

    if (!idToken) {
      throw new ApiError(
        400,
        "Google ID token is required (id_token). Send the token from Google's Sign-In SDK, or use POST /api/auth/sign-in/social."
      );
    }
    if (!process.env.GOOGLE_CLIENT_ID) {
      throw new ApiError(500, "Google login is not configured — add GOOGLE_CLIENT_ID in .env");
    }


    const verifyRes = await fetch(
      `https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(String(idToken))}`
    );
    if (!verifyRes.ok) throw new ApiError(401, "Invalid or expired Google ID token");
    const claims = await verifyRes.json();

    if (claims.aud !== process.env.GOOGLE_CLIENT_ID) {
      throw new ApiError(401, "Google ID token was issued for a different application");
    }
    
    if (String(claims.email_verified) !== "true") {
      throw new ApiError(401, "Google account email is not verified");
    }
    if (!claims.email) throw new ApiError(401, "Google ID token contains no email");

    const normalizedEmail = String(claims.email).toLowerCase().trim();
    let user = await User.findOne({ email: normalizedEmail });

    if (!user) {
   
      user = await User.create({
        name: String(claims.name || "Google User").trim(),
        email: normalizedEmail,
        photoURL: claims.picture || "https://i.ibb.co/default-avatar.png",
        password: await bcrypt.hash(unusablePassword(), 10),
      });
    }

    const token = signToken(user);
    setAuthCookie(res, token);
    res.json({
      success: true,
      message: "Google sign-in successful",
      token,
      user: { name: user.name, email: user.email, photoURL: user.photoURL },
    });
  })
);


app.post(
  "/api/auth/sign-in/social",
  asyncHandler(async (req, res) => {
    const { provider, callbackURL } = req.body || {};

    if (provider !== "google") {
      throw new ApiError(400, 'Only provider: "google" is supported on this server');
    }
    if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
      throw new ApiError(
        500,
        "Google login is not configured — add GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in the server .env"
      );
    }

    const redirectURI = `${SERVER_URL}/api/auth/callback/google`;
   
    const state = signState({ callbackURL: callbackURL || defaultClientUrl() });

    const authUrl =
      "https://accounts.google.com/o/oauth2/v2/auth?" +
      new URLSearchParams({
        client_id: process.env.GOOGLE_CLIENT_ID,
        redirect_uri: redirectURI,
        response_type: "code",
        scope: "openid email profile",
        access_type: "online",
        prompt: "select_account",
        state,
      }).toString();

  
    res.json({ redirect: true, url: authUrl });
  })
);


app.get(
  "/api/auth/callback/google",
  asyncHandler(async (req, res) => {
    const { code, state } = req.query;

    let callbackURL = defaultClientUrl();
    if (state) {
      const parsed = readState(state);
      if (!parsed) {
        return res.redirect(appendQuery(defaultClientUrl(), { error: "invalid_state" }));
      }
      if (parsed.callbackURL) callbackURL = parsed.callbackURL;
    }
    const safeCallback = isTrustedClientUrl(callbackURL) ? callbackURL : defaultClientUrl();

    if (!code) {
      return res.redirect(appendQuery(safeCallback, { error: "google_login_cancelled" }));
    }
    if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
      return res.redirect(appendQuery(safeCallback, { error: "google_not_configured" }));
    }

    const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        code: String(code),
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        redirect_uri: `${SERVER_URL}/api/auth/callback/google`,
        grant_type: "authorization_code",
      }).toString(),
    });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) {
      return res.redirect(appendQuery(safeCallback, { error: "google_token_failed" }));
    }

 
    const profileRes = await fetch("https://openidconnect.googleapis.com/v1/userinfo", {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    const profile = await profileRes.json();
    if (!profile.email) {
      return res.redirect(appendQuery(safeCallback, { error: "google_profile_failed" }));
    }

    const email = String(profile.email).toLowerCase();
    let user = await User.findOne({ email });
    if (!user) {
      user = await User.create({
        name: profile.name || "Google User",
        email,
        photoURL: profile.picture || "https://i.ibb.co/default-avatar.png",
        password: await bcrypt.hash(unusablePassword(), 10), 
      });
    }


    const token = signToken(user);
    setAuthCookie(res, token);

    res.redirect(safeCallback);
  })
);

app.post(
  "/api/auth/sign-up/email",
  rateLimit("register"),
  asyncHandler(async (req, res) => {
    const body = req.body || {};
    const { name, email, password } = body;

   
    const photoURL = body.image || body.photoURL || "https://i.ibb.co/default-avatar.png";

    const { user, token } = await registerUser({ name, email, photoURL, password });
    setAuthCookie(res, token);

    res.status(201).json({
      success: true,
      message: "Registration successful",
      token,
      user: toAuthUser(user),
    });
  })
);


app.post(
  "/api/auth/sign-in/email",
  rateLimit("login"),
  asyncHandler(async (req, res) => {
    const { email, password } = req.body || {};

    const { user, token } = await loginUser({ email, password });
    setAuthCookie(res, token);

    res.json({
      success: true,
      message: "Login successful",
      token,
      user: toAuthUser(user),
    });
  })
);


app.get(
  "/api/auth/get-session",
  asyncHandler(async (req, res) => {
    
    const token = req.cookies?.[SESSION_COOKIE_NAME] || 
      (req.headers.authorization?.startsWith("Bearer ") ? req.headers.authorization.split(" ")[1] : null);

    if (!token) return res.status(200).json(null); 

    try {
      const decoded = verifyJwt(token);
      const user = await User.findOne({ email: decoded.email }).select("-password");
      if (!user) return res.status(200).json(null);
      res.json({ session: { token, user: decoded }, user: toAuthUser(user) });
    } catch {
      res.status(200).json(null);
    }
  })
);


app.post("/api/auth/sign-out", (req, res) => {
  clearAuthCookie(res);
  res.json({ success: true, message: "Signed out" });
});


app.get("/api/auth/token", (req, res) => {
  const header = req.headers.authorization;
  const token =
    (header && header.startsWith("Bearer ") ? header.split(" ")[1] : null) ||
    req.cookies?.[SESSION_COOKIE_NAME] ||
    null;

  if (!token) {
    return res.status(401).json({
      success: false,
      error: "Not signed in — please log in first.",
      message: "Not signed in — please log in first.",
    });
  }

  try {
    verifyJwt(token); 
  } catch {
    return res.status(401).json({
      success: false,
      error: "Your session has expired. Please log in again.",
      message: "Your session has expired. Please log in again.",
    });
  }

  res.json({ token });
});

app.use("/api/auth", (req, res) => {
  res.status(404).json({
    success: false,
    message: `Auth route "${req.method} ${req.originalUrl}" does not exist on this server. Use: /api/auth/register, /api/auth/login, /api/auth/sign-up/email, /api/auth/sign-in/email, or /api/auth/sign-in/social (Google).`,
  });
});


const upcomingHandler = asyncHandler(async (req, res) => {
  const limit = parseInt(req.query.limit, 10);

 
  let query = Event.find({ date: { $gte: todayISO() } }).sort({ date: 1, createdAt: 1 });
  if (!isNaN(limit) && limit > 0) query = query.limit(limit);

  const events = await query;
  res.json({ events: events.map(serializeEvent) });
});

app.get("/api/events/upcoming", upcomingHandler);
app.get("/api/events", upcomingHandler);


app.get(
  "/api/events/my-events",
  verifyToken,
  asyncHandler(async (req, res) => {
    const events = await Event.find({ creatorEmail: req.decoded.email }).sort({
      date: 1,
      createdAt: 1,
    });
    res.json({ events: events.map(serializeEvent) });
  })
);


app.get(
  "/api/events/recent",
  asyncHandler(async (req, res) => {
    const limit = parseInt(req.query.limit, 10) || 6;

    const events = await Event.find({ date: { $gte: todayISO() } })
      .sort({ createdAt: -1 })
      .limit(limit); 

    res.json({ events: events.map(serializeEvent) });
  })
);


app.get(
  "/api/events/joined",
  verifyToken,
  asyncHandler(async (req, res) => {
    const joins = await Join.find({ userEmail: req.decoded.email }).sort({
      eventDate: 1,
      createdAt: 1,
    });

    const ids = joins.map((join) => join.eventId);
    const docs = ids.length ? await Event.find({ _id: { $in: ids } }) : [];
    const byId = new Map(docs.map((doc) => [String(doc._id), doc]));

    const events = [];
    for (const join of joins) {
      const doc = byId.get(String(join.eventId));
      if (!doc) continue; 
      events.push({
        ...serializeEvent(doc),
        joinedAt: join.createdAt ? new Date(join.createdAt).toISOString() : null,
      });
    }
    res.json({ events });
  })
);

app.post(
  "/api/events/:id/join",
  verifyToken,
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    if (!mongoose.isValidObjectId(id)) throw new ApiError(404, "Event not found");

    const event = await Event.findById(id);
    if (!event) throw new ApiError(404, "Event not found");
    if (event.date < todayISO()) {
      throw new ApiError(400, "This event has already taken place — cannot join");
    }

    const alreadyJoined = await Join.findOne({
      eventId: event._id,
      userEmail: req.decoded.email,
    });
    if (alreadyJoined) throw new ApiError(409, "You have already joined this event");

    await Join.create({
      eventId: event._id,
      userEmail: req.decoded.email,
      eventTitle: event.title,
      eventThumbnail: event.thumbnailUrl,
      eventLocation: event.location,
      eventDate: event.date,
    });
   
    await Event.updateOne({ _id: event._id }, { $inc: { joinedCount: 1 } });

    res.status(201).json({
      success: true,
      message: `You joined "${event.title}" successfully 🎉`,
    });
  })
);

app.get(
  "/api/events/:id/status",
  verifyToken,
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    if (!mongoose.isValidObjectId(id)) throw new ApiError(404, "Event not found");

    const joined = await Join.exists({ eventId: id, userEmail: req.decoded.email });
    res.json({ joined: Boolean(joined) });
  })
);



app.get(
  "/api/events/:id",
  optionalAuth,
  asyncHandler(async (req, res) => {
    const { id } = req.params;

    
    if (!mongoose.isValidObjectId(id)) throw new ApiError(404, "Event not found");

    const event = await Event.findById(id);
    if (!event) throw new ApiError(404, "Event not found");

    let joinedByMe = false;
    if (req.decoded) {
      const join = await Join.exists({ eventId: event._id, userEmail: req.decoded.email });
      joinedByMe = Boolean(join);
    }

    res.json({ event: serializeEvent(event), joinedByMe });
  })
);


app.post(
  "/api/events",
  verifyToken,
  asyncHandler(async (req, res) => {
    const value = normalizeEventBody(req.body);

    const errors = validateEventPayload(value);
    if (errors.length) throw new ApiError(400, errors.join(" "));

    const event = await Event.create({
      ...value,
   
      creatorId: req.decoded.id || req.decoded.email,
      creatorEmail: req.decoded.email,
      creatorName: req.decoded.name || "Anonymous",
      joinedCount: 0,
    });

    res.status(201).json({
      success: true,
      message: "Event created successfully",
      event: serializeEvent(event),
    });
  })
);


app.put(
  "/api/events/:id",
  verifyToken,
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    if (!mongoose.isValidObjectId(id)) throw new ApiError(404, "Event not found");

    const event = await Event.findById(id);
    if (!event) throw new ApiError(404, "Event not found");


    if (event.creatorEmail !== req.decoded.email) {
      throw new ApiError(403, "Forbidden — you can only update your own events");
    }

    const body = req.body || {};
    const patch = normalizeEventBody(body);
    if (Object.keys(patch).length === 0) throw new ApiError(400, "No valid fields to update");

   
    const value = { ...normalizeEventBody(event.toObject()), ...patch };

    const errors = validateEventPayload(value, { skipDate: !hasDateField(body) });
    if (errors.length) throw new ApiError(400, errors.join(" "));

    const updated = await Event.findByIdAndUpdate(id, value, { new: true });
    res.json({
      success: true,
      message: "Event updated successfully",
      event: serializeEvent(updated),
    });
  })
);


app.delete(
  "/api/events/:id",
  verifyToken,
  asyncHandler(async (req, res) => {
    const event = await Event.findById(req.params.id);
    if (!event) throw new ApiError(404, "Event not found");

    // ownership check — users can only delete THEIR OWN events
    if (event.creatorEmail !== req.decoded.email) {
      throw new ApiError(403, "Forbidden — you can only delete your own events");
    }

    await Join.deleteMany({ eventId: event._id });
    await event.deleteOne();

    res.json({ success: true, message: "Event deleted successfully" });
  })
);


app.post(
  "/api/joins",
  verifyToken,
  asyncHandler(async (req, res) => {
    const { eventId } = req.body || {};
    if (!eventId) throw new ApiError(400, "eventId is required");

    const event = await Event.findById(eventId);
    if (!event) throw new ApiError(404, "Event not found");

    if (event.date < todayISO()) {
      throw new ApiError(400, "This event has already taken place — cannot join");
    }

    const alreadyJoined = await Join.findOne({
      eventId: event._id,
      userEmail: req.decoded.email,
    });
    if (alreadyJoined) throw new ApiError(409, "You have already joined this event");

    await Join.create({
      eventId: event._id,
      userEmail: req.decoded.email,
      eventTitle: event.title,
      eventThumbnail: event.thumbnailUrl,
      eventLocation: event.location,
      eventDate: event.date,
    });
    await Event.updateOne({ _id: event._id }, { $inc: { joinedCount: 1 } });

    res.status(201).json({ success: true, message: `You joined "${event.title}" successfully 🎉` });
  })
);


app.get(
  "/api/joins/my",
  verifyToken,
  asyncHandler(async (req, res) => {
    const joined = await Join.find({ userEmail: req.decoded.email }).sort({ eventDate: 1 });
    res.json({ success: true, data: joined });
  })
);

app.get(
  "/api/joins/status/:eventId",
  verifyToken,
  asyncHandler(async (req, res) => {
    const joined = await Join.exists({
      eventId: req.params.eventId,
      userEmail: req.decoded.email,
    });
    res.json({ success: true, joined: Boolean(joined) });
  })
);

app.get(
  "/api/users/me",
  verifyToken,
  asyncHandler(async (req, res) => {
    const user = await User.findOne({ email: req.decoded.email }).select("-password");
    if (!user) throw new ApiError(404, "User not found");
    res.json({ success: true, data: user });
  })
);


app.patch(
  "/api/users/me",
  verifyToken,
  asyncHandler(async (req, res) => {
    const { name, photoURL } = req.body || {};
    const updates = {};
    if (name !== undefined) {
      if (!String(name).trim()) throw new ApiError(400, "Name cannot be empty");
      updates.name = String(name).trim();
    }
    if (photoURL !== undefined) {
      if (!/^https?:\/\/.+/i.test(photoURL)) throw new ApiError(400, "Photo URL must be a valid URL");
      updates.photoURL = photoURL.trim();
    }
    if (Object.keys(updates).length === 0)
      throw new ApiError(400, "Provide at least one field (name or photoURL) to update");

    const user = await User.findOneAndUpdate({ email: req.decoded.email }, updates, {
      new: true,
      select: "-password",
    });
    if (!user) throw new ApiError(404, "User not found");
    res.json({ success: true, message: "Profile updated successfully", data: user });
  })
);


app.use((req, res) => {
  res
    .status(404)
    .json({ success: false, message: `Route not found: ${req.method} ${req.originalUrl}` });
});


app.use((err, req, res, next) => {
  if (err?.type === "entity.parse.failed") {
    return res
      .status(400)
      .json({ success: false, error: "Invalid JSON in request body", message: "Invalid JSON in request body" });
  }
  console.error("❌ Server error:", err.message);
  const message = err.statusCode ? err.message : "Something went wrong on the server";

  res.status(err.statusCode || 500).json({ success: false, error: message, message });
});

mongoose.connection.once("open", () => {
  app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    console.log(`   → Deployed? Use your Render/Railway URL as NEXT_PUBLIC_API_URL on the client.`);
  });
});
