import "dotenv/config";
import express from "express";
import axios from "axios";
import crypto from "crypto";
import { fileURLToPath } from "url";
import { dirname, join } from "path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

const BASE_API  = "https://api.kordis.fr";
const AUTH_URL  = "https://authentication.kordis.fr/oauth/authorize";
const BASE_AUTH = "https://authentication.kordis.fr";
const UA        = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36";
const COOKIE    = "mgz_session";
const ALGO      = "aes-256-gcm";

// --- Chiffrement du cookie de session ---
function getKey() {
  return crypto.scryptSync(process.env.APP_SECRET, "mygez-salt", 32);
}

function encrypt(text) {
  const iv  = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGO, getKey(), iv);
  const enc = Buffer.concat([cipher.update(text, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]).toString("base64url");
}

function decrypt(data) {
  try {
    const buf = Buffer.from(data, "base64url");
    const iv  = buf.subarray(0, 12);
    const tag = buf.subarray(12, 28);
    const enc = buf.subarray(28);
    const decipher = crypto.createDecipheriv(ALGO, getKey(), iv);
    decipher.setAuthTag(tag);
    return decipher.update(enc).toString("utf8") + decipher.final("utf8");
  } catch { return null; }
}

function parseCookies(req) {
  return Object.fromEntries(
    (req.headers.cookie || "").split(";")
      .map(c => c.trim().split("="))
      .filter(p => p.length === 2)
      .map(([k, v]) => [k.trim(), decodeURIComponent(v.trim())])
  );
}

function getSession(req) {
  const raw = parseCookies(req)[COOKIE];
  if (!raw) return null;
  try {
    const session = JSON.parse(decrypt(raw));
    if (!session || Date.now() > session.expiry) return null;
    return session;
  } catch { return null; }
}

function setSessionCookie(res, token, expiry) {
  const payload = JSON.stringify({ token, expiry });
  const secure  = process.env.NODE_ENV === "production" ? "; Secure" : "";
  const maxAge  = Math.floor((expiry - Date.now()) / 1000);
  res.setHeader("Set-Cookie", `${COOKIE}=${encrypt(payload)}; HttpOnly${secure}; SameSite=Strict; Path=/; Max-Age=${maxAge}`);
}

// --- Login routes (publiques) ---
app.get("/login", (req, res) => res.sendFile(join(__dirname, "login.html")));

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.redirect("/login?error=1");
  try {
    const { token, expiry } = await getTokenForUser(username, password);
    setSessionCookie(res, token, expiry);
    res.redirect("/");
  } catch {
    res.redirect("/login?error=1");
  }
});

app.get("/logout", (req, res) => {
  res.setHeader("Set-Cookie", `${COOKIE}=; HttpOnly; Path=/; Max-Age=0`);
  res.redirect("/login");
});

// --- Auth middleware ---
app.use((req, res, next) => {
  const session = getSession(req);
  if (session) { req.mygesToken = session.token; return next(); }
  if (req.path.startsWith("/api/")) return res.status(401).json({ error: "Non authentifié" });
  res.redirect("/login");
});

// --- Fichiers statiques protégés ---
app.use(express.static("public"));

// --- MyGES Auth (par user) ---
async function getTokenForUser(username, password) {
  const jar = {};
  const saveCookies = (headers) => {
    for (const c of [headers["set-cookie"] || []].flat()) {
      const [pair] = c.split(";");
      const eq = pair.indexOf("=");
      if (eq > 0) jar[pair.slice(0, eq).trim()] = pair.slice(eq + 1).trim();
    }
  };
  const cookieHeader = () => Object.entries(jar).map(([k, v]) => `${k}=${v}`).join("; ");

  // 1. GET page de login
  let currentUrl = `${AUTH_URL}?response_type=token&client_id=skolae-app`;
  let loginPageData = "";
  for (let i = 0; i < 6; i++) {
    const r = await axios.get(currentUrl, {
      headers: { Cookie: cookieHeader(), "User-Agent": UA },
      maxRedirects: 0,
      validateStatus: (s) => s >= 200 && s < 400,
    });
    saveCookies(r.headers);
    if (r.headers.location) {
      currentUrl = new URL(r.headers.location, BASE_AUTH).href;
    } else {
      loginPageData = r.data;
      break;
    }
  }

  // 2. POST credentials
  const actionMatch = loginPageData.match(/action="([^"]+)"/);
  const actionUrl   = new URL(actionMatch?.[1]?.replace(/&amp;/g, "&") ?? "/login", BASE_AUTH);
  if (!actionUrl.searchParams.has("client_id")) {
    actionUrl.searchParams.set("response_type", "token");
    actionUrl.searchParams.set("client_id", "skolae-app");
  }

  const postRes = await axios.post(
    actionUrl.href,
    new URLSearchParams({ username, password }).toString(),
    {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Cookie: cookieHeader(),
        "User-Agent": UA,
        Referer: `${AUTH_URL}?response_type=token&client_id=skolae-app`,
      },
      maxRedirects: 0,
      validateStatus: (s) => s >= 200 && s < 400,
    }
  );
  saveCookies(postRes.headers);

  // 3. Re-GET /oauth/authorize avec le JSESSIONID
  let location = `${AUTH_URL}?response_type=token&client_id=skolae-app`;
  for (let i = 0; i < 6 && location; i++) {
    const tokenMatch = location.match(/[#&?]access_token=([^&#]+)/);
    if (tokenMatch) {
      return {
        token:  decodeURIComponent(tokenMatch[1]),
        expiry: Date.now() + 55 * 60 * 1000,
      };
    }
    const r = await axios.get(location, {
      headers: { Cookie: cookieHeader(), "User-Agent": UA },
      maxRedirects: 0,
      validateStatus: (s) => s >= 200 && s < 400,
    });
    saveCookies(r.headers);
    location = r.headers["location"] || "";
  }

  throw new Error("Identifiants incorrects.");
}

async function mygesGet(path, token) {
  const res = await axios.get(`${BASE_API}${path}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  return res.data;
}

// --- Routes API ---
const ROUTES = [
  { path: "/api/grades",   myges: (y) => `/me/${y}/grades` },
  { path: "/api/absences", myges: (y) => `/me/${y}/absences` },
  { path: "/api/teachers", myges: (y) => `/me/${y}/teachers` },
  { path: "/api/courses",  myges: (y) => `/me/${y}/courses` },
];

for (const route of ROUTES) {
  app.get(route.path, async (req, res) => {
    try {
      const year = req.query.year || "2025";
      const data = await mygesGet(route.myges(year), req.mygesToken);
      res.json(data);
    } catch (e) {
      res.status(e.response?.status || 500).json({ error: e.message, detail: e.response?.data });
    }
  });
}

app.get("/api/raw", async (req, res) => {
  const { path } = req.query;
  if (!path) return res.status(400).json({ error: "path requis" });
  try {
    const data = await mygesGet(path, req.mygesToken);
    res.json(data);
  } catch (e) {
    res.status(e.response?.status || 500).json({ error: e.message, detail: e.response?.data });
  }
});

if (process.env.NODE_ENV !== "production") {
  const PORT = 3000;
  app.listen(PORT, () => console.log(`mygez → http://localhost:${PORT}`));
}

export default app;
