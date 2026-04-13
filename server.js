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

// --- Session ---
function makeToken(username) {
  return crypto.createHmac("sha256", process.env.APP_SECRET).update(username).digest("hex");
}
function parseCookies(req) {
  return Object.fromEntries(
    (req.headers.cookie || "").split(";").map(c => c.trim().split("=").map(s => decodeURIComponent(s.trim())))
  );
}
function isAuth(req) {
  const token = parseCookies(req)[COOKIE];
  if (!token) return false;
  const expected = makeToken(process.env.USERNAME);
  try { return crypto.timingSafeEqual(Buffer.from(token, "hex"), Buffer.from(expected, "hex")); }
  catch { return false; }
}

// --- Login routes (publiques) ---
app.get("/login", (req, res) => res.sendFile(join(__dirname, "login.html")));

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  if (username === process.env.USERNAME && password === process.env.PASSWORD) {
    const token  = makeToken(username);
    const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
    res.setHeader("Set-Cookie", `${COOKIE}=${token}; HttpOnly${secure}; SameSite=Strict; Path=/; Max-Age=604800`);
    return res.redirect("/");
  }
  res.redirect("/login?error=1");
});

app.get("/logout", (req, res) => {
  res.setHeader("Set-Cookie", `${COOKIE}=; HttpOnly; Path=/; Max-Age=0`);
  res.redirect("/login");
});

// --- Auth middleware ---
app.use((req, res, next) => {
  if (isAuth(req)) return next();
  if (req.path.startsWith("/api/")) return res.status(401).json({ error: "Non authentifié" });
  res.redirect("/login");
});

// --- Fichiers statiques protégés ---
app.use(express.static("public"));

// --- MyGES Auth ---
let cachedToken = null;
let tokenExpiry = 0;

async function getToken() {
  if (cachedToken && Date.now() < tokenExpiry) return cachedToken;

  const { USERNAME, PASSWORD } = process.env;
  if (!USERNAME || !PASSWORD) throw new Error("Identifiants manquants dans .env");

  const jar = {};
  const saveCookies = (headers) => {
    for (const c of [headers["set-cookie"] || []].flat()) {
      const [pair] = c.split(";");
      const eq = pair.indexOf("=");
      if (eq > 0) jar[pair.slice(0, eq).trim()] = pair.slice(eq + 1).trim();
    }
  };
  const cookieHeader = () => Object.entries(jar).map(([k, v]) => `${k}=${v}`).join("; ");

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

  const actionMatch = loginPageData.match(/action="([^"]+)"/);
  const actionUrl = new URL(actionMatch?.[1]?.replace(/&amp;/g, "&") ?? "/login", BASE_AUTH);
  if (!actionUrl.searchParams.has("client_id")) {
    actionUrl.searchParams.set("response_type", "token");
    actionUrl.searchParams.set("client_id", "skolae-app");
  }

  const postRes = await axios.post(
    actionUrl.href,
    new URLSearchParams({ username: USERNAME, password: PASSWORD }).toString(),
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

  let location = `${AUTH_URL}?response_type=token&client_id=skolae-app`;
  for (let i = 0; i < 6 && location; i++) {
    const tokenMatch = location.match(/[#&?]access_token=([^&#]+)/);
    if (tokenMatch) {
      cachedToken = decodeURIComponent(tokenMatch[1]);
      tokenExpiry = Date.now() + 55 * 60 * 1000;
      return cachedToken;
    }
    const r = await axios.get(location, {
      headers: { Cookie: cookieHeader(), "User-Agent": UA },
      maxRedirects: 0,
      validateStatus: (s) => s >= 200 && s < 400,
    });
    saveCookies(r.headers);
    location = r.headers["location"] || "";
  }

  throw new Error("Impossible de récupérer le token MyGES.");
}

async function mygesGet(path, token) {
  const res = await axios.get(`${BASE_API}${path}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  return res.data;
}


const ROUTES = [
  { path: "/api/grades",   myges: (y) => `/me/${y}/grades` },
  { path: "/api/absences", myges: (y) => `/me/${y}/absences` },
  { path: "/api/teachers", myges: (y) => `/me/${y}/teachers` },
  { path: "/api/courses",  myges: (y) => `/me/${y}/courses` },
];

for (const route of ROUTES) {
  app.get(route.path, async (req, res) => {
    try {
      const token = await getToken();
      const year  = req.query.year || "2025";
      const data  = await mygesGet(route.myges(year), token);
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
    const token = await getToken();
    const data  = await mygesGet(path, token);
    res.json(data);
  } catch (e) {
    res.status(e.response?.status || 500).json({ error: e.message, detail: e.response?.data });
  }
});

if (process.env.NODE_ENV !== "production") {
  const PORT = 3000;
  app.listen(PORT, () => console.log(`MyGES Explorer → http://localhost:${PORT}`));
}

export default app;
