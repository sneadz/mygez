import "dotenv/config";
import express from "express";
import axios from "axios";

const app = express();
app.use(express.json());
app.use(express.static("public"));

const BASE_API = "https://api.kordis.fr";
const AUTH_URL = "https://authentication.kordis.fr/oauth/authorize";

let cachedToken = null;
let tokenExpiry = 0;

// --- Auth ---
const BASE_AUTH = "https://authentication.kordis.fr";
const UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36";

async function getToken() {
  if (cachedToken && Date.now() < tokenExpiry) return cachedToken;

  const { USERNAME, PASSWORD } = process.env;
  if (!USERNAME || !PASSWORD) throw new Error("Identifiants manquants dans .env");

  // Cookie jar simple
  const jar = {};
  const saveCookies = (headers) => {
    for (const c of [headers["set-cookie"] || []].flat()) {
      const [pair] = c.split(";");
      const eq = pair.indexOf("=");
      if (eq > 0) jar[pair.slice(0, eq).trim()] = pair.slice(eq + 1).trim();
    }
  };
  const cookieHeader = () => Object.entries(jar).map(([k, v]) => `${k}=${v}`).join("; ");

  // 1. GET page de login en suivant les redirects manuellement (pour capturer tous les cookies)
  let currentUrl = `${AUTH_URL}?response_type=token&client_id=skolae-app`;
  let loginPageData = "";
  for (let i = 0; i < 6; i++) {
    console.log(`GET [${i}] →`, currentUrl);
    const r = await axios.get(currentUrl, {
      headers: { "Cookie": cookieHeader(), "User-Agent": UA },
      maxRedirects: 0,
      validateStatus: (s) => s >= 200 && s < 400,
    });
    saveCookies(r.headers);
    console.log(`   ${r.status} | set-cookie: ${r.headers["set-cookie"] || "aucun"} | location: ${r.headers.location || "—"}`);
    if (r.headers.location) {
      currentUrl = new URL(r.headers.location, BASE_AUTH).href;
    } else {
      loginPageData = r.data;
      break;
    }
  }

  const actionMatch = loginPageData.match(/action="([^"]+)"/);
  const rawAction = actionMatch?.[1]?.replace(/&amp;/g, "&") ?? "/login";
  // Inclure les params OAuth dans l'URL de POST si absents
  const actionUrl = new URL(rawAction, BASE_AUTH);
  if (!actionUrl.searchParams.has("client_id")) {
    actionUrl.searchParams.set("response_type", "token");
    actionUrl.searchParams.set("client_id", "skolae-app");
  }
  const formAction = actionUrl.href;

  // 2. POST credentials
  const body = new URLSearchParams({ username: USERNAME, password: PASSWORD });
  console.log("POST →", formAction, "| Cookies:", cookieHeader());
  console.log("Body →", `username=${USERNAME?.slice(0,3)}*** password=${PASSWORD ? "(set)" : "(vide)"}`);
  const postRes = await axios.post(formAction, body.toString(), {
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "Cookie": cookieHeader(),
      "User-Agent": UA,
      "Referer": `${AUTH_URL}?response_type=token&client_id=skolae-app`,
    },
    maxRedirects: 0,
    validateStatus: (s) => s >= 200 && s < 400,
  });
  saveCookies(postRes.headers);

  saveCookies(postRes.headers);

  // 3. Re-GET /oauth/authorize avec le JSESSIONID — cette fois on est authentifié
  const oauthUrl = `${AUTH_URL}?response_type=token&client_id=skolae-app`;
  let location = oauthUrl;
  for (let i = 0; i < 6 && location; i++) {
    const tokenMatch = location.match(/[#&?]access_token=([^&#]+)/);
    if (tokenMatch) {
      cachedToken = decodeURIComponent(tokenMatch[1]);
      tokenExpiry = Date.now() + 55 * 60 * 1000;
      console.log("Token obtenu ✓");
      return cachedToken;
    }
    console.log("Redirect →", location);
    const r = await axios.get(location, {
      headers: { "Cookie": cookieHeader(), "User-Agent": UA },
      maxRedirects: 0,
      validateStatus: (s) => s >= 200 && s < 400,
    });
    saveCookies(r.headers);
    location = r.headers["location"] || "";
  }

  console.error("Dernière location:", location || "(vide)", "| Cookies:", cookieHeader());
  throw new Error("Impossible de récupérer le token. Vérifie tes identifiants.");
}

// --- Proxy générique ---
async function mygesGet(path, token) {
  const res = await axios.get(`${BASE_API}${path}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  return res.data;
}

// --- Debug: tester les params de l'agenda ---
app.get("/api/debug-agenda", async (req, res) => {
  const token = await getToken();
  const year = req.query.year || "2025";
  const tsStart = new Date("2026-01-01").getTime();
  const tsEnd   = new Date("2026-06-30").getTime();
  const candidates = [
    `/me/${year}/agenda`,
    `/me/${year}/agenda?startDate=${tsStart}&endDate=${tsEnd}`,
    `/me/${year}/agenda?start=${tsStart}&end=${tsEnd}`,
    `/me/agenda?startDate=${tsStart}&endDate=${tsEnd}`,
    `/me/agenda?start=${tsStart}&end=${tsEnd}`,
    `/me/${year}/agenda?startDate=2026-01-01&endDate=2026-06-30`,
  ];
  const results = await Promise.all(candidates.map(async (path) => {
    const r = await axios.get(`${BASE_API}${path}`, {
      headers: { Authorization: `Bearer ${token}` },
      validateStatus: () => true,
    });
    return { path, status: r.status, body: r.status !== 200 ? String(r.data).slice(0, 200) : "(ok)" };
  }));
  res.json(results);
});

// --- Routes API ---
app.get("/api/token-check", async (req, res) => {
  try {
    await getToken();
    res.json({ ok: true });
  } catch (e) {
    res.status(401).json({ ok: false, error: e.message });
  }
});

const YEAR = new Date().getFullYear();

const ROUTES = [
  { path: "/api/profile",  myges: (y) => `/me` },
  { path: "/api/grades",   myges: (y) => `/me/${y}/grades` },
  { path: "/api/absences", myges: (y) => `/me/${y}/absences` },
  { path: "/api/agenda",   myges: (y) => `/me/agenda?start=${weekStart()}&end=${weekEnd()}` },
  { path: "/api/news",     myges: (y) => `/me/news` },
  { path: "/api/teachers", myges: (y) => `/me/${y}/teachers` },
  { path: "/api/courses",  myges: (y) => `/me/${y}/courses` },
  { path: "/api/students", myges: (y) => `/me/${y}/students` },
];

function weekStart() {
  const d = new Date();
  d.setDate(d.getDate() - d.getDay() + 1);
  d.setHours(0, 0, 0, 0);
  return d.getTime();
}
function weekEnd() {
  const d = new Date();
  d.setDate(d.getDate() - d.getDay() + 7);
  d.setHours(23, 59, 59, 999);
  return d.getTime();
}

for (const route of ROUTES) {
  app.get(route.path, async (req, res) => {
    try {
      const token = await getToken();
      const year = req.query.year || "2025";
      const data = await mygesGet(route.myges(year), token);
      res.json(data);
    } catch (e) {
      const status = e.response?.status || 500;
      res.status(status).json({ error: e.message, detail: e.response?.data });
    }
  });
}

// Route générique /api/raw?path=/me/...
app.get("/api/raw", async (req, res) => {
  const { path } = req.query;
  if (!path) return res.status(400).json({ error: "path requis" });
  try {
    const token = await getToken();
    const data = await mygesGet(path, token);
    res.json(data);
  } catch (e) {
    res.status(e.response?.status || 500).json({ error: e.message, detail: e.response?.data });
  }
});

// Local dev
if (process.env.NODE_ENV !== "production") {
  const PORT = 3000;
  app.listen(PORT, () => console.log(`MyGES Explorer → http://localhost:${PORT}`));
}

export default app;
