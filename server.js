import "dotenv/config";
import express from "express";
import axios from "axios";

const app = express();
app.use(express.json());
app.use(express.static("public"));

const BASE_API = "https://api.kordis.fr";
const AUTH_URL = "https://authentication.kordis.fr/oauth/authorize";
const BASE_AUTH = "https://authentication.kordis.fr";
const UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36";

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

  // 1. GET page de login en suivant les redirects manuellement
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

  // 3. Re-GET /oauth/authorize avec le JSESSIONID — on est maintenant authentifié
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

  throw new Error("Impossible de récupérer le token. Vérifie tes identifiants.");
}

async function mygesGet(path, token) {
  const res = await axios.get(`${BASE_API}${path}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  return res.data;
}

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

const ROUTES = [
  { path: "/api/grades",   myges: (y) => `/me/${y}/grades` },
  { path: "/api/absences", myges: (y) => `/me/${y}/absences` },
  { path: "/api/agenda",   myges: ()  => `/me/agenda?start=${weekStart()}&end=${weekEnd()}` },
  { path: "/api/teachers", myges: (y) => `/me/${y}/teachers` },
  { path: "/api/courses",  myges: (y) => `/me/${y}/courses` },
];

for (const route of ROUTES) {
  app.get(route.path, async (req, res) => {
    try {
      const token = await getToken();
      const year = req.query.year || "2025";
      const data = await mygesGet(route.myges(year), token);
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
    const data = await mygesGet(path, token);
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
