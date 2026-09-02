/**
 * Men In A Movie — Worker
 * Пази съдържанието на сайта и пази паролите скрити.
 *
 * Нужно е едно нещо: KV namespace, вързан с име  MIM
 *
 * Маршрути:
 *   GET  /api/auth     → как се влиза в момента: с имейл и парола или с ключ
 *   POST /api/auth     → задава имейл и парола на собственика (само първия път или от админ)
 *   POST /api/login    → {email,password} или {key} → кой е този човек + талон за сесия
 *   GET  /api/users    → списък с хората (само админ)
 *   POST /api/users    → добавя, променя или трие човек (само админ)
 *   GET  /api/content  → съдържанието без тайните (или 204, ако още няма)
 *   POST /api/content  → записва съдържание; иска x-mim-token или x-mim-key
 *   всичко друго       → статичните файлове
 */

const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
};
const json = (data, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: JSON_HEADERS });

const SESSION_DAYS = 30;

/* ---------- дребни помощни ---------- */
const enc = new TextEncoder();
function hex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function unhex(s) {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
}
function randHex(n) {
  return hex(crypto.getRandomValues(new Uint8Array(n)));
}
/** сравнение с еднакво време, за да не се гадае по бързината */
function sameString(a, b) {
  a = String(a || "");
  b = String(b || "");
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
async function hashPassword(password, saltHex) {
  const key = await crypto.subtle.importKey("raw", enc.encode(String(password)), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: unhex(saltHex), iterations: 100000, hash: "SHA-256" },
    key,
    256
  );
  return hex(bits);
}
const normMail = (m) => String(m || "").trim().toLowerCase();
const ROLES = ["admin", "moderator", "author"];

/* ---------- хранилище ---------- */
async function stored(env) {
  const raw = await env.MIM.get("content");
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch (e) {
    return null;
  }
}
/** Записът за достъпа: {users:[{id,email,name,role,salt,hash}]} */
async function authRecord(env) {
  const raw = await env.MIM.get("auth");
  if (!raw) return null;
  let rec;
  try {
    rec = JSON.parse(raw);
  } catch (e) {
    return null;
  }
  if (!rec) return null;
  // стар вид: един собственик направо в записа
  if (!rec.users && rec.email && rec.hash) {
    rec = {
      users: [
        { id: "owner", email: rec.email, name: rec.name || "Администратор", role: "admin", salt: rec.salt, hash: rec.hash },
      ],
    };
  }
  if (!Array.isArray(rec.users)) return null;
  return rec;
}
const saveAuth = (env, rec) => env.MIM.put("auth", JSON.stringify(rec));

async function newSession(env, who) {
  const token = randHex(24);
  await env.MIM.put("sess:" + token, JSON.stringify(who), { expirationTtl: SESSION_DAYS * 86400 });
  return token;
}
async function bySession(env, token) {
  if (!token) return null;
  const raw = await env.MIM.get("sess:" + String(token).trim());
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch (e) {
    return null;
  }
}

/** Кой е този ключ: {role,id,name} или null — старият начин, пази се за съвместимост */
function identifyKey(key, data, env) {
  if (!key) return null;
  if (env.ADMIN_KEY && sameString(key, env.ADMIN_KEY))
    return { role: "admin", id: "owner", name: "Администратор" };
  if (data && data.settings) {
    if (data.settings.adminKey && sameString(key, data.settings.adminKey))
      return { role: "admin", id: "owner", name: "Администратор" };
    const u = (data.settings.users || []).find((x) => x && x.key && sameString(x.key, key));
    if (u) return { role: u.role || "author", id: u.id, name: u.name || "Потребител" };
  }
  return null;
}

/** Кой стои зад заявката — първо талон за сесия, после стар ключ */
async function whoIs(request, env, data) {
  const token = (request.headers.get("x-mim-token") || "").trim();
  const who = await bySession(env, token);
  if (who) return who;
  const key = (request.headers.get("x-mim-key") || "").trim();
  return identifyKey(key, data, env);
}

/** Маха тайните, преди съдържанието да тръгне към браузъра */
function publicCopy(data) {
  const out = JSON.parse(JSON.stringify(data));
  if (out.settings) {
    delete out.settings.adminKey;
    out.settings.users = (out.settings.users || []).map((u) => ({
      id: u.id,
      name: u.name,
      email: u.email,
      role: u.role,
    }));
  }
  return out;
}

/** Връща тайните, които браузърът не е виждал */
function keepSecrets(incoming, prev) {
  if (!prev || !prev.settings) return incoming;
  const s = incoming.settings || (incoming.settings = {});
  if (!s.adminKey && prev.settings.adminKey) s.adminKey = prev.settings.adminKey;
  const old = prev.settings.users || [];
  s.users = (s.users || []).map((u) => {
    if (u.key) return u;
    const o = old.find((x) => x.id === u.id);
    return o && o.key ? Object.assign({}, u, { key: o.key }) : u;
  });
  return incoming;
}

/** Хората за админ панела — без сол и без отпечатък от паролата */
const safeUsers = (rec) =>
  (rec && rec.users ? rec.users : []).map((u) => ({ id: u.id, name: u.name, email: u.email, role: u.role }));



/* ---------- снимките се раздават отделно, а не вътре в съдържанието ---------- */
const IMG_FIELDS = { reviews: "poster", news: "img", craft: "img", merch: "img" };
const KEY_OF = { reviews: "r", news: "n", craft: "c", merch: "m" };
const isDataUri = (v) => typeof v === "string" && v.slice(0, 11) === "data:image/";
/* кратък отпечатък, за да се смени адресът при нова снимка */
function stamp(str) {
  let h = 5381;
  for (let i = 0; i < str.length; i += 97) h = ((h * 33) ^ str.charCodeAt(i)) >>> 0;
  return (h.toString(36) + str.length.toString(36)).slice(0, 10);
}
/* съдържание за браузъра: снимките стават адреси */
function liftImages(data) {
  for (const kind of Object.keys(IMG_FIELDS)) {
    const f = IMG_FIELDS[kind];
    for (const it of data[kind] || []) {
      if (it && isDataUri(it[f])) it[f] = "/img/" + KEY_OF[kind] + "/" + encodeURIComponent(it.id) + "?v=" + stamp(it[f]);
    }
  }
  return data;
}
/* при запис: адресите се връщат обратно към снимките, които браузърът никога не е виждал */
function keepImages(incoming, prev) {
  if (!prev) return incoming;
  for (const kind of Object.keys(IMG_FIELDS)) {
    const f = IMG_FIELDS[kind];
    const old = prev[kind] || [];
    for (const it of incoming[kind] || []) {
      if (!it || isDataUri(it[f])) continue;
      if (typeof it[f] === "string" && it[f].indexOf("/img/") === 0) {
        const o = old.find((x) => x && x.id === it.id);
        it[f] = o && isDataUri(o[f]) ? o[f] : "";
      }
    }
  }
  return incoming;
}


/* ---------- броячи: прегледи и харесвания ---------- */
async function counters(env) {
  const raw = await env.MIM.get("stats");
  if (!raw) return { views: {}, likes: {} };
  try {
    const c = JSON.parse(raw);
    return { views: c.views || {}, likes: c.likes || {} };
  } catch (e) {
    return { views: {}, likes: {} };
  }
}
const saveCounters = (env, c) => env.MIM.put("stats", JSON.stringify(c));
const COUNT_KINDS = { r: "reviews", n: "news", c: "craft", e: "episodes", k: "calendar" };

/* Броячите се трупат тук и се записват рядко — иначе безплатният план
   свършва записите си за деня при първия по-натоварен ден. */
const FLUSH_MS = 5 * 60 * 1000;
let buf = null;          // {views:{key:+n}, likes:{key:+n}}
let bufAt = 0;
function bump(key, field, delta) {
  if (!buf) { buf = { views: {}, likes: {} }; bufAt = Date.now(); }
  buf[field][key] = (buf[field][key] || 0) + delta;
}
function merged(c) {
  if (!buf) return c;
  for (const f of ["views", "likes"])
    for (const k of Object.keys(buf[f])) c[f][k] = Math.max(0, (c[f][k] || 0) + buf[f][k]);
  return c;
}
async function flushCounters(env, force) {
  if (!buf) return;
  if (!force && Date.now() - bufAt < FLUSH_MS) return;
  const c = merged(await counters(env));
  buf = null;
  await saveCounters(env, c);
}


/* ---------- какво може да записва един автор ---------- */
const AUTHOR_KINDS = ["reviews", "news", "craft"];

/**
 * Авторът праща целия сайт, но пипаме САМО неговите материали.
 * Чуждото, настройките, рекламите и календарът се вземат от предишното състояние.
 * Публикуване няма — статусът се смъква до „чернова“ или „за одобрение“.
 */
function authorMerge(incoming, prev, who) {
  const base = prev ? JSON.parse(JSON.stringify(prev)) : { settings: incoming.settings };
  const mineId = String(who.id || "");
  for (const kind of AUTHOR_KINDS) {
    const old = Array.isArray(base[kind]) ? base[kind] : [];
    const inc = Array.isArray(incoming[kind]) ? incoming[kind] : [];
    const owner = {};
    for (const x of old) if (x && x.id != null) owner[String(x.id)] = String(x.author || "");
    const sent = {};
    for (const x of inc) {
      if (!x || x.id == null) continue;
      if (String(x.author || "") !== mineId) continue;          // чуждо — не се пипа
      const id = String(x.id);
      if (owner[id] !== undefined && owner[id] !== mineId) continue;   // чужд запис със същото id
      const wasPublished = (old.find((o) => o && String(o.id) === id) || {}).status === "published";
      if (wasPublished) continue;                                // публикуваното не се пипа от автора
      const copy = Object.assign({}, x);
      copy.author = mineId;
      copy.status = copy.status === "review" ? "review" : "draft";
      sent[id] = copy;
    }
    const out = [];
    for (const x of old) {
      const id = x && x.id != null ? String(x.id) : null;
      if (id && String(x.author || "") === mineId && x.status !== "published") {
        if (sent[id]) { out.push(sent[id]); delete sent[id]; }  // поправен
        continue;                                               // липсва в изпратеното → изтрит
      }
      out.push(x);
    }
    const fresh = Object.keys(sent).map((k) => sent[k]);         // новите отиват най-отгоре
    base[kind] = fresh.concat(out);
  }
  return base;
}

/* ---------- Movie calendar: премиери от TMDB ---------- */
const TMDB = "https://api.themoviedb.org/3";
const POSTER = "https://image.tmdb.org/t/p/w500";
const DEF_PROVIDERS = [
  { id: 8, name: "Netflix" },
  { id: 1899, name: "HBO Max" },
  { id: 337, name: "Disney+" },
  { id: 119, name: "Prime Video" },
];
const ymd = (d) => d.toISOString().slice(0, 10);

async function tmdbGet(env, path, params) {
  const u = new URL(TMDB + path);
  for (const k of Object.keys(params)) u.searchParams.set(k, params[k]);
  const key = String(env.TMDB_KEY || "").trim();
  const headers = { accept: "application/json" };
  // v4 талонът е дълъг и започва с eyJ — той върви в заглавната част, не в адреса
  if (key.length > 60 || key.slice(0, 3) === "eyJ") headers.authorization = "Bearer " + key;
  else u.searchParams.set("api_key", key);
  const r = await fetch(u.toString(), { headers: headers });
  if (!r.ok) {
    let detail = "";
    try { const j = await r.json(); detail = j && j.status_message ? j.status_message : ""; } catch (e) {}
    if (r.status === 401) detail = "ключът не се приема от TMDB" + (detail ? " (" + detail + ")" : "");
    throw new Error("TMDB " + r.status + (detail ? " — " + detail : ""));
  }
  return r.json();
}

/** Един ред за календара от сериал: sub = series | season | episode */
function tvItem(t, pv, sub, when, season, episode) {
  return {
    id: "tmdb-t-" + t.id, kind: "stream", src: "tmdb", tmdbId: t.id,
    t: t.name || t.original_name || "", when: when,
    poster: t.poster_path ? POSTER + t.poster_path : "",
    p: (t.overview || "").slice(0, 320), platform: pv.name,
    sub: sub, season: season ? +season : null, episode: episode ? +episode : null,
    video: "", note: "",
  };
}

/** Тегли премиерите и сериалите за следващите месеци и ги слива с наличните. */
async function syncCalendar(env, months) {
  if (!env.TMDB_KEY) return { error: "no_key", message: "Липсва ключът TMDB_KEY в Cloudflare." };
  const data = (await stored(env)) || {};
  const s = data.settings || (data.settings = {});
  const providers = Array.isArray(s.calProviders) && s.calProviders.length ? s.calProviders : DEF_PROVIDERS;
  const from = new Date();
  from.setDate(1);
  const to = new Date(from);
  to.setMonth(to.getMonth() + (months || 3));

  const fresh = [];
  const notes = [];
  let nMovies = 0, nSeries = 0;
  // филми по кината в България
  try {
    const mv = await tmdbGet(env, "/discover/movie", {
      region: "BG", with_release_type: "2|3", language: "bg-BG",
      "release_date.gte": ymd(from), "release_date.lte": ymd(to),
      sort_by: "primary_release_date.asc", include_adult: "false", page: "1",
    });
    for (const m of (mv.results || []).slice(0, 40)) {
      if (!m.release_date) continue;
      fresh.push({
        id: "tmdb-m-" + m.id, kind: "cinema", src: "tmdb", tmdbId: m.id,
        t: m.title || m.original_title || "", when: m.release_date,
        poster: m.poster_path ? POSTER + m.poster_path : "",
        p: (m.overview || "").slice(0, 320), video: "", note: "",
      });
      nMovies++;
    }
    if (!nMovies) notes.push("TMDB няма премиери за България в този период.");
  } catch (e) { notes.push("Филми: " + e.message); }
  // сериали по стрийминга — само с истинска дата на излъчване
  const lo = ymd(from), hi = ymd(to);
  let budget = 34;                       // таван на допълнителните запитвания към TMDB
  for (const pv of providers.slice(0, 4)) {
    // 1) премиери на НОВИ сериали
    try {
      const nw = await tmdbGet(env, "/discover/tv", {
        watch_region: "BG", with_watch_providers: String(pv.id), language: "bg-BG",
        "first_air_date.gte": lo, "first_air_date.lte": hi,
        sort_by: "popularity.desc", page: "1",
      });
      for (const t of (nw.results || []).slice(0, 6)) {
        if (!t.first_air_date || t.first_air_date < lo || t.first_air_date > hi) continue;
        if (fresh.some((f) => f.tmdbId === t.id && f.kind === "stream")) continue;
        fresh.push(tvItem(t, pv, "series", t.first_air_date, 1, 1));
        nSeries++;
      }
    } catch (e) { notes.push(pv.name + ": " + e.message); }

    // 2) нови сезони и епизоди на вървящи сериали
    try {
      const tv = await tmdbGet(env, "/discover/tv", {
        watch_region: "BG", with_watch_providers: String(pv.id), language: "bg-BG",
        "air_date.gte": lo, "air_date.lte": hi,
        sort_by: "popularity.desc", page: "1",
      });
      for (const t of (tv.results || []).slice(0, 8)) {
        if (budget <= 0) break;
        if (fresh.some((f) => f.tmdbId === t.id && f.kind === "stream")) continue;
        budget--;
        let d = null;
        try { d = await tmdbGet(env, "/tv/" + t.id, { language: "bg-BG" }); } catch (e) { continue; }
        const ne = d && d.next_episode_to_air;
        if (!ne || !ne.air_date || ne.air_date < lo || ne.air_date > hi) continue;   // няма надеждна дата — не влиза
        const sub = +ne.episode_number === 1 ? "season" : "episode";
        fresh.push(tvItem(t, pv, sub, ne.air_date, ne.season_number, ne.episode_number));
        nSeries++;
      }
    } catch (e) { notes.push(pv.name + ": " + e.message); }
  }
  if (!nSeries && !notes.some((x) => x.indexOf("TMDB 4") >= 0))
    notes.push("TMDB няма сериали с обявена дата за България в този период.");

  const old = Array.isArray(data.calendar) ? data.calendar : [];
  const byId = {};
  for (const it of old) byId[it.id] = it;
  const out = [];
  // ръчните и събитията остават непокътнати
  for (const it of old) if (it.src !== "tmdb") out.push(it);
  // от миналия месец нататък се пази само това, което е пипано
  const cut = ymd(from);
  for (const it of old)
    if (it.src === "tmdb" && it.when < cut && (it.edited || it.hidden)) out.push(it);

  const seen = {};
  for (const f of fresh) {
    if (seen[f.id]) continue;
    seen[f.id] = 1;
    const o = byId[f.id];
    if (o && (o.edited || o.hidden)) { if (!out.some((x) => x.id === o.id)) out.push(o); continue; }
    out.push(o ? Object.assign({}, o, f) : f);
  }
  out.sort((a, b) => String(a.when).localeCompare(String(b.when)));
  data.calendar = out;
  data.settings.calSyncedAt = Date.now();
  await env.MIM.put("content", JSON.stringify(data));
  return {
    ok: true, count: out.length, added: fresh.length,
    movies: nMovies, series: nSeries, notes: notes, at: data.settings.calSyncedAt,
  };
}

/* ---------- споделяне: страница с картинка за Facebook, Viber и т.н. ---------- */
const KINDS = { r: "reviews", n: "news", c: "craft", e: "episodes", m: "merch", k: "calendar" };
const SECTION = { reviews: "revyuta", news: "novini", craft: "zad-kadar", episodes: "podcast", merch: "merch", calendar: "kalendar" };

function findItem(data, kindKey, id) {
  const list = (data && data[KINDS[kindKey]]) || [];
  return list.find((x) => x && String(x.id) === String(id)) || null;
}
function itemImage(it) {
  if (!it) return "";
  return it.poster || it.img || "";
}
function ytIdOf(u) {
  u = String(u || "").trim();
  const pats = [/youtu\.be\/([\w-]{6,})/, /youtube\.com\/shorts\/([\w-]{6,})/, /youtube\.com\/live\/([\w-]{6,})/, /youtube\.com\/embed\/([\w-]{6,})/, /[?&]v=([\w-]{6,})/];
  for (const p of pats) { const m = p.exec(u); if (m) return m[1]; }
  return null;
}
function escHtml(t) {
  return String(t == null ? "" : t).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function plain(t, max) {
  const s = String(t || "").replace(/[*_>#\[\]()]/g, " ").replace(/\s+/g, " ").trim();
  return s.length > max ? s.slice(0, max - 1).trimEnd() + "…" : s;
}
/* ================= ПРАВИЛНИ АДРЕСИ ЗА ТЪРСАЧКИТЕ И AI ================= */

const SEO_PATH = { reviews: "revyu", news: "novina", craft: "zad-kadar", episodes: "epizod", calendar: "kalendar" };
const SEO_LABEL = { reviews: "Ревюта", news: "Новини", craft: "Зад кадър", episodes: "Подкаст", calendar: "Movie calendar" };
const SEO_ANCHOR = { reviews: "revyuta", news: "novini", craft: "zad-kadar", episodes: "podcast", calendar: "kalendar" };
const SEO_SHARE = { reviews: "r", news: "n", craft: "c", episodes: "e", calendar: "k" };

const BG2LAT = {
  а:"a",б:"b",в:"v",г:"g",д:"d",е:"e",ж:"zh",з:"z",и:"i",й:"y",к:"k",л:"l",м:"m",
  н:"n",о:"o",п:"p",р:"r",с:"s",т:"t",у:"u",ф:"f",х:"h",ц:"ts",ч:"ch",ш:"sh",
  щ:"sht",ъ:"a",ь:"y",ю:"yu",я:"ya",
};
function slugify(s) {
  let out = "";
  for (const ch of String(s || "").toLowerCase()) {
    if (BG2LAT[ch]) out += BG2LAT[ch];
    else if (/[a-z0-9]/.test(ch)) out += ch;
    else out += "-";
  }
  return out.replace(/-+/g, "-").replace(/^-|-$/g, "").slice(0, 70) || "bez-zaglavie";
}
/* кратка опашка от id-то, за да няма два еднакви адреса */
function idTail(id) {
  const m = /([a-z0-9]{4,})$/i.exec(String(id || ""));
  return (m ? m[1] : String(id || "x")).toLowerCase().slice(-6);
}
function seoSlug(it) { return slugify(it && it.t) + "-" + idTail(it && it.id); }
function seoUrl(kind, it) { return "/" + SEO_PATH[kind] + "/" + seoSlug(it); }

/* показва ли се на сайта изобщо */
function seoLive(kind, it) {
  if (!it || !it.t) return false;
  if (kind === "calendar") return !it.hidden;
  if (kind === "merch") return false;
  const st = it.status || "published";
  if (st !== "published") return false;
  /* насрочено за бъдеща дата — чака я, преди да излезе някъде */
  if (it.schedule !== false) {
    const d = seoDate(kind, it);
    if (/^\d{4}-\d{2}-\d{2}$/.test(d) && d > ymd(new Date())) return false;
  }
  return true;
}
function seoDate(kind, it) {
  return String(it.when || it.d || "").slice(0, 10) || "";
}
function seoDesc(it, max) {
  return plain(it.verdict || it.p || it.desc || it.body || it.note || "", max || 200);
}
function seoImage(kind, it, origin) {
  if (kind === "calendar") return /^https?:/.test(String(it.poster || "")) ? it.poster : origin + "/og.jpg";
  const key = SEO_SHARE[kind];
  if (it.poster || it.img || it.yt || it.video) return origin + "/img/" + key + "/" + encodeURIComponent(it.id);
  return origin + "/og.jpg";
}
function seoAll(data) {
  const out = [];
  for (const kind of Object.keys(SEO_PATH)) {
    for (const it of data[kind] || []) if (seoLive(kind, it)) out.push({ kind, it, url: seoUrl(kind, it) });
  }
  return out;
}
function seoFind(data, kind, slug) {
  const list = (data && data[kind]) || [];
  const want = String(slug || "").toLowerCase();
  for (const it of list) if (seoLive(kind, it) && seoSlug(it) === want) return it;
  const tail = want.split("-").pop();
  for (const it of list) if (seoLive(kind, it) && idTail(it.id) === tail) return it;
  for (const it of list) if (seoLive(kind, it) && String(it.id).toLowerCase() === want) return it;
  return null;
}

/* ---------- теми (таговете от админа) ---------- */
const SEO_TAG_MIN = 2;               // тема с един материал не получава своя страница
function itemTags(it) {
  const raw = Array.isArray(it && it.tags) ? it.tags : [];
  const seen = {}, out = [];
  for (const t of raw) {
    const name = String(t || "").trim();
    if (!name) continue;
    const sl = slugify(name);
    if (!sl || seen[sl]) continue;
    seen[sl] = 1;
    out.push({ name, slug: sl });
  }
  return out.slice(0, 12);
}
function seoTagMap(data) {
  const map = {};
  for (const x of seoAll(data)) {
    for (const t of itemTags(x.it)) {
      if (!map[t.slug]) map[t.slug] = { name: t.name, slug: t.slug, items: [] };
      map[t.slug].items.push(x);
    }
  }
  return map;
}
function seoTagList(data) {
  const m = seoTagMap(data);
  return Object.keys(m).map((k) => m[k])
    .filter((t) => t.items.length >= SEO_TAG_MIN)
    .sort((a, b) => b.items.length - a.items.length || a.name.localeCompare(b.name));
}
function tagChipsHTML(it, big) {
  const tags = itemTags(it);
  if (!tags.length) return "";
  return '<div class="tags">' + (big ? "" : "<span>Теми:</span>") +
    tags.map((t) => (big && big[t.slug]
      ? '<a class="tag" href="/tema/' + t.slug + '">' + escHtml(t.name) + "</a>"
      : '<span class="tag">' + escHtml(t.name) + "</span>")).join("") + "</div>";
}

/* ---------- скромен markdown → html ---------- */
function seoBody(txt) {
  const src = String(txt || "").replace(/\r/g, "");
  if (!src.trim()) return "";
  const esc = (t) => escHtml(t);
  const inline = (t) =>
    esc(t)
      .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
      .replace(/(^|[^*])\*([^*]+)\*/g, "$1<em>$2</em>")
      .replace(/\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g, '<a href="$2" rel="nofollow">$1</a>');
  const out = [];
  let list = null;
  for (const raw of src.split("\n")) {
    const line = raw.trim();
    if (!line) { if (list) { out.push("<ul>" + list.join("") + "</ul>"); list = null; } continue; }
    const h = /^(#{2,4})\s+(.*)$/.exec(line);
    if (h) { if (list) { out.push("<ul>" + list.join("") + "</ul>"); list = null; }
      const lvl = Math.min(h[1].length + 1, 4); out.push("<h" + lvl + ">" + inline(h[2]) + "</h" + lvl + ">"); continue; }
    const li = /^[-*•]\s+(.*)$/.exec(line);
    if (li) { (list = list || []).push("<li>" + inline(li[1]) + "</li>"); continue; }
    const q = /^>\s+(.*)$/.exec(line);
    if (q) { if (list) { out.push("<ul>" + list.join("") + "</ul>"); list = null; }
      out.push("<blockquote>" + inline(q[1]) + "</blockquote>"); continue; }
    if (list) { out.push("<ul>" + list.join("") + "</ul>"); list = null; }
    out.push("<p>" + inline(line) + "</p>");
  }
  if (list) out.push("<ul>" + list.join("") + "</ul>");
  return out.join("");
}

const BG_MONTHS = ["януари","февруари","март","април","май","юни","юли","август","септември","октомври","ноември","декември"];
function seoDateBg(iso) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(iso || ""));
  return m ? +m[3] + " " + BG_MONTHS[+m[2] - 1] + " " + m[1] : "";
}

/* ---------- структурирани данни ---------- */
function seoJsonLd(kind, it, origin, canon, image) {
  const org = { "@type": "Organization", name: "Men In A Movie", url: origin + "/", logo: origin + "/og.jpg" };
  const author = it.authorName ? { "@type": "Person", name: it.authorName } : org;
  const date = seoDate(kind, it);
  const base = {
    "@context": "https://schema.org",
    headline: it.t, name: it.t,
    description: seoDesc(it, 300),
    image: [image],
    inLanguage: "bg-BG",
    mainEntityOfPage: canon,
    url: canon,
    author, publisher: org,
  };
  const kw = itemTags(it).map((t) => t.name);
  if (kw.length) base.keywords = kw.join(", ");
  if (date) { base.datePublished = date; base.dateModified = date; }

  let node;
  if (kind === "reviews") {
    node = Object.assign({}, base, {
      "@type": "Review",
      itemReviewed: { "@type": "Movie", name: it.t, ...(it.y ? { dateCreated: String(it.y) } : {}), ...(it.g ? { genre: it.g } : {}) },
      reviewRating: { "@type": "Rating", ratingValue: String(it.s || ""), bestRating: "5", worstRating: "1" },
      reviewBody: plain(it.body, 1500),
    });
    if (!it.s) delete node.reviewRating;
  } else if (kind === "news") {
    node = Object.assign({}, base, { "@type": "NewsArticle", articleSection: it.tag || "Новини" });
  } else if (kind === "craft") {
    node = Object.assign({}, base, { "@type": "Article", articleSection: it.tag || "Зад кадър" });
  } else if (kind === "episodes") {
    node = Object.assign({}, base, {
      "@type": "PodcastEpisode",
      episodeNumber: it.n ? +it.n : undefined,
      partOfSeries: { "@type": "PodcastSeries", name: "Men In A Movie", url: origin + "/#podcast" },
    });
  } else if (kind === "calendar" && it.kind === "event") {
    node = Object.assign({}, base, {
      "@type": "Event",
      startDate: it.when + (it.time ? "T" + it.time : ""),
      eventStatus: "https://schema.org/EventScheduled",
      eventAttendanceMode: "https://schema.org/OfflineEventAttendanceMode",
      location: { "@type": "Place", name: it.place || "България", address: it.place || "България" },
      organizer: it.organizer ? { "@type": "Organization", name: it.organizer } : undefined,
      ...(it.ticketUrl ? { offers: { "@type": "Offer", url: it.ticketUrl, availability: "https://schema.org/InStock" } } : {}),
    });
    delete node.headline;
  } else if (kind === "calendar") {
    node = Object.assign({}, base, {
      "@type": it.kind === "stream" ? "TVSeries" : "Movie",
      datePublished: it.when || undefined,
    });
    delete node.headline; delete node.dateModified;
  }
  const crumbs = {
    "@context": "https://schema.org", "@type": "BreadcrumbList",
    itemListElement: [
      { "@type": "ListItem", position: 1, name: "Men In A Movie", item: origin + "/" },
      { "@type": "ListItem", position: 2, name: SEO_LABEL[kind], item: origin + "/#" + SEO_ANCHOR[kind] },
      { "@type": "ListItem", position: 3, name: it.t, item: canon },
    ],
  };
  const clean = JSON.parse(JSON.stringify([node, crumbs]));
  return '<script type="application/ld+json">' + JSON.stringify(clean).replace(/</g, "\\u003c") + "</script>";
}

/* ---------- обвивката на страницата ---------- */
const SEO_CSS = `*{box-sizing:border-box}body{margin:0;background:#0A0908;color:#F6F2E6;font-family:Manrope,system-ui,-apple-system,"Segoe UI",sans-serif;line-height:1.65;font-size:17px}
a{color:#F6C92B}.wrap{max-width:760px;margin:0 auto;padding:0 22px}
header.top{border-bottom:1px solid rgba(246,242,230,.12);padding:16px 0;margin-bottom:34px}
header.top .wrap{display:flex;align-items:center;gap:14px;flex-wrap:wrap}
.brand{font-family:Montserrat,system-ui,sans-serif;font-weight:900;font-style:italic;text-transform:uppercase;letter-spacing:.02em;color:#F6C92B;text-decoration:none;font-size:18px}
header.top nav{display:flex;gap:16px;flex-wrap:wrap;margin-left:auto;font-size:13px;text-transform:uppercase;letter-spacing:.1em}
header.top nav a{color:#B9B3A6;text-decoration:none}header.top nav a:hover{color:#F6C92B}
.kicker{font-size:12px;letter-spacing:.18em;text-transform:uppercase;color:#F6C92B;margin:0 0 10px}
h1{font-family:Montserrat,system-ui,sans-serif;font-weight:900;font-style:italic;text-transform:uppercase;font-size:clamp(28px,6vw,44px);line-height:1.05;margin:0 0 14px}
h2,h3,h4{font-family:Montserrat,system-ui,sans-serif;font-weight:800;font-style:italic;text-transform:uppercase;line-height:1.15;margin:32px 0 10px}
h2{font-size:24px}h3{font-size:20px}h4{font-size:17px}
.meta{font-size:12.5px;letter-spacing:.12em;text-transform:uppercase;color:#B9B3A6;margin:0 0 22px}
.lede{font-size:19px;color:#EDE7D8;border-left:3px solid #F6C92B;padding-left:16px;margin:0 0 26px}
figure{margin:0 0 28px}figure img{width:100%;height:auto;display:block;border:1px solid rgba(246,242,230,.12)}
blockquote{border-left:3px solid #F6C92B;margin:22px 0;padding-left:16px;color:#EDE7D8;font-style:italic}
ul{padding-left:20px}li{margin:6px 0}
.sig{text-align:right;color:#B9B3A6;font-size:14px;margin:26px 0 0}
.btns{display:flex;gap:10px;flex-wrap:wrap;margin:30px 0}
.btn{display:inline-block;padding:11px 18px;border:1px solid rgba(246,242,230,.25);color:#F6F2E6;text-decoration:none;font-size:13px;letter-spacing:.1em;text-transform:uppercase}
.btn.gold{background:#F6C92B;border-color:#F6C92B;color:#000;font-weight:700}
.btn.like{display:inline-flex;align-items:center;gap:8px;cursor:pointer;font-family:inherit}
.btn.like.on{border-color:#F6C92B;color:#F6C92B}
.btn.like svg{display:block}
.rel{border-top:1px solid rgba(246,242,230,.12);margin-top:44px;padding-top:26px}
.rel ul{list-style:none;padding:0;margin:0}.rel li{margin:0 0 10px}
.rel a{text-decoration:none}.rel a:hover{text-decoration:underline}
.rel small{display:block;color:#8C877C;font-size:11.5px;letter-spacing:.12em;text-transform:uppercase}
.tags{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:30px 0 0;padding-top:18px;border-top:1px solid rgba(246,242,230,.12)}
.tags>span:first-child{font-size:11px;letter-spacing:.16em;text-transform:uppercase;color:#8C877C;margin-right:2px}
.tag{display:inline-block;font-size:12px;letter-spacing:.06em;padding:5px 11px;border:1px solid rgba(246,242,230,.22);color:#B9B3A6;text-decoration:none}
a.tag:hover{border-color:#F6C92B;color:#F6C92B}
footer.bot{border-top:1px solid rgba(246,242,230,.12);margin-top:50px;padding:26px 0 50px;color:#8C877C;font-size:13px}
footer.bot a{color:#B9B3A6}`;

function seoShell(opts) {
  const { title, desc, canon, image, ogType, head, body } = opts;
  return (
    '<!doctype html><html lang="bg"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1">' +
    "<title>" + escHtml(title) + "</title>" +
    '<meta name="description" content="' + escHtml(desc) + '">' +
    '<meta name="robots" content="index, follow, max-image-preview:large, max-snippet:-1">' +
    (opts.keywords ? '<meta name="keywords" content="' + escHtml(opts.keywords) + '">' : "") +
    '<link rel="canonical" href="' + escHtml(canon) + '">' +
    '<meta property="og:type" content="' + (ogType || "article") + '">' +
    '<meta property="og:site_name" content="Men In A Movie">' +
    '<meta property="og:locale" content="bg_BG">' +
    '<meta property="og:url" content="' + escHtml(canon) + '">' +
    '<meta property="og:title" content="' + escHtml(title) + '">' +
    '<meta property="og:description" content="' + escHtml(desc) + '">' +
    '<meta property="og:image" content="' + escHtml(image) + '">' +
    '<meta name="twitter:card" content="summary_large_image">' +
    '<meta name="twitter:title" content="' + escHtml(title) + '">' +
    '<meta name="twitter:description" content="' + escHtml(desc) + '">' +
    '<meta name="twitter:image" content="' + escHtml(image) + '">' +
    '<link rel="preconnect" href="https://fonts.googleapis.com">' +
    '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>' +
    '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Montserrat:ital,wght@1,800;1,900&family=Manrope:wght@400;600;700&display=swap">' +
    "<style>" + SEO_CSS + "</style>" + (head || "") +
    "</head><body>" +
    '<header class="top"><div class="wrap"><a class="brand" href="/">Men In A Movie</a>' +
    '<nav><a href="/#novini">Новини</a><a href="/#revyuta">Ревюта</a><a href="/#podcast">Подкаст</a>' +
    '<a href="/#kalendar">Movie calendar</a><a href="/karta">Карта на сайта</a></nav></div></header>' +
    '<main class="wrap">' + body + "</main>" +
    '<footer class="bot"><div class="wrap">Men In A Movie — кино, подкаст и ревюта. ' +
    '<a href="/">Към сайта</a> · <a href="/karta">Всички материали</a></div></footer>' +
    "</body></html>"
  );
}

function seoRelated(data, kind, it, limit) {
  const all = seoAll(data).filter((x) => !(x.kind === kind && x.it.id === it.id));
  const same = all.filter((x) => x.kind === kind);
  const rest = all.filter((x) => x.kind !== kind);
  const pick = same.slice(0, 4).concat(rest.slice(0, Math.max(0, (limit || 7) - Math.min(4, same.length))));
  if (!pick.length) return "";
  return '<section class="rel"><h2>Още от Men In A Movie</h2><ul>' +
    pick.map((x) => '<li><a href="' + x.url + '">' + escHtml(x.it.t) + "</a>" +
      "<small>" + escHtml(SEO_LABEL[x.kind]) + (seoDate(x.kind, x.it) ? " · " + escHtml(seoDateBg(seoDate(x.kind, x.it))) : "") + "</small></li>").join("") +
    "</ul></section>";
}

function seoItemPage(kind, it, data, origin) {
  const canon = origin + seoUrl(kind, it);
  const bigTags = {};
  for (const t of seoTagList(data)) bigTags[t.slug] = 1;   // кои теми имат своя страница
  const image = seoImage(kind, it, origin);
  const date = seoDate(kind, it);
  const CK = { cinema: "По кината", stream: "Стрийминг", event: "Събитие" };

  let title, metaBits = [], lede = "", extra = "";
  if (kind === "reviews") {
    title = it.t + (it.y ? " (" + it.y + ")" : "") + " — ревю | Men In A Movie";
    metaBits = ["Ревю", it.g, it.y, it.s ? it.s + "/5 клапи" : "", it.mins ? it.mins + " мин." : ""];
    lede = it.verdict || "";
    if (it.imdb) extra += '<a class="btn" rel="nofollow" href="' + escHtml(/^https?:/.test(it.imdb) ? it.imdb : "https://www.imdb.com/title/" + it.imdb + "/") + '">IMDb</a>';
  } else if (kind === "news") {
    title = it.t + " | Men In A Movie";
    metaBits = [it.tag || "Новини", seoDateBg(date)];
    lede = it.p || "";
  } else if (kind === "craft") {
    title = it.t + " | Зад кадър — Men In A Movie";
    metaBits = ["Зад кадър", it.tag, seoDateBg(date), it.role];
    lede = it.p || "";
  } else if (kind === "episodes") {
    title = "Епизод " + (it.n || "") + ": " + it.t + " | Подкаст Men In A Movie";
    metaBits = ["Подкаст", it.n ? "Епизод " + it.n : "", seoDateBg(date), it.tag];
    lede = it.desc || "";
  } else {
    title = it.t + (it.when ? " — " + seoDateBg(it.when) : "") + " | Movie calendar";
    metaBits = [CK[it.kind] || "Movie calendar", seoDateBg(it.when), it.platform, it.place, it.organizer];
    lede = it.p || "";
    if (it.ticketUrl) extra += '<a class="btn gold" rel="nofollow" href="' + escHtml(it.ticketUrl) + '">Билети</a>';
  }
  const vid = it.video || it.yt || "";
  if (vid) extra += '<a class="btn" rel="nofollow" href="' + escHtml(vid) + '">Гледай видеото</a>';

  const ckind = SEO_SHARE[kind];
  const countable = !!ckind;
  const likeHTML = () => countable
    ? '<button class="btn like" id="lk" type="button" aria-label="Харесай">' +
      '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">' +
      '<path d="M20.8 5.6a5.5 5.5 0 0 0-7.8 0L12 6.6l-1-1a5.5 5.5 0 0 0-7.8 7.8l1 1L12 22l7.8-7.6 1-1a5.5 5.5 0 0 0 0-7.8z"/></svg>' +
      '<span id="lkn"></span></button>'
    : "";
  /* същите ключове като на сайта, за да е едно и също сърце и един и същ брояч */
  const countJs = countable
    ? "<script>(function(){var KIND=" + JSON.stringify(ckind) + ",ID=" + JSON.stringify(String(it.id)) +
      ",K=KIND+':'+ID,B=document.getElementById('lk'),N=document.getElementById('lkn');" +
      "function rd(s,k){try{return JSON.parse(s.getItem(k)||'{}')}catch(e){return{}}}" +
      "function mine(){return !!rd(localStorage,'mim-likes')[K]}" +
      "function paint(n){if(n!=null&&N)N.textContent=n||'';if(!B)return;B.classList.toggle('on',mine());" +
      "var v=B.querySelector('svg');if(v)v.setAttribute('fill',mine()?'currentColor':'none')}" +
      "function hit(o){return fetch('/api/hit',{method:'POST',headers:{'content-type':'application/json'}," +
      "body:JSON.stringify(o)}).then(function(r){return r.ok?r.json():null}).catch(function(){return null})}" +
      "paint(null);" +
      "fetch('/api/stats',{cache:'no-store'}).then(function(r){return r.ok?r.json():null})" +
      ".then(function(j){if(j)paint((j.likes||{})[K]||0)}).catch(function(){});" +
      "if(B)B.addEventListener('click',function(){var on=!mine();var m=rd(localStorage,'mim-likes');" +
      "if(on)m[K]=1;else delete m[K];try{localStorage.setItem('mim-likes',JSON.stringify(m))}catch(e){}" +
      "paint(null);hit({kind:KIND,id:ID,like:on}).then(function(j){if(j)paint(j.likes)})});" +
      "try{var seen=rd(sessionStorage,'mim-seen');if(!seen[K]){seen[K]=1;" +
      "sessionStorage.setItem('mim-seen',JSON.stringify(seen));hit({kind:KIND,id:ID})}}catch(e){}" +
      "})();<\/script>"
    : "";

  const bodyTxt = kind === "episodes" ? it.desc : (kind === "calendar" ? it.p : it.body);
  const html =
    '<p class="kicker">' + escHtml(SEO_LABEL[kind]) + "</p>" +
    "<h1>" + escHtml(it.t) + "</h1>" +
    '<p class="meta">' + escHtml(metaBits.filter(Boolean).join(" • ")) + "</p>" +
    (image && !/\/og\.jpg$/.test(image) ? '<figure><img src="' + escHtml(image) + '" alt="' + escHtml(it.t) + '" loading="lazy" onerror="this.parentNode.remove()"></figure>' : "") +
    (lede ? '<p class="lede">' + escHtml(plain(lede, 400)) + "</p>" : "") +
    seoBody(bodyTxt) +
    (it.authorName ? '<p class="sig">— ' + escHtml(it.authorName) + "</p>" : "") +
    tagChipsHTML(it, bigTags) +
    '<div class="btns">' + likeHTML() + '<a class="btn gold" href="/#' + SEO_ANCHOR[kind] + '">Виж всичко в „' + escHtml(SEO_LABEL[kind]) + '“</a>' + extra + "</div>" +
    seoRelated(data, kind, it, 7);

  return seoShell({
    title, desc: seoDesc(it, 180), canon, image, ogType: "article",
    keywords: itemTags(it).map((t) => t.name).join(", "),
    head: seoJsonLd(kind, it, origin, canon, image),
    body: html + countJs,
  });
}

function seoTagPage(tag, data, origin) {
  const canon = origin + "/tema/" + tag.slug;
  const byKind = {};
  for (const x of tag.items) (byKind[x.kind] = byKind[x.kind] || []).push(x);
  const sections = Object.keys(SEO_PATH).filter((k) => (byKind[k] || []).length).map((k) =>
    "<h2>" + escHtml(SEO_LABEL[k]) + "</h2><ul>" +
    byKind[k].map((x) => '<li><a href="' + x.url + '">' + escHtml(x.it.t) + "</a>" +
      "<small>" + escHtml(SEO_LABEL[x.kind]) +
      (seoDate(x.kind, x.it) ? " · " + escHtml(seoDateBg(seoDate(x.kind, x.it))) : "") + "</small></li>").join("") +
    "</ul>").join("");
  const others = seoTagList(data).filter((t) => t.slug !== tag.slug).slice(0, 14);
  const ld = {
    "@context": "https://schema.org", "@type": "CollectionPage",
    name: tag.name + " — Men In A Movie", url: canon, inLanguage: "bg-BG",
    description: "Всичко за " + tag.name + " в Men In A Movie: " + tag.items.length + " материала.",
    isPartOf: { "@type": "WebSite", name: "Men In A Movie", url: origin + "/" },
    mainEntity: {
      "@type": "ItemList", numberOfItems: tag.items.length,
      itemListElement: tag.items.slice(0, 30).map((x, i) => ({
        "@type": "ListItem", position: i + 1, name: x.it.t, url: origin + x.url,
      })),
    },
  };
  const body =
    '<p class="kicker">Тема</p><h1>' + escHtml(tag.name) + "</h1>" +
    '<p class="meta">' + tag.items.length + " материала в Men In A Movie</p>" +
    '<div class="rel" style="border:0;margin:0;padding:0">' + sections + "</div>" +
    (others.length
      ? '<div class="tags" style="margin-top:38px"><span>Още теми:</span>' +
        others.map((t) => '<a class="tag" href="/tema/' + t.slug + '">' + escHtml(t.name) + "</a>").join("") + "</div>"
      : "");
  return seoShell({
    title: tag.name + " — всичко по темата | Men In A Movie",
    desc: "Ревюта, новини и епизоди за " + tag.name + " в Men In A Movie. " + tag.items.length + " материала.",
    canon, image: origin + "/og.jpg", ogType: "website",
    keywords: tag.name,
    head: '<script type="application/ld+json">' + JSON.stringify(ld).replace(/</g, "\\u003c") + "</script>",
    body,
  });
}

function seoMapPage(data, origin) {
  const all = seoAll(data);
  const byKind = {};
  for (const x of all) (byKind[x.kind] = byKind[x.kind] || []).push(x);
  const sections = Object.keys(SEO_PATH).filter((k) => (byKind[k] || []).length).map((k) =>
    "<h2>" + escHtml(SEO_LABEL[k]) + "</h2><ul>" +
    byKind[k].map((x) => '<li><a href="' + x.url + '">' + escHtml(x.it.t) + "</a>" +
      (seoDate(x.kind, x.it) ? " <small>" + escHtml(seoDateBg(seoDate(x.kind, x.it))) + "</small>" : "") + "</li>").join("") +
    "</ul>").join("");
  const tags = seoTagList(data);
  const body =
    '<p class="kicker">Карта на сайта</p><h1>Всички материали</h1>' +
    '<p class="meta">' + all.length + " материала · Men In A Movie</p>" +
    (tags.length
      ? '<div class="tags" style="margin:0 0 34px;border-top:0;padding-top:0"><span>Теми:</span>' +
        tags.map((t) => '<a class="tag" href="/tema/' + t.slug + '">' + escHtml(t.name) + " (" + t.items.length + ")</a>").join("") + "</div>"
      : "") +
    '<div class="rel" style="border:0;margin:0;padding:0">' + (sections || "<p>Още няма публикувани материали.</p>") + "</div>";
  return seoShell({
    title: "Карта на сайта — всички материали | Men In A Movie",
    desc: "Пълен списък с ревютата, новините, епизодите и календара с премиери на Men In A Movie.",
    canon: origin + "/karta", image: origin + "/og.jpg", ogType: "website", body,
  });
}

function seoSitemap(data, origin) {
  const rows = ['<url><loc>' + origin + '/</loc><changefreq>daily</changefreq><priority>1.0</priority></url>',
                '<url><loc>' + origin + '/karta</loc><changefreq>daily</changefreq><priority>0.5</priority></url>'];
  for (const x of seoAll(data)) {
    const d = seoDate(x.kind, x.it);
    rows.push("<url><loc>" + origin + x.url + "</loc>" + (d ? "<lastmod>" + d + "</lastmod>" : "") +
      "<changefreq>weekly</changefreq><priority>0.8</priority></url>");
  }
  for (const t of seoTagList(data))
    rows.push("<url><loc>" + origin + "/tema/" + t.slug + "</loc><changefreq>weekly</changefreq><priority>0.6</priority></url>");
  return '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n' +
    rows.join("\n") + "\n</urlset>\n";
}

/* Търсачките и ботовете, които ЦИТИРАТ, минават. Чисто обучаващите — не. */
function seoRobots(origin) {
  const cite = ["Googlebot","Bingbot","OAI-SearchBot","ChatGPT-User","PerplexityBot","Perplexity-User",
                "Claude-SearchBot","Claude-User","Applebot","DuckDuckBot","YandexBot","Amazonbot"];
  const train = ["GPTBot","CCBot","Bytespider","meta-externalagent","FacebookBot","Google-Extended",
                 "Applebot-Extended","ClaudeBot","anthropic-ai","cohere-ai","Diffbot","Omgilibot","Timpibot","AI2Bot"];
  return "User-agent: *\nAllow: /\nDisallow: /api/\n\n" +
    cite.map((b) => "User-agent: " + b + "\nAllow: /\n").join("\n") + "\n" +
    train.map((b) => "User-agent: " + b + "\nDisallow: /\n").join("\n") +
    "\nSitemap: " + origin + "/sitemap.xml\n";
}

/* data:image/... → същинските байтове */
function dataUriToResponse(uri) {
  const m = /^data:([^;,]+);base64,(.*)$/s.exec(String(uri || ""));
  if (!m) return null;
  const bin = atob(m[2]);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new Response(bytes, {
    headers: { "content-type": m[1], "cache-control": "public, max-age=300" },
  });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // един адрес: www.meninamovie.com → meninamovie.com
    if (url.hostname.startsWith("www.")) {
      const to = new URL(url.toString());
      to.hostname = url.hostname.slice(4);
      return Response.redirect(to.toString(), 301);
    }

    /* ---------- как се влиза ---------- */
    if (path === "/api/auth") {
      if (request.method === "GET") {
        const rec = await authRecord(env);
        const has = !!(rec && rec.users.length);
        return json({ mode: has ? "password" : "key", set: has });
      }
      if (request.method === "POST") {
        let body = {};
        try {
          body = await request.json();
        } catch (e) {}
        const email = normMail(body.email);
        const password = String(body.password || "");
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email))
          return json({ error: "bad_email", message: "Имейлът не изглежда истински." }, 400);
        if (password.length < 8)
          return json({ error: "weak", message: "Паролата трябва да е поне 8 знака." }, 400);

        const rec = await authRecord(env);
        const data = await stored(env);
        const who = await whoIs(request, env, data);

        // Смяна на достъпа може: собственикът, или първият човек, ако още няма зададен достъп
        if (rec && rec.users.length) {
          if (!who || who.role !== "admin")
            return json({ error: "forbidden", message: "Само администраторът сменя достъпа." }, 403);
        } else if (!who && data) {
          return json({ error: "forbidden", message: "Влез първо с ключа." }, 403);
        }

        const salt = randHex(16);
        const hash = await hashPassword(password, salt);
        const owner = {
          id: "owner",
          email,
          name: String(body.name || "Администратор").trim() || "Администратор",
          role: "admin",
          salt,
          hash,
        };
        const rest = rec ? rec.users.filter((u) => u.id !== "owner") : [];
        await saveAuth(env, { users: [owner, ...rest] });
        return json({ ok: true, email });
      }
      return json({ error: "method" }, 405);
    }

    /* ---------- влизане ---------- */
    if (path === "/api/login" && request.method === "POST") {
      let body = {};
      try {
        body = await request.json();
      } catch (e) {}
      const rec = await authRecord(env);
      const data = await stored(env);

      // резервен вход: ключът ADMIN_KEY от Cloudflare влиза винаги,
      // за да има как да се влезе при забравена парола
      const rescue = String(body.key || "").trim();
      if (rescue && env.ADMIN_KEY && sameString(rescue, env.ADMIN_KEY)) {
        const who = { role: "admin", id: "owner", name: "Администратор" };
        const token = await newSession(env, who);
        return json(Object.assign({ token, rescue: true }, who));
      }

      if (rec && rec.users.length) {
        const email = normMail(body.email);
        const password = String(body.password || "");
        const u = rec.users.find((x) => normMail(x.email) === email);
        if (!u) return json({ error: "bad_login" }, 401);
        const hash = await hashPassword(password, u.salt);
        if (!sameString(hash, u.hash)) return json({ error: "bad_login" }, 401);
        const who = { role: u.role || "author", id: u.id, name: u.name || "Потребител", email: u.email };
        const token = await newSession(env, who);
        return json(Object.assign({ token }, who));
      }

      // още няма имейл и парола — влиза се с ключ
      const key = String(body.key || "").trim();
      const who = identifyKey(key, data, env);
      if (who) {
        const token = await newSession(env, who);
        return json(Object.assign({ token }, who));
      }
      if (!data && !env.ADMIN_KEY && key) {
        const first = { role: "admin", id: "owner", name: "Администратор" };
        const token = await newSession(env, first);
        return json(Object.assign({ token, bootstrap: true }, first));
      }
      return json({ error: "bad_key" }, 401);
    }

    /* ---------- хората ---------- */
    if (path === "/api/users") {
      const data = await stored(env);
      const who = await whoIs(request, env, data);
      if (!who || who.role !== "admin")
        return json({ error: "forbidden", message: "Само администраторът вижда хората." }, 403);
      const rec = (await authRecord(env)) || { users: [] };

      if (request.method === "GET") return json({ users: safeUsers(rec) });

      if (request.method === "POST") {
        let body = {};
        try {
          body = await request.json();
        } catch (e) {}
        const act = String(body.act || "save");

        if (act === "delete") {
          const id = String(body.id || "");
          if (id === "owner") return json({ error: "owner", message: "Собственикът не се трие." }, 400);
          rec.users = rec.users.filter((u) => u.id !== id);
          await saveAuth(env, rec);
          return json({ ok: true, users: safeUsers(rec) });
        }

        const email = normMail(body.email);
        const name = String(body.name || "").trim();
        let role = String(body.role || "author");
        if (ROLES.indexOf(role) < 0) role = "author";
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email))
          return json({ error: "bad_email", message: "Имейлът не изглежда истински." }, 400);
        if (!name) return json({ error: "no_name", message: "Сложи име." }, 400);

        const id = String(body.id || "") || "u" + randHex(6);
        const taken = rec.users.find((u) => normMail(u.email) === email && u.id !== id);
        if (taken) return json({ error: "taken", message: "Този имейл вече е зает." }, 400);

        const old = rec.users.find((u) => u.id === id);
        if (old && old.id === "owner") role = "admin";

        const password = String(body.password || "");
        if (!old && password.length < 8)
          return json({ error: "weak", message: "Паролата трябва да е поне 8 знака." }, 400);
        if (password && password.length < 8)
          return json({ error: "weak", message: "Паролата трябва да е поне 8 знака." }, 400);

        let salt = old ? old.salt : null;
        let hash = old ? old.hash : null;
        if (password) {
          salt = randHex(16);
          hash = await hashPassword(password, salt);
        }
        const rec2 = { id, email, name, role, salt, hash };
        rec.users = old ? rec.users.map((u) => (u.id === id ? rec2 : u)) : rec.users.concat([rec2]);
        await saveAuth(env, rec);
        return json({ ok: true, users: safeUsers(rec) });
      }
      return json({ error: "method" }, 405);
    }

    /* ---------- съдържание ---------- */
    if (path === "/api/content") {
      if (request.method === "GET") {
        const data = await stored(env);
        if (!data) return new Response(null, { status: 204, headers: { "cache-control": "no-store" } });
        const pub = publicCopy(data);
        if (url.searchParams.get("full") === "1") {
          const who = await whoIs(request, env, data);
          if (!who) return json({ error: "forbidden" }, 403);
          return json(pub);                       // с всички снимки вътре — за резервното копие
        }
        return json(liftImages(pub));
      }

      if (request.method === "POST") {
        const prev = await stored(env);
        const who = await whoIs(request, env, prev);
        const rec = await authRecord(env);

        // първи запис, когато хранилището е празно и още няма зададен достъп
        const bootstrap = !prev && !env.ADMIN_KEY && !(rec && rec.users.length);

        if (!who && !bootstrap) return json({ error: "bad_key", message: "Непознат достъп." }, 401);
        const roleOk = !who || who.role === "admin" || who.role === "moderator" || who.role === "author";
        if (!roleOk) return json({ error: "forbidden", message: "Тази роля не записва на сайта." }, 403);

        let body;
        try {
          body = await request.json();
        } catch (e) {
          return json({ error: "bad_json", message: "Невалидни данни." }, 400);
        }
        if (!body || typeof body !== "object" || !body.settings)
          return json({ error: "bad_shape", message: "Данните не приличат на съдържание на сайта." }, 400);

        // авторът стига само до собствените си материали
        const shaped = who && who.role === "author" ? authorMerge(body, prev, who) : body;
        const merged = keepImages(keepSecrets(shaped, prev), prev);
        const text = JSON.stringify(merged);
        if (text.length > 20 * 1024 * 1024)
          return json({ error: "too_large", message: "Съдържанието е над 20 MB." }, 413);

        if (prev) await env.MIM.put("content-prev", JSON.stringify(prev));
        await env.MIM.put("content", text);
        return json({
          ok: true, at: Date.now(), by: who ? who.role : "bootstrap",
          scope: who && who.role === "author" ? "own" : "all",
        });
      }

      return json({ error: "method" }, 405);
    }

    /* обновяване на календара — ръчно от админа */
    if (path === "/api/calendar/sync" && request.method === "POST") {
      const data = (await stored(env)) || {};
      const who = await whoIs(request, env, data);
      if (!who || (who.role !== "admin" && who.role !== "moderator"))
        return json({ error: "forbidden", message: "Само администратор и модератор обновяват календара." }, 403);
      let body = {};
      try { body = await request.json(); } catch (e) {}
      const res = await syncCalendar(env, +body.months || 3);
      return json(res, res.error ? 400 : 200);
    }

    /* брои преглед или харесване: POST /api/hit {kind,id,like} */
    if (path === "/api/hit" && request.method === "POST") {
      let body = {};
      try { body = await request.json(); } catch (e) {}
      const kind = String(body.kind || "");
      const id = String(body.id || "").slice(0, 64);
      if (!COUNT_KINDS[kind] || !id) return json({ error: "bad" }, 400);
      const key = kind + ":" + id;
      const isLike = body.like === true || body.like === false;
      if (body.like === true) bump(key, "likes", 1);
      else if (body.like === false) bump(key, "likes", -1);
      else bump(key, "views", 1);
      /* Харесванията са рядко събитие и всяко има значение — записват се веднага.
         Отварянията са честите; те чакат буфера, за да не изядат лимита на KV. */
      if (isLike) await flushCounters(env, true);
      else ctx.waitUntil(flushCounters(env, false));
      const c = merged(await counters(env));
      return json({ ok: true, views: c.views[key] || 0, likes: c.likes[key] || 0 });
    }

    /* всички броячи наведнъж — сайтът ги ползва за сърцата, админът за таблото */
    if (path === "/api/stats" && request.method === "GET") {
      const c = merged(await counters(env));
      return new Response(JSON.stringify(c), {
        headers: { "content-type": "application/json; charset=utf-8", "cache-control": "public, max-age=60" },
      });
    }

    /* картинката на един материал — за визитката при споделяне */
    if (path.startsWith("/img/")) {
      if (url.searchParams.get("v")) {
        const hit = await caches.default.match(request);
        if (hit) return hit;
      }
      const parts = path.split("/").filter(Boolean); // img, kind, id
      const kindKey = parts[1], id = decodeURIComponent(parts[2] || "");
      if (!KINDS[kindKey]) return new Response("no", { status: 404 });
      const data = await stored(env);
      const it = findItem(data, kindKey, id);
      if (!it) return new Response("no", { status: 404 });
      const yt = ytIdOf(it.yt || it.video);
      const img = itemImage(it);
      if (!img && yt) return Response.redirect("https://i.ytimg.com/vi/" + yt + "/maxresdefault.jpg", 302);
      const resp = img && dataUriToResponse(img);
      if (resp) {
        if (url.searchParams.get("v")) {
          resp.headers.set("cache-control", "public, max-age=31536000, immutable");
          ctx.waitUntil(caches.default.put(request, resp.clone()));
        }
        return resp;
      }
      if (img) return Response.redirect(img, 302);
      return Response.redirect(new URL("/og.jpg", url).toString(), 302);
    }

    /* robots.txt — кой бот какво може */
    if (path === "/robots.txt") {
      return new Response(seoRobots(url.origin), {
        headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "public, max-age=3600" },
      });
    }

    /* карта на сайта за търсачките */
    if (path === "/sitemap.xml") {
      const data = (await stored(env)) || {};
      return new Response(seoSitemap(data, url.origin), {
        headers: { "content-type": "application/xml; charset=utf-8", "cache-control": "public, max-age=900" },
      });
    }

    /* карта на сайта за хората и за обхождането */
    if (path === "/karta" || path === "/karta/") {
      const data = (await stored(env)) || {};
      return new Response(seoMapPage(data, url.origin), {
        headers: { "content-type": "text/html; charset=utf-8", "cache-control": "public, max-age=600" },
      });
    }

    /* страница на тема: /tema/dyun */
    if (path.startsWith("/tema/") || path === "/tema") {
      const data = (await stored(env)) || {};
      const slug = decodeURIComponent(path.split("/").filter(Boolean)[1] || "");
      const tag = seoTagList(data).find((t) => t.slug === slug);
      if (!tag) return Response.redirect(url.origin + "/karta", 302);
      return new Response(seoTagPage(tag, data, url.origin), {
        headers: { "content-type": "text/html; charset=utf-8", "cache-control": "public, max-age=600" },
      });
    }

    /* истинска страница за всеки материал: /revyu/dyun-chast-vtora-r1 */
    {
      const seg = path.split("/").filter(Boolean);
      const kind = Object.keys(SEO_PATH).find((k) => SEO_PATH[k] === seg[0]);
      if (kind && seg.length >= 2) {
        const data = (await stored(env)) || {};
        const it = seoFind(data, kind, decodeURIComponent(seg[1]));
        if (!it) return Response.redirect(url.origin + "/#" + SEO_ANCHOR[kind], 302);
        const good = seoUrl(kind, it);
        if (path !== good) return Response.redirect(url.origin + good, 301);
        return new Response(seoItemPage(kind, it, data, url.origin), {
          headers: { "content-type": "text/html; charset=utf-8", "cache-control": "public, max-age=600" },
        });
      }
      if (kind && seg.length === 1) return Response.redirect(url.origin + "/#" + SEO_ANCHOR[kind], 302);
    }

    /* адрес за споделяне: показва визитка на ботовете, човека праща в сайта */
    if (path.startsWith("/s/")) {
      const parts = path.split("/").filter(Boolean); // s, kind, id
      const kindKey = parts[1], id = decodeURIComponent(parts[2] || "");
      const data = await stored(env);
      const it = KINDS[kindKey] ? findItem(data, kindKey, id) : null;
      const site = (data && data.settings) || {};
      const origin = url.origin;
      /* вече има истински адрес — пращаме там, за да не се дели силата на две */
      if (it && KINDS[kindKey] && SEO_PATH[KINDS[kindKey]] && seoLive(KINDS[kindKey], it))
        return Response.redirect(origin + seoUrl(KINDS[kindKey], it), 301);
      const target = origin + "/#/" + kindKey + "/" + encodeURIComponent(id);
      if (!it) return Response.redirect(origin + "/", 302);
      const title = it.t || "Men In A Movie";
      const desc = plain(it.verdict || it.p || it.desc || it.body || "", 200);
      const image = origin + "/img/" + kindKey + "/" + encodeURIComponent(id);
      const html =
        '<!doctype html><html lang="bg"><head><meta charset="utf-8">' +
        '<meta name="viewport" content="width=device-width, initial-scale=1">' +
        "<title>" + escHtml(title) + " — Men In A Movie</title>" +
        '<meta name="description" content="' + escHtml(desc) + '">' +
        '<link rel="canonical" href="' + escHtml(target) + '">' +
        '<meta property="og:type" content="article">' +
        '<meta property="og:site_name" content="Men In A Movie">' +
        '<meta property="og:locale" content="bg_BG">' +
        '<meta property="og:url" content="' + escHtml(target) + '">' +
        '<meta property="og:title" content="' + escHtml(title) + '">' +
        '<meta property="og:description" content="' + escHtml(desc) + '">' +
        '<meta property="og:image" content="' + escHtml(image) + '">' +
        '<meta property="og:image:alt" content="' + escHtml(title) + '">' +
        '<meta name="twitter:card" content="summary_large_image">' +
        '<meta name="twitter:title" content="' + escHtml(title) + '">' +
        '<meta name="twitter:description" content="' + escHtml(desc) + '">' +
        '<meta name="twitter:image" content="' + escHtml(image) + '">' +
        '<meta http-equiv="refresh" content="0; url=' + escHtml(target) + '">' +
        '<style>body{background:#0A0908;color:#F6F2E6;font-family:system-ui,sans-serif;display:grid;place-items:center;height:100vh;margin:0}a{color:#F6C92B}</style>' +
        "</head><body><p>Отваряме „" + escHtml(title) + "“ — <a href=\"" + escHtml(target) + '">натисни тук, ако не стане само</a>.</p>' +
        '<script>location.replace(' + JSON.stringify(target) + ")<\/script></body></html>";
      return new Response(html, { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "public, max-age=120" } });
    }

    const assets = env.ASSETS || env.assets;
    if (!assets) return new Response("Няма вързани статични файлове (binding ASSETS).", { status: 500 });
    const res = await assets.fetch(request);
    // страницата да не се кешира: иначе новата версия не стига до хората
    const ct = res.headers.get("content-type") || "";
    if (ct.includes("text/html")) {
      const out = new Response(res.body, res);
      out.headers.set("cache-control", "no-cache, must-revalidate");
      return out;
    }
    return res;
  },

  /* по график: веднъж месечно обновяваме календара и записваме броячите */
  async scheduled(event, env, ctx) {
    ctx.waitUntil(
      (async () => {
        await flushCounters(env, true);
        try { await syncCalendar(env, 3); } catch (e) {}
      })()
    );
  },
};
