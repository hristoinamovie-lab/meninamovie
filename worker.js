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
/* допълнителни снимки извън основното поле: кадър за споделяне и банери на рубриките */
const EXTRA_IMG = [{ key: "rs", kind: "reviews", field: "share" }];
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
  for (const x of EXTRA_IMG) {
    for (const it of data[x.kind] || []) {
      if (it && isDataUri(it[x.field]))
        it[x.field] = "/img/" + x.key + "/" + encodeURIComponent(it.id) + "?v=" + stamp(it[x.field]);
    }
  }
  for (const r of Object.keys(data.heads || {})) {
    const hd = data.heads[r];
    if (hd && isDataUri(hd.banner)) hd.banner = "/img/hd/" + encodeURIComponent(r) + "?v=" + stamp(hd.banner);
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
  for (const x of EXTRA_IMG) {
    const old = prev[x.kind] || [];
    for (const it of incoming[x.kind] || []) {
      if (!it || isDataUri(it[x.field])) continue;
      if (typeof it[x.field] === "string" && it[x.field].indexOf("/img/") === 0) {
        const o = old.find((y) => y && y.id === it.id);
        it[x.field] = o && isDataUri(o[x.field]) ? o[x.field] : "";
      }
    }
  }
  for (const r of Object.keys(incoming.heads || {})) {
    const hd = incoming.heads[r], o = (prev.heads || {})[r];
    if (hd && typeof hd.banner === "string" && hd.banner.indexOf("/img/") === 0)
      hd.banner = o && isDataUri(o.banner) ? o.banner : "";
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
const BACKDROP = "https://image.tmdb.org/t/p/w780";
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
    backdrop: t.backdrop_path ? BACKDROP + t.backdrop_path : "",
    p: (t.overview || "").slice(0, 320), platform: pv.name,
    sub: sub, season: season ? +season : null, episode: episode ? +episode : null,
    video: "", note: "",
  };
}

/** Първо видео от TMDB, дадено с приоритет на official trailer в YouTube. */
function tmdbPickTrailer(results) {
  if (!Array.isArray(results) || !results.length) return "";
  const yt = results.filter((r) => r.site === "YouTube");
  const v = yt.find((r) => r.type === "Trailer" && r.official) || yt.find((r) => r.type === "Trailer") || yt[0];
  return v ? "https://www.youtube.com/watch?v=" + v.key : "";
}
/** Трейлър + резюме (+ оценка на епизод, ако е приложимо) — тегли се при отваряне на страницата, не при синхронизацията. */
async function tmdbExtra(env, media, tmdbId, season, episode) {
  const out = { trailer: "", overview: "", rating: null };
  if (!env.TMDB_KEY || !tmdbId) return out;
  try {
    if (media === "movie") {
      const vids = await tmdbGet(env, "/movie/" + tmdbId + "/videos", { language: "bg-BG" });
      out.trailer = tmdbPickTrailer(vids.results) || tmdbPickTrailer((await tmdbGet(env, "/movie/" + tmdbId + "/videos", {})).results);
    } else if (season && episode) {
      const ep = await tmdbGet(env, "/tv/" + tmdbId + "/season/" + season + "/episode/" + episode, { language: "bg-BG" });
      out.overview = ep.overview || "";
      out.rating = ep.vote_average ? Math.round(ep.vote_average * 10) / 10 : null;
      try {
        const vids = await tmdbGet(env, "/tv/" + tmdbId + "/season/" + season + "/episode/" + episode + "/videos", { language: "bg-BG" });
        out.trailer = tmdbPickTrailer(vids.results);
      } catch (e) {}
    } else {
      const vids = await tmdbGet(env, "/tv/" + tmdbId + "/videos", { language: "bg-BG" });
      out.trailer = tmdbPickTrailer(vids.results);
    }
  } catch (e) {}
  return out;
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
        backdrop: m.backdrop_path ? BACKDROP + m.backdrop_path : "",
        p: (m.overview || "").slice(0, 320), video: "", note: "",
      });
      nMovies++;
    }
    if (!nMovies) notes.push("TMDB няма премиери за България в този период.");
  } catch (e) { notes.push("Филми: " + e.message); }
  // сериали по стрийминга — само с истинска дата на излъчване
  const lo = ymd(from), hi = ymd(to);
  /* Cloudflare пуска 50 запитвания в едно изпълнение. Едно вече отиде за филмите,
     всяка платформа взима по две за списъците — останалото се дели поравно между тях,
     за да не изяде първата платформа целия остатък и последните да останат празни. */
  const MAX_PROVIDERS = 12;
  const used = providers.length > MAX_PROVIDERS ? providers.slice(0, MAX_PROVIDERS) : providers;
  if (providers.length > MAX_PROVIDERS)
    notes.push("Платформите са " + providers.length + " — обновявам първите " + MAX_PROVIDERS + ".");
  const perPlatform = {};
  let budget = Math.max(0, 46 - 1 - used.length * 2);
  const share = Math.max(1, Math.floor(budget / Math.max(1, used.length)));
  for (const pv of used) {
    const before = nSeries;
    let mine = share;                    // дял от запитванията за тази платформа
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
        if (mine <= 0 || budget <= 0) break;
        if (fresh.some((f) => f.tmdbId === t.id && f.kind === "stream")) continue;
        mine--; budget--;
        let d = null;
        try { d = await tmdbGet(env, "/tv/" + t.id, { language: "bg-BG" }); } catch (e) { continue; }
        const ne = d && d.next_episode_to_air;
        if (!ne || !ne.air_date || ne.air_date < lo || ne.air_date > hi) continue;   // няма надеждна дата — не влиза
        const sub = +ne.episode_number === 1 ? "season" : "episode";
        fresh.push(tvItem(t, pv, sub, ne.air_date, ne.season_number, ne.episode_number));
        nSeries++;
      }
    } catch (e) { notes.push(pv.name + ": " + e.message); }

    perPlatform[pv.name] = nSeries - before;
  }
  const emptyPv = Object.keys(perPlatform).filter((n) => !perPlatform[n]);
  if (emptyPv.length && emptyPv.length < used.length)
    notes.push("Без обявени дати в TMDB: " + emptyPv.join(", ") + ".");
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
    movies: nMovies, series: nSeries, perPlatform: perPlatform,
    notes: notes, at: data.settings.calSyncedAt,
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
/* жанр може да е стар единичен низ или нов списък */
function genreArr(v) { return Array.isArray(v) ? v : (v ? [v] : []); }
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
  return plain(it.lead || it.verdict || it.p || it.desc || it.body || it.note || "", max || 200);
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

/* тагове от типа ![подпис](inline:N) → истинския адрес на снимката, пазена отделно в it.inlineImages */
function resolveInlineImages(text, images) {
  if (!images || !images.length) return text;
  return String(text || "").replace(/\(inline:(\d+)\)/g, (m, idx) => {
    const img = images[+idx];
    return img && img.data ? "(" + img.data + ")" : m;
  });
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
    const img = /^!\[([^\]]*)\]\(([^)\s]+)\)$/.exec(line);
    if (img) { if (list) { out.push("<ul>" + list.join("") + "</ul>"); list = null; }
      out.push('<figure><img src="' + esc(img[2]) + '" alt="' + esc(img[1]) + '" loading="lazy">' + (img[1] ? "<figcaption>" + esc(img[1]) + "</figcaption>" : "") + "</figure>"); continue; }
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

/* movie calendar: същият текст като на сайта, за да не се разминават */
function calCat(c) {
  if (c.kind === "event") return c.organizer || "Събитие";
  if (c.kind === "stream") return c.platform || "Стрийминг";
  return "По кината";
}
function calSubLabel(c) {
  if (String(c.note || "").trim()) return c.note;
  if (c.sub === "series") return "Нов сериал";
  if (c.sub === "season") return c.season ? "Сезон " + c.season : "Нов сезон";
  if (c.sub === "episode") return c.season && c.episode ? "S" + c.season + " · E" + c.episode : "Нов епизод";
  return "";
}
function calReviewFor(data, it) {
  const t = String(it.t || "").trim().toLowerCase();
  if (!t) return null;
  return (data.reviews || []).find((r) => seoLive("reviews", r) && String(r.t || "").trim().toLowerCase() === t) || null;
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
      itemReviewed: { "@type": "Movie", name: it.t, ...(it.y ? { dateCreated: String(it.y) } : {}), ...(genreArr(it.g).length ? { genre: genreArr(it.g) } : {}) },
      reviewRating: { "@type": "Rating", ratingValue: String(it.s || ""), bestRating: "5", worstRating: "1" },
      reviewBody: plain(it.body, 1500),
    });
    if (!it.s) delete node.reviewRating;
  } else if (kind === "news") {
    node = Object.assign({}, base, { "@type": "NewsArticle", articleSection: it.cat || it.tag || "Новини" });
  } else if (kind === "craft") {
    node = Object.assign({}, base, { "@type": "Article", articleSection: it.cat || it.tag || "Зад кадър" });
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
const SEO_CSS = `*{box-sizing:border-box;border-radius:0}
body{margin:0;background:#0A0908;color:#F2F0EB;font-family:Manrope,system-ui,-apple-system,"Segoe UI",sans-serif;line-height:1.7;font-size:17px}
img{display:block;max-width:100%}
a{color:#F6C92B;text-decoration:none}
.wrap{max-width:1180px;margin:0 auto;padding:0 22px}
.ital{font-family:Montserrat,system-ui,sans-serif;font-weight:900;font-style:italic;text-transform:uppercase;letter-spacing:-.02em}

/* ---- хедър като на сайта ---- */
header.top{background:#F6C92B;color:#141210;position:sticky;top:0;z-index:205}
header.top .wrap{display:flex;align-items:center;gap:24px;min-height:62px;flex-wrap:wrap;row-gap:10px;padding-top:10px;padding-bottom:10px}
.brand{display:flex;align-items:center;gap:10px;color:#141210;text-decoration:none;flex:none}
.logo-mark{height:34px;width:auto;display:block;color:#141210}
.logo-mark path,.logo-mark rect{fill:currentColor}
.btxt b{display:block;font-family:Montserrat,system-ui,sans-serif;font-style:italic;font-weight:900;font-size:16px;letter-spacing:-.02em;text-transform:uppercase;line-height:1.1}
.btxt i{display:block;font-style:normal;font-family:Oswald,system-ui,sans-serif;font-size:9px;letter-spacing:.14em;text-transform:uppercase;opacity:.65;margin-top:3px}
nav.main{display:flex;gap:18px;flex-wrap:wrap}
nav.main a{font-family:Oswald,system-ui,sans-serif;font-weight:500;font-size:14px;letter-spacing:.06em;text-transform:uppercase;padding:4px 0;border-bottom:2px solid transparent;color:#141210}
nav.main a:hover{border-bottom-color:#141210}
.hbtns{display:flex;align-items:center;gap:22px;margin-left:auto;flex-wrap:wrap;row-gap:10px}
.sbtn{width:34px;height:34px;border:1px solid rgba(20,18,16,.35);background:none;color:#141210;cursor:pointer;display:grid;place-items:center;flex:none}
.sbtn:hover{background:rgba(20,18,16,.08)}
.btn-cal{display:inline-block;background:#141210;color:#F6C92B;font-family:Oswald,system-ui,sans-serif;font-size:12px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;padding:9px 16px;white-space:nowrap}
.btn-cal:hover{background:#000;color:#ffd84a}
.hmenu{display:none;width:38px;height:38px;border:1px solid rgba(20,18,16,.35);background:none;color:#141210;cursor:pointer;place-items:center;flex:none;margin-left:auto}
.hmenu:hover{background:rgba(20,18,16,.08)}
@media(max-width:900px){
  header.top{position:relative}
  header.top .wrap{flex-wrap:nowrap}
  .hmenu{display:grid}
  .hbtns{display:none;position:absolute;top:100%;left:0;right:0;margin-left:0;flex-direction:column;align-items:stretch;gap:0;background:#F6C92B;border-top:1px solid rgba(20,18,16,.15);padding:6px 20px 18px;box-shadow:0 12px 20px rgba(0,0,0,.15);z-index:220}
  .hbtns.open{display:flex}
  .hbtns nav.main{flex-direction:column;gap:0;width:100%}
  .hbtns nav.main a{padding:12px 2px;border-bottom:1px solid rgba(20,18,16,.1)}
  .hbtns .sbtn{align-self:flex-start;margin-top:12px}
  .hbtns .btn-cal{margin-top:12px;text-align:center}
}

/* ---- жълта лента на статията: текст/тагове/цитат/бутони вляво, снимка вдясно ---- */
.crumbs{font-size:11px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;opacity:.7;margin:0;padding-top:16px}
.band{background:#F6C92B;color:#141210;padding:2px 0 26px}
.band .in{display:flex;gap:26px;align-items:center;flex-wrap:wrap;min-height:30vh;padding-top:8px}
.band .side{flex:1 1 380px;min-width:280px}
.band .shot{flex:1 1 380px;min-width:280px;max-width:560px;aspect-ratio:16/9;background:#F6C92B;display:flex}
.band .shot img{width:100%;height:100%;object-fit:contain;margin:auto}
.band .shot.wide{flex:1 1 380px}
.band .kick{font-size:11px;font-weight:700;letter-spacing:.2em;text-transform:uppercase;opacity:.7}
.band h1{margin:.15em 0 .3em;font-size:30px;line-height:1.08;font-family:Montserrat,system-ui,sans-serif;font-weight:900;font-style:italic;text-transform:uppercase;letter-spacing:-.02em}
.band .facts{font-size:12px;font-weight:700;letter-spacing:.15em;text-transform:uppercase;opacity:.85}
.claps{display:flex;gap:5px;margin:10px 0 0}
.claps svg{width:20px;height:20px}
.claps-big{display:flex;gap:6px;justify-content:center;margin:32px 0 0}
.claps-big svg{width:26px;height:26px}
.band .tags{margin-top:14px}
.band .tags .lbl{color:rgba(20,18,16,.55)}
.band .tag{color:rgba(20,18,16,.6);border-color:rgba(20,18,16,.3)}
.band a.tag:hover{border-color:#141210;color:#141210}
.band .btns{margin-top:16px}
.band .btn{color:#141210;border-color:rgba(20,18,16,.35)}
.band .btn:hover{border-color:#141210;background:rgba(20,18,16,.08)}
.band .btn.like.on{border-color:#141210;color:#141210;background:rgba(20,18,16,.08)}
.band .btn.gold{background:#141210;border-color:#141210;color:#F6C92B}
.band .btn.gold:hover{background:#000}
@media(max-width:900px){.band .in{min-height:0;padding:20px 0}}

/* ---- лента на календар/ревю: без жълто, вертикален постер вдясно ---- */
.band.no-band{background:transparent;color:#F2F0EB}
.band.no-band .shot{aspect-ratio:2/3;min-width:0;max-width:280px;flex:0 0 260px;align-self:flex-start;background:#141210}
.band.no-band .shot img{object-fit:cover}
.band.no-band .lede{color:#F2F0EB;border-left-color:#F6C92B;font-size:22px;line-height:1.45;font-style:italic;border-left-width:5px;padding-left:18px;margin-top:22px}
.band.no-band h1{margin-top:14px}
.hl{display:inline-block;background:#F6C92B;color:#141210;font-family:Montserrat,system-ui,sans-serif;font-weight:900;font-style:italic;font-size:clamp(24px,4vw,40px);text-transform:uppercase;letter-spacing:-.02em;padding:.08em .34em .12em;box-shadow:5px 6px 0 rgba(0,0,0,.35);line-height:1.05}
.hl-stack .hl:nth-child(2){margin-left:16px}
.hl-stack .hl:nth-child(3){margin-left:32px}
.hl-notch{clip-path:polygon(0 0,100% 0,100% calc(100% - 13px),calc(100% - 13px) 100%,0 100%)}
.band.no-band .tag{color:#F6C92B;border-color:#2A2723}
.band.no-band a.tag:hover{border-color:#F6C92B;color:#141210;background:#F6C92B}
.band.no-band .btn{color:#F2F0EB;border-color:#2A2723}
.band.no-band .btn:hover{border-color:#F6C92B;background:none;color:#F6C92B}
.band.no-band .btn.like.on{border-color:#F6C92B;color:#F6C92B;background:none}
.band.no-band .btn.gold{background:#F6C92B;border-color:#F6C92B;color:#141210}
.band.no-band .btn.gold:hover{background:#ffd84a}
@media(max-width:900px){.band.no-band .shot{width:180px;max-width:180px;flex:none;margin:0 auto}}

/* ---- тяло ---- */
main{padding-bottom:30px}
.col{max-width:1180px;margin:0 auto;padding:30px 22px 0}
.lede{font-size:16px;line-height:1.5;border-left:4px solid rgba(20,18,16,.35);padding-left:16px;margin:14px 0 0;color:rgba(20,18,16,.75)}
.col h2{font-family:Montserrat,system-ui,sans-serif;font-weight:900;font-style:italic;text-transform:uppercase;font-size:23px;margin:1.7em 0 .5em;letter-spacing:-.01em}
.col p{margin:0 0 1.15em}
.col ul{padding-left:20px}
.col blockquote{border-left:4px solid #F6C92B;margin:1.4em 0;padding-left:18px;color:#B9B3A6}
.col figure{margin:1.8em 0}
.col figure img{width:100%}
.col figcaption{font-size:13px;color:#8C877C;margin-top:7px}
.col a{border-bottom:1px solid rgba(246,201,43,.45)}
.sig{margin:26px 0 0;padding-top:16px;border-top:1px solid rgba(246,242,230,.14);color:#B9B3A6}
.kicker{font-size:11px;font-weight:700;letter-spacing:.2em;text-transform:uppercase;color:#F6C92B;margin:0 0 8px}
.meta{font-size:12px;font-weight:700;letter-spacing:.14em;text-transform:uppercase;color:#8C877C;margin:0 0 20px}

/* ---- бутони, тагове ---- */
.btns{display:flex;gap:9px;flex-wrap:wrap;margin:26px 0 0;align-items:center}
.btn{display:inline-flex;align-items:center;gap:7px;border:1px solid rgba(246,242,230,.25);color:#F2F0EB;font-size:12px;font-weight:700;letter-spacing:.13em;text-transform:uppercase;padding:11px 17px;background:none;cursor:pointer;font-family:inherit}
.btn:hover{border-color:#F6C92B;color:#F6C92B}
.btn.gold{background:#F6C92B;border-color:#F6C92B;color:#141210}
.btn.gold:hover{background:#ffd84a;color:#141210}
.btn.like.on{border-color:#F6C92B;color:#F6C92B}
.tags{margin:26px 0 0;display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.tags .lbl{font-size:11px;font-weight:700;letter-spacing:.2em;text-transform:uppercase;color:#8C877C}
.tag{display:inline-block;font-size:11px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;padding:6px 12px;border:1px solid rgba(246,242,230,.22);color:#B9B3A6}
a.tag:hover{border-color:#F6C92B;color:#F6C92B}

/* ---- още по темата ---- */
.rel{max-width:1180px;margin:52px auto 0;padding:0 22px}
.rel h2{font-family:Montserrat,system-ui,sans-serif;font-weight:900;font-style:italic;text-transform:uppercase;font-size:24px;margin:0 0 16px;letter-spacing:-.01em}
.rel .grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}
.rel .card{background:#161412;border:1px solid rgba(246,242,230,.09);display:block;color:#F2F0EB}
.rel .card:hover{border-color:#F6C92B}
.rel .card .ph{width:100%;aspect-ratio:16/9;object-fit:cover;background:#0f0e0c}
.rel .card .ph.p{aspect-ratio:2/3}
.rel .card .tx{padding:11px 13px 15px}
.rel .card small{display:block;font-size:10px;font-weight:700;letter-spacing:.16em;text-transform:uppercase;color:#F6C92B;margin-bottom:6px}
.rel .card b{font-size:15px;line-height:1.32;font-weight:700}

/* ---- списъчни страници ---- */
.lbanner{background:#F6C92B;color:#141210}
.lbanner .wrap{display:flex;align-items:center;gap:20px;min-height:96px;padding-top:14px;padding-bottom:14px}
.lbanner h1{margin:0;flex:1;font-family:Montserrat,system-ui,sans-serif;font-weight:900;font-style:italic;text-transform:uppercase;font-size:40px;line-height:1;letter-spacing:-.03em}
.lbanner .cnt{font-size:11px;font-weight:700;letter-spacing:.18em;text-transform:uppercase;opacity:.7}
.lbanner img.bn{flex:0 0 40%;max-width:470px;aspect-ratio:4/1;object-fit:cover}
.list{max-width:1180px;margin:26px auto 0;padding:0 22px;display:flex;flex-direction:column;gap:12px}
.li{display:flex;gap:20px;background:#161412;border:1px solid rgba(246,242,230,.09);padding:14px;color:#F2F0EB;height:210px;overflow:hidden}
.li:hover{border-color:#F6C92B}
.li img{flex:0 0 28%;max-width:320px;height:100%;object-fit:cover;background:#0f0e0c}
.li img.p{flex:0 0 128px}
.li .tx{flex:1;min-width:0;min-height:0;display:flex;flex-direction:column}
.li h3{margin:0 0 8px;font-size:21px;line-height:1.25;font-family:Montserrat,system-ui,sans-serif;font-weight:900;font-style:italic;text-transform:uppercase;letter-spacing:-.015em;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.li p{margin:0;color:#B9B3A6;font-size:15px}
.li .more{display:inline-block;margin-top:auto;align-self:flex-end;flex:none;font-size:11px;font-weight:700;letter-spacing:.14em;text-transform:uppercase;background:#F6C92B;color:#141210;border:0;padding:9px 14px}
.li .more:hover{background:#ffd84a}

/* ---- grid карти: ревюта и movie calendar, с вертикални постери ---- */
.grid-cards{max-width:1180px;margin:26px auto 0;padding:0 22px;display:grid;grid-template-columns:repeat(4,1fr);gap:14px}
.rcard,.calcard{display:block;background:#161412;border:1px solid rgba(246,242,230,.09);color:#F2F0EB}
.rcard:hover,.calcard:hover{border-color:#F6C92B}
.rcard-art{position:relative;aspect-ratio:2/3;background:#0f0e0c}
.rcard-art img{width:100%;height:100%;object-fit:cover}
.rcard-art .claps{position:absolute;top:8px;right:8px;gap:2px;margin:0;background:rgba(10,9,8,.75);padding:4px 6px}
.rcard-art .claps svg{width:12px;height:12px}
.rcard .cbody,.calcard .cbody{padding:12px 13px 15px}
.rcard h3{margin:0 0 6px;font-size:15px;line-height:1.3;font-family:Montserrat,system-ui,sans-serif;font-weight:900;font-style:italic;text-transform:uppercase;letter-spacing:-.01em}
.rcard .kicker,.calcard .kicker{margin:0;color:#8C877C;font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase}
.calcard{position:relative}
.calcard-art{position:relative;aspect-ratio:2/3;background:#0f0e0c;overflow:hidden}
.calcard-art::after{content:"";position:absolute;inset:0;background:linear-gradient(to top,rgba(0,0,0,.75),transparent 42%)}
.calcard-art img{width:100%;height:100%;object-fit:cover}
.calcard-tab{position:absolute;top:0;left:0;z-index:2;background:#F6C92B;color:#141210;font-family:Oswald,system-ui,sans-serif;font-weight:600;font-size:9.5px;letter-spacing:.09em;text-transform:uppercase;padding:5px 11px 5px 8px}
.calcard-tab2{position:absolute;top:23px;left:0;z-index:2;background:#141210;color:#F6C92B;font-family:Oswald,system-ui,sans-serif;font-weight:600;font-size:9.5px;letter-spacing:.09em;text-transform:uppercase;padding:4px 10px 4px 8px}
.calcard-when{position:absolute;left:9px;bottom:9px;z-index:2;font-family:Oswald,system-ui,sans-serif;font-weight:600;font-size:10px;letter-spacing:.07em;text-transform:uppercase;color:#F6C92B}
.calcard h3{margin:0 0 4px;font-size:14px;line-height:1.3;font-weight:700}
@media(max-width:900px){.grid-cards{grid-template-columns:repeat(2,1fr)}}
.pcard{display:block;background:#161412;border:1px solid rgba(246,242,230,.09);color:#F2F0EB}
.pcard:hover{border-color:#F6C92B}
.pshot{position:relative;aspect-ratio:1/1;background:#0f0e0c;overflow:hidden}
.pshot img{width:100%;height:100%;object-fit:cover}
.pshot.dim img{opacity:.35}
.pbadge{position:absolute;top:9px;left:9px;font-family:Oswald,system-ui,sans-serif;font-size:10px;font-weight:700;letter-spacing:.09em;text-transform:uppercase;padding:5px 9px}
.pbadge.ok{background:#F6C92B;color:#141210}
.pbadge.out{background:#161412;color:#e07a76;border:1px solid #7a2320}

/* ---- мърч: e-shop продуктова страница ---- */
.shop-crumbs{max-width:1180px;margin:0 auto;padding:20px 22px 0;font-size:11px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#8C877C}
.shop-crumbs a{color:#8C877C}
.shop-grid{max-width:1180px;margin:0 auto;padding:22px 22px 44px;display:grid;grid-template-columns:minmax(0,480px) 1fr;gap:48px;align-items:start}
.shop-frame{aspect-ratio:1/1;background:#161412;border:1px solid rgba(246,242,230,.09);overflow:hidden}
.shop-frame img{width:100%;height:100%;object-fit:cover}
.shop-panel h1{font-family:Montserrat,system-ui,sans-serif;font-style:italic;font-weight:900;text-transform:uppercase;letter-spacing:-.02em;font-size:26px;margin:0 0 14px}
.shop-stockline{display:flex;align-items:center;gap:9px;margin-bottom:16px}
.shop-stockdot{width:8px;height:8px;border-radius:50%;background:#F6C92B}
.shop-stockdot.out{background:#e07a76}
.shop-stocktxt{font-family:Oswald,system-ui,sans-serif;font-size:12px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#F6C92B}
.shop-stocktxt.out{color:#e07a76}
.shop-price{font-family:Oswald,system-ui,sans-serif;font-weight:700;font-size:28px;margin:0 0 16px}
.shop-desc{color:#B9B3A6;font-size:15px;line-height:1.6;max-width:44ch;margin:0 0 20px}
.shop-cta{display:flex;align-items:center;justify-content:center;width:100%;max-width:320px;font-family:Oswald,system-ui,sans-serif;font-size:14px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;padding:16px 24px;background:#F6C92B;color:#141210;border:0;text-decoration:none}
.shop-cta:hover{background:#ffd84a}
.shop-cta[aria-disabled="true"]{background:#161412;color:#8C877C}
.shop-lower{max-width:1180px;margin:0 auto;padding:0 22px 60px}
.shop-lower h2{font-family:Montserrat,system-ui,sans-serif;font-style:italic;font-weight:900;text-transform:uppercase;font-size:19px;margin:0 0 14px;border-top:1px solid rgba(246,242,230,.09);padding-top:30px}
@media(max-width:860px){.shop-grid{grid-template-columns:1fr}}

.pager{max-width:1180px;margin:34px auto 0;padding:0 22px;display:flex;gap:7px;justify-content:center}
.pager a,.pager span{border:1px solid rgba(246,242,230,.2);color:#B9B3A6;font-size:13px;font-weight:700;padding:8px 14px}
.pager .cur{background:#F6C92B;border-color:#F6C92B;color:#141210}

/* ---- футър като на сайта ---- */
footer.bot{background:#F6C92B;color:#141210;margin-top:60px;padding:30px 0 34px;font-size:14px}
footer.bot a{color:#141210;text-decoration:none}
footer.bot a:hover{text-decoration:underline}
footer.bot .cols{display:grid;grid-template-columns:2fr 1fr 1fr 1fr;gap:26px}
footer.bot h4{font-size:11px;font-weight:700;letter-spacing:.2em;text-transform:uppercase;margin:0 0 12px;opacity:.75}
footer.bot .fin{margin-top:24px;padding-top:16px;border-top:1px solid rgba(20,18,16,.25);font-size:11px;letter-spacing:.1em;text-transform:uppercase;display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap}

@media(max-width:900px){
  .band .in{flex-direction:column}
  .band .shot,.band .shot.wide{flex:none;max-width:none;width:100%}
  .band h1{font-size:29px}
  .lbanner h1{font-size:28px}.lbanner img.bn{display:none}
  .rel .grid{grid-template-columns:repeat(2,1fr)}
  footer.bot .cols{grid-template-columns:1fr 1fr}
}
@media(max-width:560px){
  .li{flex-direction:column;height:auto}.li img,.li img.p{flex:none;width:100%;max-width:none;height:auto;aspect-ratio:16/9}
  .li img.p{width:140px;aspect-ratio:2/3}
  footer.bot .cols{grid-template-columns:1fr}
}`;

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
    '<link rel="icon" href="/favicon.svg" type="image/svg+xml">' +
    '<link rel="icon" href="/favicon-32.png" sizes="32x32" type="image/png">' +
    '<link rel="icon" href="/favicon-192.png" sizes="192x192" type="image/png">' +
    '<link rel="apple-touch-icon" href="/apple-touch-icon.png">' +
    '<link rel="alternate" type="application/rss+xml" title="Men In A Movie — RSS" href="/feed.xml">' +
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
    '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Montserrat:ital,wght@1,900&family=Oswald:wght@400;500;600&family=Manrope:wght@400;500;700&display=swap">' +
    "<style>" + SEO_CSS + "</style>" + (head || "") +
    "</head><body>" +
    SEO_HEADER +
    "<main>" + body + "</main>" +
    SEO_FOOTER +
    "</body></html>"
  );
}

const LOGO_SVG =
  '<svg class="logo-mark" viewBox="0 0 464.69 331.68" aria-hidden="true">' +
  '<g><path d="M136.71,279.21v-89.06l-23.57,89.06h-42.09l-26.89-89.06v89.06H1.2v-139.7h76.84l17.46,61.29,17.64-61.29h78.76v139.7h-55.18Z"/><path d="M205.16,279.21v-139.7h55.18v139.7h-55.18Z"/><path d="M409.13,279.21v-89.06l-23.57,89.06h-42.09l-26.89-89.06v89.06h-42.96v-139.7h76.84l17.46,61.29,17.64-61.29h78.76v139.7h-55.18Z"/></g>' +
  '<g><path d="M38.81,73.56l-2.11-23.33-4.06,23.89-11.02,1-9.16-22.69,2.11,23.33-11.25,1.02L0,40.18l20.13-1.82,6.03,15.64,3.17-16.47,20.63-1.87,3.32,36.59-14.45,1.31Z"/><path d="M56.56,71.95l-3.32-36.59,33.07-3,1,11.07-18.62,1.69.34,3.75,9.06-.82.63,7-9.06.82.34,3.75,18.62-1.69,1,11.02-33.07,3Z"/><path d="M117.8,66.4l-14.31-14.89,1.45,16.06-12.3,1.11-3.32-36.59,12.85-1.16,13.75,14.8-1.44-15.92,12.3-1.11,3.32,36.59-12.3,1.11Z"/><path d="M146.16,63.83l-3.32-36.59,14.46-1.31,3.32,36.59-14.46,1.31Z"/><path d="M189.25,59.93l-14.31-14.89,1.45,16.06-12.3,1.11-3.32-36.59,12.85-1.16,13.75,14.8-1.44-15.92,12.3-1.11,3.32,36.59-12.3,1.11Z"/><path d="M239.33,55.39l-1.99-4.62-11.71,1.06-1.12,4.9-12.03,1.09,10.27-37.83,14.5-1.31,17.08,35.35-15,1.36ZM229.75,33.66l-2.23,9.98,6.4-.58-4.17-9.4Z"/><path d="M300.62,49.84l-2.11-23.33-4.06,23.89-11.02,1-9.16-22.69,2.11,23.33-11.25,1.02-3.32-36.59,20.13-1.82,6.03,15.64,3.17-16.47,20.63-1.87,3.32,36.59-14.45,1.31Z"/><path d="M337.16,47.45c-10.48.95-19.76-6.88-20.72-17.49-.96-10.61,6.77-19.98,17.24-20.93,10.47-.95,19.76,6.88,20.72,17.49.96,10.61-6.77,19.98-17.24,20.93ZM334.65,19.78c-2.43.22-4.2,2.46-3.62,8.86.58,6.4,2.74,8.33,5.16,8.11,2.42-.22,4.2-2.5,3.62-8.91s-2.73-8.28-5.16-8.06Z"/><path d="M380.16,42.63l-11.57,1.05-17.08-35.35,15-1.36,7.81,18.52,4.08-19.6,12.03-1.09-10.27,37.83Z"/><path d="M395.8,41.22l-3.32-36.59,14.46-1.31,3.32,36.59-14.46,1.31Z"/><path d="M413.73,39.59l-3.32-36.59,33.07-3,1,11.07-18.62,1.69.34,3.75,9.06-.82.63,7-9.06.82.34,3.75,18.62-1.69,1,11.02-33.07,3Z"/></g>' +
  '<rect x=".98" y="303.18" width="463.63" height="28.5"/><rect x="1.06" y="87.7" width="463.63" height="28.5"/>' +
  '</svg>';

const SEO_HEADER =
  '<header class="top"><div class="wrap">' +
  '<a class="brand" href="/">' + LOGO_SVG + '<span class="btxt"><b>Men In A Movie</b><i>кино · подкаст · ревюта · новини</i></span></a>' +
  '<button class="hmenu" id="btnMenu" aria-label="Меню" aria-expanded="false">' +
  '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M3 6h18M3 12h18M3 18h18"/></svg>' +
  "</button>" +
  '<div class="hbtns" id="hbtns">' +
  '<nav class="main">' +
  '<a href="/novini">Новини</a><a href="/revyuta">Ревюта</a><a href="/podkast">Подкаст</a>' +
  '<a href="/zad-kadar">Зад кадър</a><a href="/march">Мърч</a><a href="/#za-nas">За нас</a>' +
  "</nav>" +
  '<button class="sbtn" aria-label="Търсене" title="Търсене">' +
  '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3"><circle cx="11" cy="11" r="7"/><path d="M20 20l-3.6-3.6"/></svg>' +
  "</button>" +
  '<a class="btn-cal" href="/kalendar">Movie calendar</a>' +
  "</div>" +
  "</div></header>" +
  '<script>(function(){var b=document.getElementById("btnMenu"),h=document.getElementById("hbtns");if(!b||!h)return;' +
  'b.addEventListener("click",function(){var o=h.classList.toggle("open");b.setAttribute("aria-expanded",o?"true":"false")});})();<\/script>';

const SEO_FOOTER =
  '<footer class="bot"><div class="wrap"><div class="cols">' +
  '<div><b class="ital" style="font-size:18px">Men In A Movie</b>' +
  "<p>Канал за комерсиално кино. Ревюта, подкаст и новини от индустрията — на български.</p></div>" +
  '<div><h4>Съдържание</h4><a href="/novini">Новини</a><br><a href="/revyuta">Ревюта</a><br>' +
  '<a href="/podkast">Подкаст</a><br><a href="/zad-kadar">Зад кадър</a><br><a href="/kalendar">Какво да гледам</a><br>' +
  '<a href="/karta">Карта на сайта</a></div>' +
  '<div><h4>Последвай ни</h4><a href="https://www.youtube.com/@meninamovie" rel="noopener">YouTube</a><br>' +
  '<a href="https://www.instagram.com/meninamovie" rel="noopener">Instagram</a></div>' +
  '<div><h4>Контакт</h4><a href="mailto:hristoinamovie@gmail.com">hristoinamovie@gmail.com</a></div>' +
  "</div>" +
  '<div class="fin"><span>© 2026 Men In A Movie</span>' +
  '<span>Данни за премиерите от <a href="https://www.themoviedb.org/" rel="noopener">TMDB</a>. ' +
  "This product uses the TMDB API but is not endorsed or certified by TMDB.</span></div>" +
  "</div></footer>";

/* клапите — същата оценка като на сайта */
function clapsHTML(n) {
  const full =
    '<svg viewBox="0 0 24 24" fill="#141210" aria-hidden="true"><path d="M2 8.6 20.4 3.6l1 3.7L4 12.3 2 8.6Z"/><path d="M6.6 4.1 8.9 7.9l3.1-.9-2.3-3.8-3.1.9Z" fill="#F6C92B"/><path d="M13.4 2.3l2.3 3.8 3.1-.9-2.3-3.8-3.1.9Z" fill="#F6C92B"/><rect x="3" y="12.6" width="18" height="8.8"/></svg>';
  const empty =
    '<svg viewBox="0 0 24 24" fill="none" stroke="#141210" stroke-width="1.6" opacity=".32" aria-hidden="true"><path d="M2.6 8.9 20 4.2l.8 3-17.4 4.7-.8-3Z"/><rect x="3.4" y="12.9" width="17.2" height="8.2"/></svg>';
  let out = '<div class="claps" role="img" aria-label="Оценка ' + (n || 0) + ' от 5">';
  for (let i = 1; i <= 5; i++) out += i <= (n || 0) ? full : empty;
  return out + "</div>";
}

/* заглавие с жълти "плочки", както на началната страница — вместо обикновен текст */
function titleBlocksHTML(t, limit) {
  const w = String(t || "").split(" ");
  const lines = [];
  let cur = "", L = limit || 15;
  for (const x of w) {
    if ((cur + " " + x).trim().length > L) { if (cur) lines.push(cur); cur = x; }
    else cur = (cur + " " + x).trim();
  }
  if (cur) lines.push(cur);
  return lines.slice(0, 3).map((l, i, a) =>
    '<span class="hl' + (i === a.length - 1 ? " hl-notch" : "") + '">' + escHtml(l) + "</span>"
  ).join("");
}

/* бутон за споделяне — копира адреса */
const SHARE_BTN =
  '<button class="btn" type="button" id="shr">Сподели</button>';
const SHARE_JS =
  "<script>(function(){var b=document.getElementById('shr');if(!b)return;b.addEventListener('click',function(){" +
  "var u=location.href;if(navigator.share){navigator.share({title:document.title,url:u}).catch(function(){});return}" +
  "navigator.clipboard&&navigator.clipboard.writeText(u).then(function(){var t=b.textContent;b.textContent='Копирано';" +
  "setTimeout(function(){b.textContent=t},1600)})})})();<\/script>";

function seoRelated(data, kind, it, limit) {
  const mine = new Set(itemTags(it).map((t) => t.slug));
  const all = seoAll(data).filter((x) => !(x.kind === kind && x.it.id === it.id));
  const score = (x) => itemTags(x.it).filter((t) => mine.has(t.slug)).length;
  const shared = all.filter((x) => score(x) > 0).sort((a, b) => score(b) - score(a));
  const rest = all.filter((x) => score(x) === 0 && x.kind === kind);
  const pick = shared.concat(rest).slice(0, limit || 4);
  if (!pick.length) return "";
  const shot = (x) => {
    const im = seoImage(x.kind, x.it, "");
    const p = x.kind === "reviews" || x.kind === "calendar" ? " p" : "";
    return im ? '<img class="ph' + p + '" src="' + escHtml(im) + '" alt="' + escHtml(x.it.t) + '" loading="lazy">' : '<div class="ph' + p + '"></div>';
  };
  return '<section class="rel"><h2>' + (shared.length ? "Още по темата" : "Още от Men In A Movie") + "</h2>" +
    '<div class="grid">' +
    pick.map((x) => '<a class="card" href="' + x.url + '">' + shot(x) +
      '<div class="tx"><small>' + escHtml(SEO_LABEL[x.kind]) + "</small><b>" + escHtml(x.it.t) + "</b></div></a>").join("") +
    "</div></section>";
}

async function seoItemPage(kind, it, data, origin, env) {
  const canon = origin + seoUrl(kind, it);
  const bigTags = {};
  for (const t of seoTagList(data)) bigTags[t.slug] = 1;   // кои теми имат своя страница
  const image = seoImage(kind, it, origin);
  const date = seoDate(kind, it);
  let title, metaBits = [], lede = "", extra = "";
  if (kind === "reviews") {
    title = it.t + (it.y ? " (" + it.y + ")" : "") + " — ревю | Men In A Movie";
    metaBits = [SEO_LABEL[kind], it.y, genreArr(it.g).join(", "), it.mins ? it.mins + " мин" : ""];
    lede = it.lead || it.verdict || "";
    if (it.imdb) extra += '<a class="btn" rel="nofollow" href="' + escHtml(/^https?:/.test(it.imdb) ? it.imdb : "https://www.imdb.com/title/" + it.imdb + "/") + '">IMDb</a>';
  } else if (kind === "news") {
    title = it.t + " | Men In A Movie";
    metaBits = [SEO_LABEL[kind], seoDateBg(date), it.cat || it.tag];
    lede = it.lead || it.p || it.desc || "";
  } else if (kind === "craft") {
    title = it.t + " | Зад кадър — Men In A Movie";
    metaBits = [SEO_LABEL[kind], seoDateBg(date), it.cat || it.tag, [it.guest, it.role].filter(Boolean).join(", ")];
    lede = it.lead || it.p || it.desc || "";
  } else if (kind === "episodes") {
    title = "Епизод " + (it.n || "") + ": " + it.t + " | Подкаст Men In A Movie";
    metaBits = [SEO_LABEL[kind], seoDateBg(date), it.cat || it.tag, it.n ? "Епизод " + it.n : ""];
    lede = it.desc || "";
  } else {
    title = it.t + (it.when ? " — " + seoDateBg(it.when) : "") + " | Movie calendar";
    lede = it.lead || it.p || it.desc || "";
    /* билетите/гледането са бутон в жълтата лента; останалите детайли влизат в calKicker по-долу */
  }
  const calPast = kind === "calendar" && String(it.when || "") < ymd(new Date());
  /* трейлър/резюме/оценка от TMDB, теглени "на живо" при отваряне на страницата (не при синхронизацията) */
  let tmdbX = { trailer: "", overview: "", rating: null };
  if (kind === "calendar" && it.src === "tmdb" && it.tmdbId && env) {
    const media = it.kind === "cinema" ? "movie" : "tv";
    const s = it.sub === "episode" ? it.season : "", e = it.sub === "episode" ? it.episode : "";
    tmdbX = await tmdbExtra(env, media, it.tmdbId, s, e);
    if (tmdbX.overview) lede = tmdbX.overview;
  }
  const calKicker = kind === "calendar"
    ? [calCat(it), it.kind === "stream" ? calSubLabel(it) : "", calPast ? "вече е налично" : seoDateBg(it.when),
       it.time, it.place, it.kind === "event" && it.price ? "от " + it.price + " €" : "",
       genreArr(it.genre).join(", "), it.mins ? it.mins + " мин." : "",
       tmdbX.rating ? "TMDB " + tmdbX.rating + "/10" : ""].filter(Boolean).join(" • ")
    : SEO_LABEL[kind];
  const vid = it.video || it.yt || "";
  /* видеото вече е бутон в жълтата лента */

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

  const bodyTxt = kind === "episodes" ? (it.body || it.lead || it.desc) : (kind === "calendar" ? (it.body || it.p) : it.body);
  const poster = kind === "reviews" || kind === "calendar";
  const shotImg = image && !/\/og\.jpg$/.test(image)
    ? '<div class="shot' + (poster ? "" : " wide") + '"><img src="' + escHtml(image) + '" alt="' + escHtml(it.t) + '" onerror="this.parentNode.remove()"></div>'
    : '<div class="shot' + (poster ? "" : " wide") + '"></div>';

  /* „Чуй повече“ — епизодът, в който сме говорили за материала (не и за календара — там video е трейлърът) */
  let listen = "";
  if (kind !== "episodes" && kind !== "calendar" && it.video) listen = '<a class="btn gold" rel="nofollow" href="' + escHtml(it.video) + '">Чуй повече</a> ';
  if (kind === "calendar") {
    const rv = calReviewFor(data, it);
    if (rv) extra += '<a class="btn" href="' + escHtml(seoUrl("reviews", rv)) + '">Прочети ревюто</a> ';
  }

  /* бутоните в жълтата лента — трейлър, чуй повече, харесай, сподели и т.н. */
  let bandBtns = "";
  const trailer = kind === "calendar" ? (it.video || tmdbX.trailer || "") : (it.trailer || "");
  if (trailer) bandBtns += '<a class="btn" rel="nofollow" href="' + escHtml(trailer) + '">Виж трейлъра</a> ';
  if (kind === "episodes" && it.yt) bandBtns += '<a class="btn" rel="nofollow" href="' + escHtml(it.yt) + '">Гледай в YouTube</a> ';
  if (kind === "episodes" && it.sp) bandBtns += '<a class="btn" rel="nofollow" href="' + escHtml(it.sp) + '">Слушай в Spotify</a> ';
  if (kind === "calendar" && it.kind === "event" && it.ticketUrl) bandBtns += '<a class="btn" rel="nofollow" href="' + escHtml(it.ticketUrl) + '">Билети</a> ';
  if (kind === "calendar" && it.kind === "stream" && it.watchUrl) bandBtns += '<a class="btn" rel="nofollow" href="' + escHtml(it.watchUrl) + '">Гледай в ' + escHtml(it.platform || "платформата") + '</a> ';
  if (kind === "calendar" && it.kind === "cinema" && data.settings && data.settings.cinemaProgramUrl) bandBtns += '<a class="btn" rel="nofollow" href="' + escHtml(data.settings.cinemaProgramUrl) + '">Програма по кината</a> ';
  if (kind === "merch") bandBtns += '<a class="btn" href="/march">Виж мърча</a> ';

  /* календар/ревю: без жълта лента, вертикален постер вдясно; при ревю тагове+бутони слизат долу под подписа */
  const noBand = kind === "reviews" || kind === "calendar";
  const btnsRow = '<div class="btns">' + likeHTML() + SHARE_BTN + listen + extra + bandBtns +
      (kind === "calendar" ? '<a class="btn" href="/kalendar">Целият календар</a>' : "") +
    "</div>";
  let sideInner = '<p class="facts">' + escHtml((kind === "calendar" ? [calKicker] : metaBits).filter(Boolean).join(" · ")) + "</p>" +
    (noBand ? '<h1 class="hl-stack">' + titleBlocksHTML(it.t, 20) + "</h1>" : "<h1>" + escHtml(it.t) + "</h1>");
  if (kind === "reviews") {
    sideInner += (lede ? '<p class="lede">' + escHtml(plain(lede, 400)) + "</p>" : "");
  } else {
    sideInner += tagChipsHTML(it, bigTags) +
      (lede ? '<p class="lede">' + escHtml(plain(lede, 400)) + "</p>" : "") +
      btnsRow;
  }

  const band =
    '<div class="band' + (noBand ? " no-band" : "") + '"><div class="wrap"><p class="crumbs">Начало › ' + escHtml(SEO_LABEL[kind]) + "</p>" +
    '<div class="in"><div class="side">' + sideInner +
    "</div>" + shotImg + "</div></div></div>";

  const html = band +
    '<div class="col">' +
    seoBody(resolveInlineImages(bodyTxt, it.inlineImages)) +
    (it.guest ? '<p class="meta" style="margin-top:22px">Гост: ' + escHtml(it.guest) + (it.role ? " · " + escHtml(it.role) : "") + "</p>" : "") +
    (kind === "reviews" ? '<div class="claps-big">' + clapsHTML(it.s) + "</div>" : "") +
    (it.authorName ? '<p class="sig">— ' + escHtml(it.authorName) + "</p>" : "") +
    (kind === "reviews" ? btnsRow + tagChipsHTML(it, bigTags) : "") +
    (kind === "calendar" ? calItemLinks(data, it) : "") +
    "</div>" +
    seoRelated(data, kind, it, 4);

  return seoShell({
    title, desc: seoDesc(it, 180), canon, image, ogType: "article",
    keywords: itemTags(it).map((t) => t.name).join(", "),
    head: seoJsonLd(kind, it, origin, canon, image),
    body: html + countJs + SHARE_JS,
  });
}

/* ---------- списъчни страници на рубриките ---------- */
const SEO_LIST = {
  novini:      { kind: "news",     title: "Новини",        h1: "Новини от киното",                    desc: "Какво се случва в киното: премиери, кастинг, трейлъри и боксофис — на български." },
  revyuta:     { kind: "reviews",  title: "Ревюта",        h1: "Гледано, преживяно, оценено",          desc: "Големите заглавия, оценени по единствения важен критерий — струва ли си билетът." },
  podkast:     { kind: "episodes", title: "Подкаст",       h1: "Хората във филма",                     desc: "Разговори за киното, което всички гледаме. Навсякъде, където слушате подкасти." },
  "zad-kadar": { kind: "craft",    title: "Зад кадър",     h1: "Как всъщност се прави",                desc: "Оператори, монтажисти, звукари и каскадьори обясняват решенията зад кадрите, които помним." },
  march:       { kind: "merch",    title: "Мърч",          h1: "Хората във филма имат и мърч",         desc: "Малки серии, брандирани с логото." },
};
const SEO_PER_PAGE = 8;

function seoListPage(slug, page, data, origin) {
  const cfg = SEO_LIST[slug];
  const kind = cfg.kind;
  const heads = data.heads || {};
  const hd = heads[slug] || {};
  const banner = hd.banner ? (String(hd.banner).indexOf("/img/") === 0 ? origin + hd.banner : hd.banner) : "";

  let list = (data[kind] || []).filter((it) => it && (kind === "merch" ? (it.status || "published") === "published" : seoLive(kind, it)));
  list = list.slice().sort((a, b) => String(seoDate(kind, b) || "").localeCompare(String(seoDate(kind, a) || "")));

  const pages = Math.max(1, Math.ceil(list.length / SEO_PER_PAGE));
  const p = Math.min(Math.max(1, page || 1), pages);
  const slice = list.slice((p - 1) * SEO_PER_PAGE, p * SEO_PER_PAGE);
  const poster = kind === "reviews" || kind === "calendar";

  const rows = slice.map((it) => {
    if (kind === "reviews") {
      const im = seoImage(kind, it, origin);
      return '<a class="rcard" href="' + seoUrl(kind, it) + '"><div class="rcard-art">' +
        (im && !/\/og\.jpg$/.test(im) ? '<img src="' + escHtml(im) + '" alt="' + escHtml(it.t) + '" loading="lazy">' : "") +
        clapsHTML(it.s) +
        '</div><div class="cbody"><h3>' + escHtml(it.t) + '</h3>' +
        '<p class="kicker">' + escHtml([it.y, genreArr(it.g).join(", ")].filter(Boolean).join(" · ")) + "</p></div></a>";
    }
    if (kind === "merch") {
      const im = it.img ? origin + "/img/m/" + encodeURIComponent(it.id) : "";
      const u = "/produkt/" + slugify(it.t) + "-" + idTail(it.id);
      return '<a class="pcard" href="' + u + '"><div class="pshot' + (it.on ? "" : " dim") + '">' +
        (im ? '<img src="' + escHtml(im) + '" alt="' + escHtml(it.t) + '" loading="lazy">' : "") +
        '<span class="pbadge ' + (it.on ? "ok" : "out") + '">' + (it.on ? "Налично" : "Изчерпано") + "</span>" +
        '</div><div class="cbody"><h3>' + escHtml(it.t) + "</h3>" +
        (it.lead ? "<p>" + escHtml(it.lead) + "</p>" : "") +
        '<p class="kicker" style="margin-top:8px;color:#F6C92B;font-size:15px">' + escHtml(String(it.price || 0)) + " &euro;</p>" +
        "</div></a>";
    }
    const u = seoUrl(kind, it);
    const im = seoImage(kind, it, origin);
    const meta = [SEO_LABEL[kind] || cfg.title, seoDateBg(seoDate(kind, it))].filter(Boolean);
    return '<a class="li" href="' + u + '">' +
      (im && !/\/og\.jpg$/.test(im) ? '<img class="' + (poster ? "p" : "") + '" src="' + escHtml(im) + '" alt="' + escHtml(it.t) + '" loading="lazy">' : '<div class="' + (poster ? "p" : "") + '"></div>') +
      '<div class="tx"><p class="kicker">' + escHtml(meta.join(" · ")) + "</p>" +
      "<h3>" + escHtml(it.t) + "</h3>" +
      "<p>" + escHtml(plain(it.lead || it.p || it.verdict || it.desc || it.body || "", 210)) + "</p>" +
      (kind === "merch" && it.price ? '<p class="kicker" style="margin-top:10px;color:#F6C92B;font-size:15px">' + escHtml(String(it.price)) + " &euro;</p>" : "") +
      '<span class="more">Виж повече</span></div></a>';
  }).join("");

  const pager = pages > 1
    ? '<nav class="pager">' + Array.from({ length: pages }, (_, i) => i + 1).map((n) =>
        n === p ? '<span class="cur">' + n + "</span>"
                : '<a href="/' + slug + (n > 1 ? "/" + n : "") + '">' + n + "</a>").join("") + "</nav>"
    : "";

  const items = slice.map((it, i) => ({
    "@type": "ListItem", position: (p - 1) * SEO_PER_PAGE + i + 1,
    url: origin + (kind === "merch" ? "/march" : seoUrl(kind, it)), name: it.t,
  }));
  const ld = {
    "@context": "https://schema.org", "@type": "CollectionPage",
    name: cfg.h1, description: cfg.desc, url: origin + "/" + slug + (p > 1 ? "/" + p : ""),
    mainEntity: { "@type": "ItemList", itemListElement: items },
  };

  return seoShell({
    title: (hd.title || cfg.h1) + (p > 1 ? " — страница " + p : "") + " | Men In A Movie",
    desc: cfg.desc,
    canon: origin + "/" + slug + (p > 1 ? "/" + p : ""),
    image: banner || (slice[0] ? seoImage(kind, slice[0], origin) : origin + "/og.jpg"),
    ogType: "website",
    head: '<script type="application/ld+json">' + JSON.stringify(ld) + "<\/script>",
    body:
      '<div class="lbanner"><div class="wrap"><h1>' + escHtml(hd.title || cfg.title) + "</h1>" +
      '<span class="cnt">' + list.length + " материала</span>" +
      (banner ? '<img class="bn" src="' + escHtml(banner) + '" alt="">' : "") +
      "</div></div>" +
      '<div class="col" style="padding-top:24px;padding-bottom:0"><p class="lede" style="font-size:18px">' + escHtml(cfg.desc) + "</p></div>" +
      '<div class="' + (kind === "reviews" || kind === "merch" ? "grid-cards" : "list") + '">' + (rows || '<p class="kicker">Още няма нищо тук.</p>') + "</div>" + pager,
  });
}

/* продуктова страница (мърч) — e-shop стил, за да не дава 404 при директно зареждане/refresh */
function seoMerchPage(it, origin) {
  const canon = origin + "/produkt/" + slugify(it.t) + "-" + idTail(it.id);
  const im = it.img ? origin + "/img/m/" + encodeURIComponent(it.id) : "";
  const sizes = Array.isArray(it.sizes) ? it.sizes : [];
  const body =
    '<p class="shop-crumbs"><a href="/">Начало</a> › <a href="/march">Мърч</a> › ' + escHtml(it.t) + "</p>" +
    '<div class="shop-grid">' +
    '<div class="shop-frame">' + (im ? '<img src="' + escHtml(im) + '" alt="' + escHtml(it.t) + '">' : "") + "</div>" +
    '<div class="shop-panel"><h1>' + escHtml(it.t) + "</h1>" +
    '<div class="shop-stockline"><span class="shop-stockdot' + (it.on ? "" : " out") + '"></span>' +
    '<span class="shop-stocktxt' + (it.on ? "" : " out") + '">' + (it.on ? "В наличност" : "Изчерпано") + "</span></div>" +
    '<p class="shop-price">' + escHtml(String(it.price || 0)) + " €</p>" +
    (it.lead ? '<p class="shop-desc">' + escHtml(it.lead) + "</p>" : "") +
    (sizes.length ? '<p class="kicker">Размери</p><p style="margin:0 0 24px">' + escHtml(sizes.join(" · ")) + "</p>" : "") +
    (it.on
      ? '<a class="shop-cta" href="mailto:?subject=' + encodeURIComponent("Поръчка: " + it.t) + '">Поръчай по имейл</a>'
      : '<span class="shop-cta" aria-disabled="true">Изчерпано</span>') +
    "</div></div>" +
    '<div class="shop-lower"><div><h2>Описание</h2><div class="prose">' +
    (it.body ? seoBody(resolveInlineImages(it.body, it.inlineImages)) : it.lead ? "<p>" + escHtml(it.lead) + "</p>" : "<p>Няма допълнително описание.</p>") +
    "</div></div></div>";
  return seoShell({
    title: it.t + " | Мърч — Men In A Movie",
    desc: it.lead || it.t,
    canon, image: im || origin + "/og.jpg", ogType: "product",
    body,
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

/* ================= СТРАНИЦИ НА КАЛЕНДАРА =================
   /kalendar                  — какво да гледам, всичко напред по месеци
   /kalendar/septemvri-2026   — какво излиза през даден месец
   /kalendar/kino             — само премиерите по кината
   /kalendar/streaming        — само стрийминга
   /kalendar/netflix          — само една платформа
*/
const CAL_SUB_LABEL = { series: "Нов сериал", season: "Нов сезон", episode: "Нов епизод" };

function calMonthName(ym) {
  const m = /^(\d{4})-(\d{2})$/.exec(String(ym || ""));
  return m ? BG_MONTHS[+m[2] - 1] + " " + m[1] : "";
}
function calMonthSlug(ym) {
  const m = /^(\d{4})-(\d{2})$/.exec(String(ym || ""));
  return m ? slugify(BG_MONTHS[+m[2] - 1]) + "-" + m[1] : "";
}
/* всичко видимо в календара, подредено по дата */
function calLive(data) {
  return ((data && data.calendar) || [])
    .filter((it) => seoLive("calendar", it) && /^\d{4}-\d{2}-\d{2}$/.test(String(it.when || "")))
    .slice()
    .sort((a, b) => String(a.when).localeCompare(String(b.when)));
}
/* подстраниците, които наистина имат съдържание */
function calViews(data) {
  const today = ymd(new Date());
  const soon = calLive(data).filter((x) => x.when >= today);
  const views = [];
  const push = (v) => { if (v.items.length && !views.some((o) => o.slug === v.slug)) views.push(v); };

  const months = [];
  for (const it of soon) { const ym = it.when.slice(0, 7); if (months.indexOf(ym) < 0) months.push(ym); }
  for (const ym of months.slice(0, 6))
    push({ slug: calMonthSlug(ym), type: "month", ym: ym, name: calMonthName(ym),
           items: soon.filter((x) => x.when.slice(0, 7) === ym) });

  push({ slug: "kino", type: "cinema", name: "По кината", items: soon.filter((x) => x.kind === "cinema") });
  const str = soon.filter((x) => x.kind === "stream");
  push({ slug: "streaming", type: "stream", name: "Стрийминг", items: str });

  const byPlat = {};
  for (const it of str) { const p = String(it.platform || "").trim(); if (p) (byPlat[p] = byPlat[p] || []).push(it); }
  for (const p of Object.keys(byPlat).sort())
    push({ slug: slugify(p), type: "platform", name: p, items: byPlat[p] });

  return views;
}
function calFindView(data, slug) {
  const want = String(slug || "").toLowerCase();
  return calViews(data).find((v) => v.slug === want) || null;
}
/* текстовете, с които страницата се явява пред търсачките */
function calWords(v) {
  if (!v) return {
    kicker: "Movie calendar", h1: "Какво да гледам",
    title: "Какво да гледам — премиери по кината и стрийминга в България | Men In A Movie",
    desc: "Всички премиери по кината в България и новите филми и сериали по Netflix, HBO Max, Disney+ и другите стрийминг платформи — подредени по дата.",
    keywords: "какво да гледам, премиери, кино програма, нови филми, нови сериали, стрийминг, България",
    lede: "Тук е цялата програма напред: какво влиза по кината в България и какво излиза по стрийминга — филм по филм, сериал по сериал, по дати.",
  };
  if (v.type === "month") return {
    kicker: "Movie calendar", h1: "Какво излиза през " + v.name,
    title: "Филми и сериали през " + v.name + " — премиери в България | Men In A Movie",
    desc: "Премиерите през " + v.name + " в България: " + v.items.length + " заглавия по кината и по стрийминга, с точните дати.",
    keywords: "филми " + v.name + ", премиери " + v.name + ", какво да гледам през " + v.name,
    lede: "Всичко, което излиза през " + v.name + " — по кината и по стрийминга.",
  };
  if (v.type === "cinema") return {
    kicker: "Movie calendar", h1: "Премиери по кината",
    title: "Премиери по кината в България — какво върви в кино | Men In A Movie",
    desc: "Кои филми излизат по кината в България и на коя дата. " + v.items.length + " предстоящи премиери.",
    keywords: "кино програма, премиери по кината, нови филми в кино, България",
    lede: "Филмите, които влизат по кината в България — подредени по дата на премиерата.",
  };
  if (v.type === "stream") return {
    kicker: "Movie calendar", h1: "Какво излиза по стрийминга",
    title: "Нови филми и сериали по стрийминга в България | Men In A Movie",
    desc: "Новите филми, сериали, сезони и епизоди по стрийминг платформите в България — " + v.items.length + " заглавия с дати.",
    keywords: "какво да гледам, нови сериали, нови филми, стрийминг България, Netflix, HBO Max",
    lede: "Нови сериали, нови сезони и отделни епизоди по платформите, които се гледат в България.",
  };
  return {
    kicker: "Movie calendar", h1: "Какво ново по " + v.name,
    title: "Какво ново по " + v.name + " в България — премиери по дати | Men In A Movie",
    desc: "Новите филми и сериали по " + v.name + " в България: " + v.items.length + " заглавия с датите, на които излизат.",
    keywords: v.name + ", какво да гледам по " + v.name + ", нови сериали " + v.name + ", " + v.name + " България",
    lede: "Всичко ново по " + v.name + ", което се пуска в България, с датата до всяко заглавие.",
  };
}
function calRow(it, origin) {
  const im = it.poster || it.backdrop || "";
  const tab1 = calCat(it);
  const tab2 = CAL_SUB_LABEL[it.sub] || (it.sub === "episode" && it.season && it.episode ? "S" + it.season + " · E" + it.episode : "");
  const past = it.when < ymd(new Date());
  const formatTxt = it.kind === "event" ? "Събитие" : it.kind === "stream" ? (it.sub ? "Сериал" : "Филм") : "По кината";
  return '<a class="calcard" href="' + seoUrl("calendar", it) + '"><div class="calcard-art">' +
    (im && /^https?:/.test(im) ? '<img src="' + escHtml(im) + '" alt="' + escHtml(it.t) + '" loading="lazy">' : "") +
    '<span class="calcard-tab">' + escHtml(tab1) + "</span>" +
    (tab2 ? '<span class="calcard-tab2">' + escHtml(tab2) + "</span>" : "") +
    '<span class="calcard-when">' + escHtml(past ? "вече е налично" : seoDateBg(it.when)) + "</span>" +
    '</div><div class="cbody"><h3>' + escHtml(it.t) + '</h3>' +
    '<p class="kicker">' + escHtml((it.kind === "event" ? [it.price ? "от " + it.price + " €" : "", it.place] : [it.platform]).concat([formatTxt]).filter(Boolean).join(" · ")) + "</p></div></a>";
}
function calByMonth(items) {
  const order = [], group = {};
  for (const it of items) { const ym = it.when.slice(0, 7); if (!group[ym]) { group[ym] = []; order.push(ym); } group[ym].push(it); }
  return order.map((ym) =>
    "<h2>" + escHtml(calMonthName(ym)) + '</h2><div class="grid-cards">' + group[ym].map((it) => calRow(it)).join("") + "</div>").join("");
}
function calOtherViews(views, currentSlug) {
  const rest = views.filter((v) => v.slug !== currentSlug);
  if (!rest.length) return "";
  const label = (v) => v.type === "month" ? v.name : v.name;
  return '<div class="tags" style="margin-top:38px"><span>Виж и:</span>' +
    (currentSlug ? '<a class="tag" href="/kalendar">Целият календар</a>' : "") +
    rest.map((v) => '<a class="tag" href="/kalendar/' + v.slug + '">' + escHtml(label(v)) + " (" + v.items.length + ")</a>").join("") +
    "</div>";
}
/* от отделното заглавие обратно към месеца и платформата му */
function calItemLinks(data, it) {
  const views = calViews(data);
  const want = [calMonthSlug(String(it.when || "").slice(0, 7)),
                it.kind === "cinema" ? "kino" : "",
                it.platform ? slugify(it.platform) : ""].filter(Boolean);
  const pick = views.filter((v) => want.indexOf(v.slug) >= 0);
  if (!pick.length) return "";
  return '<div class="tags" style="margin-top:30px"><span>Виж и:</span>' +
    pick.map((v) => '<a class="tag" href="/kalendar/' + v.slug + '">' +
      escHtml(v.type === "month" ? "Какво излиза през " + v.name : v.name) + "</a>").join("") +
    '<a class="tag" href="/kalendar">Целият календар</a></div>';
}

function calJsonLd(items, w, canon, origin) {
  const ld = {
    "@context": "https://schema.org", "@type": "CollectionPage",
    name: w.h1 + " — Men In A Movie", url: canon, inLanguage: "bg-BG",
    description: w.desc,
    isPartOf: { "@type": "WebSite", name: "Men In A Movie", url: origin + "/" },
    mainEntity: {
      "@type": "ItemList", numberOfItems: items.length,
      itemListElement: items.slice(0, 60).map((it, i) => ({
        "@type": "ListItem", position: i + 1,
        item: {
          "@type": it.kind === "stream" ? "TVSeries" : "Movie",
          name: it.t, url: origin + seoUrl("calendar", it),
          ...(it.poster && /^https?:/.test(it.poster) ? { image: it.poster } : {}),
          ...(it.when ? { datePublished: it.when } : {}),
        },
      })),
    },
  };
  const crumbs = {
    "@context": "https://schema.org", "@type": "BreadcrumbList",
    itemListElement: [
      { "@type": "ListItem", position: 1, name: "Men In A Movie", item: origin + "/" },
      { "@type": "ListItem", position: 2, name: "Movie calendar", item: origin + "/kalendar" },
    ].concat(canon === origin + "/kalendar" ? [] : [{ "@type": "ListItem", position: 3, name: w.h1, item: canon }]),
  };
  return '<script type="application/ld+json">' +
    JSON.stringify(JSON.parse(JSON.stringify([ld, crumbs]))).replace(/</g, "\\u003c") + "</script>";
}
function calListPage(data, origin, view) {
  const views = calViews(data);
  const today = ymd(new Date());
  const items = view ? view.items : calLive(data).filter((x) => x.when >= today);
  const w = calWords(view);
  const canon = origin + "/kalendar" + (view ? "/" + view.slug : "");
  const first = items.find((it) => it.poster && /^https?:/.test(it.poster));
  const image = first ? first.poster : origin + "/og.jpg";
  const body =
    '<p class="kicker">' + escHtml(w.kicker) + "</p><h1>" + escHtml(w.h1) + "</h1>" +
    '<p class="meta">' + items.length + " заглавия · обновено " + escHtml(seoDateBg(today)) + "</p>" +
    '<p class="lede">' + escHtml(w.lede) + "</p>" +
    '<div class="rel" style="border:0;margin:0;padding:0">' +
    (items.length ? (view && view.type === "month" ? '<div class="grid-cards">' + items.map((it) => calRow(it)).join("") + "</div>" : calByMonth(items))
                  : "<p>Точно сега няма обявени дати. Върни се след ден-два — календарът се обновява сам.</p>") +
    "</div>" +
    '<div class="btns" style="margin-top:34px"><a class="btn gold" href="/#kalendar">Виж календара на сайта</a>' +
    '<a class="btn" href="/karta">Всички материали</a></div>' +
    calOtherViews(views, view ? view.slug : "");
  return seoShell({
    title: w.title, desc: w.desc, canon, image, ogType: "website", keywords: w.keywords,
    head: calJsonLd(items, w, canon, origin), body,
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
    '<div class="btns" style="margin:0 0 30px"><a class="btn gold" href="/kalendar">Какво да гледам — целият календар</a></div>' +
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

/* Google News иска отделна карта — само новини от последните 48 часа */
function seoNewsSitemap(data, origin) {
  const cutoff = Date.now() - 2 * 24 * 60 * 60 * 1000;
  const items = (data.news || []).filter((it) => {
    if (!seoLive("news", it)) return false;
    const d = seoDate("news", it);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(d)) return false;
    return new Date(d + "T12:00:00Z").getTime() >= cutoff;
  });
  const rows = items.map((it) => {
    const loc = origin + seoUrl("news", it);
    const pubDate = seoDate("news", it) + "T12:00:00+03:00";
    return "<url><loc>" + escHtml(loc) + "</loc><news:news>" +
      "<news:publication><news:name>Men In A Movie</news:name><news:language>bg</news:language></news:publication>" +
      "<news:publication_date>" + pubDate + "</news:publication_date>" +
      "<news:title>" + escHtml(it.t) + "</news:title>" +
      "</news:news></url>";
  });
  return '<?xml version="1.0" encoding="UTF-8"?>\n' +
    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:news="http://www.google.com/schemas/sitemap-news/0.9">\n' +
    rows.join("\n") + "\n</urlset>\n";
}

function seoSitemap(data, origin) {
  const rows = ['<url><loc>' + origin + '/</loc><changefreq>daily</changefreq><priority>1.0</priority></url>',
                '<url><loc>' + origin + '/kalendar</loc><changefreq>daily</changefreq><priority>0.9</priority></url>',
                '<url><loc>' + origin + '/karta</loc><changefreq>daily</changefreq><priority>0.5</priority></url>'];
  for (const v of calViews(data))
    rows.push("<url><loc>" + origin + "/kalendar/" + v.slug + "</loc><changefreq>daily</changefreq><priority>0.7</priority></url>");
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

/* RSS carta за читатели — новини, ревюта, зад кадър, подкаст, най-новото отгоре */
function seoFeed(data, origin) {
  const items = seoAll(data)
    .filter((x) => x.kind !== "calendar")
    .map((x) => Object.assign({ date: seoDate(x.kind, x.it) }, x))
    .sort((a, b) => (b.date || "").localeCompare(a.date || ""))
    .slice(0, 40);
  const rows = items.map((x) => {
    const loc = origin + x.url;
    const pub = /^\d{4}-\d{2}-\d{2}$/.test(x.date) ? new Date(x.date + "T12:00:00Z").toUTCString() : "";
    return "<item>" +
      "<title>" + escHtml(x.it.t) + "</title>" +
      "<link>" + escHtml(loc) + "</link>" +
      '<guid isPermaLink="true">' + escHtml(loc) + "</guid>" +
      (pub ? "<pubDate>" + pub + "</pubDate>" : "") +
      "<description>" + escHtml(seoDesc(x.it, 300)) + "</description>" +
      "<category>" + escHtml(SEO_LABEL[x.kind] || x.kind) + "</category>" +
      "</item>";
  });
  return '<?xml version="1.0" encoding="UTF-8"?>\n' +
    '<rss version="2.0"><channel>' +
    "<title>Men In A Movie</title>" +
    "<link>" + origin + "/</link>" +
    "<description>Български канал и сайт за комерсиално кино — ревюта, подкаст, новини от индустрията и рубрика „Зад кадър“.</description>" +
    "<language>bg-BG</language>" +
    '<atom:link xmlns:atom="http://www.w3.org/2005/Atom" href="' + origin + '/feed.xml" rel="self" type="application/rss+xml"/>' +
    rows.join("") +
    "</channel></rss>\n";
}

/* Търсачките и ботовете, които ЦИТИРАТ, минават. Чисто обучаващите — не. */
function isTestEnv(env) {
  return String((env && env.MIM_ENV) || "").toLowerCase() === "test";
}

function seoRobots(origin, test) {
  if (test) return "User-agent: *\nDisallow: /\n";
  const cite = ["Googlebot","Bingbot","OAI-SearchBot","ChatGPT-User","PerplexityBot","Perplexity-User",
                "Claude-SearchBot","Claude-User","Applebot","DuckDuckBot","YandexBot","Amazonbot"];
  const train = ["GPTBot","CCBot","Bytespider","meta-externalagent","FacebookBot","Google-Extended",
                 "Applebot-Extended","ClaudeBot","anthropic-ai","cohere-ai","Diffbot","Omgilibot","Timpibot","AI2Bot"];
  return "User-agent: *\nAllow: /\nDisallow: /api/\nDisallow: /admin\n\n" +
    cite.map((b) => "User-agent: " + b + "\nAllow: /\n").join("\n") + "\n" +
    train.map((b) => "User-agent: " + b + "\nDisallow: /\n").join("\n") +
    "\nSitemap: " + origin + "/sitemap.xml" +
    "\nSitemap: " + origin + "/news-sitemap.xml\n";
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
    const res = await handleRequest(request, env, ctx);
    const out = new Response(res.body, res);
    // основни защитни хедъри — важат за целия сайт, за всеки отговор
    out.headers.set("x-content-type-options", "nosniff");
    out.headers.set("referrer-policy", "strict-origin-when-cross-origin");
    out.headers.set("permissions-policy", "geolocation=(), camera=(), microphone=(), interest-cohort=()");
    out.headers.set("x-frame-options", "SAMEORIGIN");
    out.headers.set("strict-transport-security", "max-age=31536000; includeSubDomains; preload");
    /* сайтът разчита на инлайн <script>/<style> в много страници — 'unsafe-inline' е компромис,
       но всичко останало е стегнато до конкретните домейни, които реално се ползват */
    out.headers.set("content-security-policy",
      "default-src 'self'; " +
      "script-src 'self' 'unsafe-inline'; " +
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
      "font-src 'self' https://fonts.gstatic.com; " +
      "img-src 'self' data: https://image.tmdb.org https://i.ytimg.com; " +
      "frame-src https://www.youtube.com; " +
      "connect-src 'self'; " +
      "object-src 'none'; " +
      "base-uri 'self'; " +
      "form-action 'self'; " +
      "frame-ancestors 'self'; " +
      "upgrade-insecure-requests"
    );
    if (!isTestEnv(env)) return out;

    out.headers.set("x-robots-tag", "noindex, nofollow, noarchive, nosnippet");
    const ct = out.headers.get("content-type") || "";
    if (!ct.includes("text/html")) return out;

    const body = await out.text();
    const bar =
      '<div style="position:sticky;top:0;z-index:99999;background:#B3261E;color:#fff;' +
      'font:600 12px/1 system-ui,sans-serif;letter-spacing:.08em;text-align:center;padding:7px 10px">' +
      "ТЕСТОВА СРЕДА · ТОВА НЕ Е ЖИВИЯТ САЙТ</div>";
    const marked = body.includes("<body")
      ? body.replace(/<body([^>]*)>/i, "<body$1>" + bar)
      : bar + body;
    return new Response(marked, out);
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

async function handleRequest(request, env, ctx) {
  {
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

    /* кои стрийминг платформи изобщо ги има в България */
    if (path === "/api/calendar/providers" && request.method === "GET") {
      const data = (await stored(env)) || {};
      const who = await whoIs(request, env, data);
      if (!who || (who.role !== "admin" && who.role !== "moderator"))
        return json({ error: "forbidden", message: "Само администратор и модератор." }, 403);
      if (!env.TMDB_KEY) return json({ error: "no_key", message: "Липсва ключът TMDB_KEY в Cloudflare." }, 400);
      try {
        const r = await tmdbGet(env, "/watch/providers/tv", { watch_region: "BG", language: "bg-BG" });
        const list = (r.results || [])
          .map((x) => ({
            id: x.provider_id, name: x.provider_name,
            pri: (x.display_priorities && x.display_priorities.BG != null)
              ? x.display_priorities.BG : (x.display_priority != null ? x.display_priority : 999),
          }))
          .sort((a, b) => a.pri - b.pri || a.name.localeCompare(b.name));
        return json({ ok: true, providers: list });
      } catch (e) {
        return json({ error: "tmdb", message: String(e.message || e) }, 400);
      }
    }

    /* трейлър/резюме/оценка за конкретен филм или епизод — за клиентската страница на календарен елемент */
    if (path === "/api/tmdb-extra" && request.method === "GET") {
      const media = url.searchParams.get("media") === "movie" ? "movie" : "tv";
      const tmdbId = url.searchParams.get("id") || "";
      const season = url.searchParams.get("season") || "";
      const episode = url.searchParams.get("episode") || "";
      const out = await tmdbExtra(env, media, tmdbId, season, episode);
      return new Response(JSON.stringify(out), {
        headers: { "content-type": "application/json; charset=utf-8", "cache-control": "public, max-age=21600" },
      });
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

      /* кадър за споделяне и банер на рубрика */
      const extra = EXTRA_IMG.find((x) => x.key === kindKey);
      if (extra || kindKey === "hd") {
        const d2 = await stored(env);
        let raw = "";
        if (extra) {
          const it2 = (d2 && d2[extra.kind] || []).find((x) => x && String(x.id) === id);
          raw = it2 ? it2[extra.field] : "";
        } else {
          raw = ((d2 && d2.heads || {})[id] || {}).banner || "";
        }
        const r2 = raw && dataUriToResponse(raw);
        if (!r2) return new Response("no", { status: 404 });
        if (url.searchParams.get("v")) {
          r2.headers.set("cache-control", "public, max-age=31536000, immutable");
          ctx.waitUntil(caches.default.put(request, r2.clone()));
        }
        return r2;
      }

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

    /* панелът е отделна страница */
    if (path === "/admin" || path === "/admin/") {
      const a = env.ASSETS || env.assets;
      if (a) {
        const r = await a.fetch(new Request(new URL("/admin", url).toString(), request));
        if (r.status === 200) {
          const out = new Response(r.body, r);
          out.headers.set("content-type", "text/html; charset=utf-8");
          out.headers.set("cache-control", "no-store");
          out.headers.set("x-robots-tag", "noindex, nofollow");
          return out;
        }
      }
      return new Response("Няма admin.html в public/", { status: 404 });
    }

    /* robots.txt — кой бот какво може */
    if (path === "/robots.txt") {
      return new Response(seoRobots(url.origin, isTestEnv(env)), {
        headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "public, max-age=3600" },
      });
    }

    /* кратко описание на сайта за AI агенти (ChatGPT, Claude, Perplexity...) */
    if (path === "/llms.txt") {
      const o = url.origin;
      const txt =
        "# Men In A Movie\n\n" +
        "> Български канал и сайт за комерсиално кино — ревюта, подкаст, новини от индустрията и рубрика „Зад кадър“. Работи се на български език.\n\n" +
        "Съдържанието се обновява ежедневно. Всяка статия/ревю/епизод има собствен постоянен адрес (виж sitemap.xml).\n\n" +
        "## Основни раздели\n" +
        "- [Новини](" + o + "/novini): ежедневни новини от киноиндустрията\n" +
        "- [Ревюта](" + o + "/revyuta): оценки на филми в клапи (1–5), с постер и подпис на автора\n" +
        "- [Подкаст](" + o + "/podkast): епизоди от YouTube за филми и сериали\n" +
        "- [Зад кадър](" + o + "/zad-kadar): статии/видео за занаята — камера, монтаж, звук\n" +
        "- [Movie calendar](" + o + "/kalendar): премиери по кината и стрийминг платформите в България\n" +
        "- [Мърч](" + o + "/march): каталог с продукти на канала\n\n" +
        "## Данни\n" +
        "- Пълна карта на адресите: " + o + "/sitemap.xml\n" +
        "- RSS: " + o + "/feed.xml\n" +
        "- Език: български (bg-BG)\n" +
        "- Контакт: hristoinamovie@gmail.com\n";
      return new Response(txt, {
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

    /* отделна карта само с новини от последните 48 часа — за Google News */
    if (path === "/news-sitemap.xml") {
      const data = (await stored(env)) || {};
      return new Response(seoNewsSitemap(data, url.origin), {
        headers: { "content-type": "application/xml; charset=utf-8", "cache-control": "public, max-age=900" },
      });
    }

    /* RSS — за читатели с feed reader и агрегатори */
    if (path === "/feed.xml" || path === "/rss.xml") {
      const data = (await stored(env)) || {};
      return new Response(seoFeed(data, url.origin), {
        headers: { "content-type": "application/rss+xml; charset=utf-8", "cache-control": "public, max-age=900" },
      });
    }

    /* карта на сайта за хората и за обхождането */
    /* списъчни страници на рубриките */
    {
      const seg = path.replace(/^\/+|\/+$/g, "").split("/");
      if (SEO_LIST[seg[0]] && (seg.length === 1 || /^\d+$/.test(seg[1] || ""))) {
        const data = await stored(env);
        if (data) {
          return new Response(seoListPage(seg[0], +(seg[1] || 1), data, url.origin), {
            headers: { "content-type": "text/html; charset=utf-8", "cache-control": "public, max-age=300" },
          });
        }
      }
    }

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

    /* календарът като истинска страница: /kalendar и подстраниците ѝ */
    if (path === "/kalendar" || path === "/kalendar/") {
      const data = (await stored(env)) || {};
      return new Response(calListPage(data, url.origin, null), {
        headers: { "content-type": "text/html; charset=utf-8", "cache-control": "public, max-age=600" },
      });
    }
    if (path.startsWith("/kalendar/")) {
      const seg = path.split("/").filter(Boolean);
      if (seg.length === 2) {
        const data = (await stored(env)) || {};
        const view = calFindView(data, decodeURIComponent(seg[1]));
        if (view)
          return new Response(calListPage(data, url.origin, view), {
            headers: { "content-type": "text/html; charset=utf-8", "cache-control": "public, max-age=600" },
          });
      }
    }

    /* продукт от мърча: /produkt/teniska-mim-classic-m1 */
    if (path.startsWith("/produkt/")) {
      const seg = path.split("/").filter(Boolean);
      if (seg.length === 2) {
        const data = (await stored(env)) || {};
        const slug = decodeURIComponent(seg[1]).toLowerCase();
        const tail = slug.split("-").pop();
        const list = Array.isArray(data.merch) ? data.merch : [];
        const it = list.find((x) => x && (x.status || "published") === "published" &&
          (idTail(x.id) === tail || String(x.id).toLowerCase() === tail));
        if (it) return new Response(seoMerchPage(it, url.origin), {
          headers: { "content-type": "text/html; charset=utf-8", "cache-control": "public, max-age=600" },
        });
      }
      return Response.redirect(url.origin + "/march", 302);
    }

    /* истинска страница за всеки материал: /revyu/dyun-chast-vtora-r1 */
    {
      const seg = path.split("/").filter(Boolean);
      const kind = Object.keys(SEO_PATH).find((k) => SEO_PATH[k] === seg[0]);
      if (kind && seg.length >= 2) {
        const data = (await stored(env)) || {};
        const it = seoFind(data, kind, decodeURIComponent(seg[1]));
        if (!it) return Response.redirect(url.origin + (kind === "calendar" ? "/kalendar" : "/#" + SEO_ANCHOR[kind]), 302);
        const good = seoUrl(kind, it);
        if (path !== good) return Response.redirect(url.origin + good, 301);
        return new Response(await seoItemPage(kind, it, data, url.origin, env), {
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
      const desc = plain(it.lead || it.verdict || it.p || it.desc || it.body || "", 200);
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
  }
}
