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
  u.searchParams.set("api_key", env.TMDB_KEY);
  const r = await fetch(u.toString(), { headers: { accept: "application/json" } });
  if (!r.ok) throw new Error("TMDB " + r.status);
  return r.json();
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
    }
  } catch (e) {}
  // сериали по стрийминга
  for (const pv of providers.slice(0, 4)) {
    try {
      const tv = await tmdbGet(env, "/discover/tv", {
        watch_region: "BG", with_watch_providers: String(pv.id), language: "bg-BG",
        "air_date.gte": ymd(from), "air_date.lte": ymd(to),
        sort_by: "popularity.desc", page: "1",
      });
      for (const t of (tv.results || []).slice(0, 8)) {
        const when = t.first_air_date && t.first_air_date >= ymd(from) ? t.first_air_date : ymd(from);
        fresh.push({
          id: "tmdb-t-" + t.id, kind: "stream", src: "tmdb", tmdbId: t.id,
          t: t.name || t.original_name || "", when: when,
          poster: t.poster_path ? POSTER + t.poster_path : "",
          p: (t.overview || "").slice(0, 320), platform: pv.name, video: "", note: "",
        });
      }
    } catch (e) {}
  }

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
  return { ok: true, count: out.length, added: fresh.length, at: data.settings.calSyncedAt };
}

/* ---------- споделяне: страница с картинка за Facebook, Viber и т.н. ---------- */
const KINDS = { r: "reviews", n: "news", c: "craft", e: "episodes", m: "merch" };
const SECTION = { reviews: "revyuta", news: "novini", craft: "zad-kadar", episodes: "podcast", merch: "merch" };

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
        if (who && who.role !== "admin" && who.role !== "moderator")
          return json({ error: "forbidden", message: "Тази роля не записва на сайта." }, 403);

        let body;
        try {
          body = await request.json();
        } catch (e) {
          return json({ error: "bad_json", message: "Невалидни данни." }, 400);
        }
        if (!body || typeof body !== "object" || !body.settings)
          return json({ error: "bad_shape", message: "Данните не приличат на съдържание на сайта." }, 400);

        const merged = keepImages(keepSecrets(body, prev), prev);
        const text = JSON.stringify(merged);
        if (text.length > 20 * 1024 * 1024)
          return json({ error: "too_large", message: "Съдържанието е над 20 MB." }, 413);

        if (prev) await env.MIM.put("content-prev", JSON.stringify(prev));
        await env.MIM.put("content", text);
        return json({ ok: true, at: Date.now(), by: who ? who.role : "bootstrap" });
      }

      return json({ error: "method" }, 405);
    }

    /* обновяване на календара — ръчно от админа */
    if (path === "/api/calendar/sync" && request.method === "POST") {
      const data = await stored(env);
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
      if (body.like === true) bump(key, "likes", 1);
      else if (body.like === false) bump(key, "likes", -1);
      else bump(key, "views", 1);
      ctx.waitUntil(flushCounters(env, false));
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

    /* адрес за споделяне: показва визитка на ботовете, човека праща в сайта */
    if (path.startsWith("/s/")) {
      const parts = path.split("/").filter(Boolean); // s, kind, id
      const kindKey = parts[1], id = decodeURIComponent(parts[2] || "");
      const data = await stored(env);
      const it = KINDS[kindKey] ? findItem(data, kindKey, id) : null;
      const site = (data && data.settings) || {};
      const origin = url.origin;
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
