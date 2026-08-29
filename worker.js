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

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

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
        return json(publicCopy(data));
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

        const merged = keepSecrets(body, prev);
        const text = JSON.stringify(merged);
        if (text.length > 20 * 1024 * 1024)
          return json({ error: "too_large", message: "Съдържанието е над 20 MB." }, 413);

        if (prev) await env.MIM.put("content-prev", JSON.stringify(prev));
        await env.MIM.put("content", text);
        return json({ ok: true, at: Date.now(), by: who ? who.role : "bootstrap" });
      }

      return json({ error: "method" }, 405);
    }

    const assets = env.ASSETS || env.assets;
    if (!assets) return new Response("Няма вързани статични файлове (binding ASSETS).", { status: 500 });
    return assets.fetch(request);
  },
};
