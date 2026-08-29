/**
 * Men In A Movie — Worker
 * Пази съдържанието на сайта и пази ключовете скрити.
 *
 * Нужно е едно нещо: KV namespace, вързан с име  MIM
 * По желание (препоръчително): Secret с име  ADMIN_KEY
 *
 * Маршрути:
 *   GET  /api/content  → съдържанието без ключовете (или 204, ако още няма)
 *   POST /api/login    → {key} → каква роля има този ключ
 *   POST /api/content  → записва съдържание; иска header x-mim-key
 *   всичко друго       → статичните файлове
 */

const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
};
const json = (data, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: JSON_HEADERS });

async function stored(env) {
  const raw = await env.MIM.get("content");
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch (e) {
    return null;
  }
}

/** Кой е този ключ: {role,id,name} или null */
function identify(key, data, env) {
  if (!key) return null;
  if (env.ADMIN_KEY && key === env.ADMIN_KEY)
    return { role: "admin", id: "owner", name: "Администратор" };
  if (data && data.settings) {
    if (data.settings.adminKey && key === data.settings.adminKey)
      return { role: "admin", id: "owner", name: "Администратор" };
    const u = (data.settings.users || []).find((x) => x && x.key && x.key === key);
    if (u) return { role: u.role || "author", id: u.id, name: u.name || "Потребител" };
  }
  return null;
}

/** Маха ключовете, преди съдържанието да тръгне към браузъра */
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

/** Връща ключовете, които браузърът не е виждал */
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

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/login" && request.method === "POST") {
      let body = {};
      try {
        body = await request.json();
      } catch (e) {}
      const key = (body.key || "").trim();
      const data = await stored(env);
      const who = identify(key, data, env);
      if (who) return json(who);
      if (!data && !env.ADMIN_KEY && key)
        return json({ role: "admin", id: "owner", name: "Администратор", bootstrap: true });
      return json({ error: "bad_key" }, 401);
    }

    if (url.pathname === "/api/content") {
      if (request.method === "GET") {
        const data = await stored(env);
        if (!data) return new Response(null, { status: 204, headers: { "cache-control": "no-store" } });
        return json(publicCopy(data));
      }

      if (request.method === "POST") {
        const key = (request.headers.get("x-mim-key") || "").trim();
        const prev = await stored(env);
        const who = identify(key, prev, env);

        // първи запис, когато хранилището е празно и няма зададен ADMIN_KEY
        const bootstrap = !prev && !env.ADMIN_KEY;

        if (!who && !bootstrap)
          return json({ error: "bad_key", message: "Непознат ключ." }, 401);
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

        if (bootstrap && !body.settings.adminKey)
          return json({ error: "no_key", message: "Първият запис трябва да съдържа админ ключ." }, 400);

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
