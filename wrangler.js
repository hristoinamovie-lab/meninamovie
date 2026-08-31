{
  "name": "meninamovie",
  "main": "worker.js",
  "compatibility_date": "2026-08-01",
  "assets": {
    "directory": "./public",
    "binding": "ASSETS"
  },
  "kv_namespaces": [
    { "binding": "MIM", "id": "c1c8bc44854040fb8086da78e052f8b3" }
  ],
  // веднъж месечно, 1-во число в 04:00 UTC — обновява Movie calendar от TMDB
  "triggers": {
    "crons": ["0 4 1 * *"]
  }
}
