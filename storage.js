/* Storage adapter — GitHub Pages edition with sync.
   - Data is encrypted with the password (AES-GCM 256, key from PBKDF2-SHA256).
   - A local encrypted copy lives in this browser (works offline).
   - Sync: the encrypted data file is stored in the same GitHub repository, branch "data",
     through the GitHub API. Every device merges changes document by document (newest wins). */
(function () {
  "use strict";
  var COLS = ["boxes", "items", "ledger", "meta"];
  var LS_DATA = "uchet-vintazha-enc-v1", LS_KEY = "uchet-vintazha-key-v1", LS_CFG = "uchet-vintazha-sync-v1", LS_DIRTY = "uchet-vintazha-dirty-v1";
  var BRANCH = "data", DATA_PATH = "db.enc.json", CFG_PATH = "config.enc.json";
  var POLL_MS = 20000;

  var data = emptyData(), listeners = [], key = null, seedInfo = null, cfg = null;
  var sync = { state: "off", at: null, error: "" };

  function emptyData() { return { boxes: {}, items: {}, ledger: {}, meta: {}, _deleted: {} }; }
  function norm(d) {
    var o = emptyData();
    COLS.forEach(function (c) { if (d && d[c] && typeof d[c] === "object" && !Array.isArray(d[c])) o[c] = d[c]; });
    if (d && d._deleted && typeof d._deleted === "object") o._deleted = d._deleted;
    return o;
  }
  function clone(o) { return JSON.parse(JSON.stringify(o)); }
  function b64(buf) { var s = "", b = new Uint8Array(buf); for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); return btoa(s); }
  function unb64(str) { var s = atob(str), b = new Uint8Array(s.length); for (var i = 0; i < s.length; i++) b[i] = s.charCodeAt(i); return b; }
  function lsGet(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }
  function lsSet(k, v) { try { localStorage.setItem(k, v); } catch (e) {} }
  function lsDel(k) { try { localStorage.removeItem(k); } catch (e) {} }

  /* ---------- crypto ---------- */
  async function deriveKey(password, salt, iter) {
    var base = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt: salt, iterations: iter }, base,
      { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  }
  async function decryptJSON(k, box) {
    var pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(box.iv) }, k, unb64(box.ct));
    return JSON.parse(new TextDecoder().decode(pt));
  }
  async function encryptJSON(k, obj) {
    var iv = crypto.getRandomValues(new Uint8Array(12));
    var ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, k, new TextEncoder().encode(JSON.stringify(obj)));
    return { iv: b64(iv), ct: b64(ct) };
  }

  /* ---------- local persistence ---------- */
  var saving = Promise.resolve();
  function saveLocal() {
    var snapshot = clone(data);
    saving = saving.then(async function () {
      var box = await encryptJSON(key, snapshot);
      try { localStorage.setItem(LS_DATA, JSON.stringify(box)); }
      catch (e) { throw { code: "quota_exceeded", message: String(e) }; }
    });
    return saving;
  }
  async function loadCfg() {
    var raw = lsGet(LS_CFG); if (!raw) return null;
    try { var c = await decryptJSON(key, JSON.parse(raw)); return c && c.token ? c : null; } catch (e) { return null; }
  }
  async function saveCfg() { lsSet(LS_CFG, JSON.stringify(await encryptJSON(key, cfg))); }

  /* ---------- merge: newest version of each document wins ---------- */
  function merge(local, remote) {
    var out = emptyData(), del = Object.assign({}, local._deleted), k;
    for (k in remote._deleted) del[k] = Math.max(del[k] || 0, remote._deleted[k]);
    COLS.forEach(function (c) {
      var ids = {}; Object.keys(local[c]).forEach(function (i) { ids[i] = 1; }); Object.keys(remote[c]).forEach(function (i) { ids[i] = 1; });
      Object.keys(ids).forEach(function (id) {
        var x = local[c][id], y = remote[c][id];
        var doc = !x ? y : !y ? x : ((x._ts || 0) > (y._ts || 0) ? x : y);
        var t = del[c + "/" + id];
        if (t && t >= (doc._ts || 0)) return;
        out[c][id] = doc;
      });
    });
    var cutoff = Date.now() - 120 * 864e5;
    for (k in del) if (del[k] < cutoff) delete del[k];
    out._deleted = del;
    return out;
  }

  /* ---------- GitHub API ---------- */
  function guessRepo() {
    var m = location.hostname.match(/^([a-z0-9-]+)\.github\.io$/i);
    if (!m) return null;
    var seg = location.pathname.split("/").filter(Boolean)[0];
    return { owner: m[1], repo: seg && !/\.html?$/.test(seg) ? seg : m[1] + ".github.io" };
  }
  function gh(c, method, path, body, headers) {
    var h = { "Authorization": "Bearer " + c.token, "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28" };
    if (body) h["Content-Type"] = "application/json";
    if (headers) for (var k in headers) h[k] = headers[k];
    return fetch("https://api.github.com/repos/" + encodeURIComponent(c.owner) + "/" + encodeURIComponent(c.repo) + path,
      { method: method, headers: h, body: body ? JSON.stringify(body) : undefined, cache: "no-store" });
  }
  function ghError(r, what) {
    var msg = r.status === 401 ? "токен недействителен или истёк" : r.status === 403 ? "нет прав или превышен лимит запросов" :
      r.status === 404 ? "репозиторий не найден или у токена нет доступа к нему" : "ошибка GitHub " + r.status;
    return new Error((what ? what + ": " : "") + msg);
  }
  var contentsPath = function (p) { return "/contents/" + p + "?ref=" + BRANCH; };
  async function readFile(c, p, etag) {
    var r = await gh(c, "GET", contentsPath(p), null, etag ? { "If-None-Match": etag } : null);
    if (r.status === 304) return { unchanged: true };
    if (r.status === 404) return { missing: true };
    if (!r.ok) throw ghError(r, "чтение");
    var j = await r.json(), text;
    if (j.content && j.encoding === "base64") text = atob(j.content.replace(/\s/g, ""));
    else {
      var r2 = await gh(c, "GET", contentsPath(p), null, { "Accept": "application/vnd.github.raw" });
      if (!r2.ok) throw ghError(r2, "чтение");
      text = await r2.text();
    }
    return { sha: j.sha, etag: r.headers.get("ETag"), json: JSON.parse(text) };
  }
  async function writeFile(c, p, json, sha, message) {
    var body = { message: message, content: btoa(JSON.stringify(json)), branch: BRANCH };
    if (sha) body.sha = sha;
    var r = await gh(c, "PUT", "/contents/" + p, body);
    if (r.status === 409 || r.status === 422) return { conflict: true };
    if (!r.ok) throw ghError(r, "запись");
    var j = await r.json();
    return { sha: j.content.sha };
  }
  async function ensureBranch(c) {
    var r = await gh(c, "GET", "/git/ref/heads/" + BRANCH);
    if (r.ok) return;
    if (r.status !== 404) throw ghError(r, "ветка данных");
    var repo = await gh(c, "GET", "");
    if (!repo.ok) throw ghError(repo, "репозиторий");
    var info = await repo.json();
    if (info.permissions && info.permissions.push === false) throw new Error("у токена нет права записи (нужно Contents: Read and write)");
    var base = await gh(c, "GET", "/git/ref/heads/" + encodeURIComponent(info.default_branch));
    if (!base.ok) throw ghError(base, "основная ветка");
    var ref = await base.json();
    var mk = await gh(c, "POST", "/git/refs", { ref: "refs/heads/" + BRANCH, sha: ref.object.sha });
    if (!mk.ok && mk.status !== 422) throw ghError(mk, "создание ветки данных");
  }

  /* ---------- sync loop ---------- */
  var remoteSha = null, remoteEtag = null, running = null, again = false, pushTimer = 0, writeSeq = 0, pollTimer = 0;
  var dirty = lsGet(LS_DIRTY) === "1";
  function setSync(state, error) {
    var changed = sync.state !== state || (error || "") !== sync.error;
    sync.state = state; sync.error = error || "";
    if (state === "idle") sync.at = new Date();
    if (changed) window.dispatchEvent(new Event("syncstatus"));
  }
  function markDirty() {
    dirty = true; writeSeq++; lsSet(LS_DIRTY, "1");
    if (!cfg) return;
    clearTimeout(pushTimer); pushTimer = setTimeout(syncNow, 1200);
  }
  function syncNow() {
    if (!cfg || !key) return Promise.resolve();
    if (running) { again = true; return running; }
    running = (async function () {
      try {
        for (var attempt = 0; attempt < 5; attempt++) {
          var rem = await readFile(cfg, DATA_PATH, remoteEtag);
          if (rem.missing) { remoteSha = null; remoteEtag = null; dirty = true; }
          else if (!rem.unchanged) {
            remoteSha = rem.sha; remoteEtag = rem.etag;
            var remoteData = norm(await decryptJSON(key, rem.json));
            var before = JSON.stringify(data);
            data = merge(data, remoteData);
            if (JSON.stringify(data) !== before) { COLS.forEach(notify); await saveLocal(); }
          }
          if (!dirty) break;
          if (sync.state !== "syncing") setSync("syncing");
          var seq = writeSeq;
          var box = await encryptJSON(key, data);
          var w = await writeFile(cfg, DATA_PATH, box, remoteSha, "Обновление данных");
          if (w.conflict) { remoteEtag = null; continue; }
          remoteSha = w.sha; remoteEtag = null;
          if (writeSeq === seq) { dirty = false; lsDel(LS_DIRTY); }
          break;
        }
        setSync("idle");
      } catch (e) {
        if (e && e.name === "OperationError") setSync("error", "данные в репозитории зашифрованы другим паролем");
        else setSync("error", (e && e.message) || "нет связи с GitHub");
      } finally {
        running = null;
        if (again) { again = false; syncNow(); }
      }
    })();
    return running;
  }
  function startSync() {
    clearInterval(pollTimer);
    pollTimer = setInterval(function () { if (document.visibilityState !== "hidden") syncNow(); }, POLL_MS);
    if (!startSync.bound) {
      startSync.bound = true;
      document.addEventListener("visibilitychange", function () { if (document.visibilityState === "visible") syncNow(); });
      window.addEventListener("online", function () { syncNow(); });
      window.addEventListener("pagehide", function () { if (dirty) syncNow(); });
    }
    setSync("idle");
    return syncNow();
  }
  async function initSync() {
    cfg = await loadCfg();
    if (!cfg) {
      var g = guessRepo();
      if (g) {
        try {
          var r = await fetch("https://raw.githubusercontent.com/" + g.owner + "/" + g.repo + "/" + BRANCH + "/" + CFG_PATH + "?t=" + Date.now(), { cache: "no-store" });
          if (r.ok) { var c = await decryptJSON(key, await r.json()); if (c && c.token) { cfg = c; await saveCfg(); } }
        } catch (e) { /* not shared yet */ }
      }
    }
    if (cfg) startSync(); else setSync("off");
  }
  async function connect(c) {
    await ensureBranch(c);
    var existing = await readFile(c, CFG_PATH);
    var w = await writeFile(c, CFG_PATH, await encryptJSON(key, c), existing.sha, "Настройки синхронизации");
    if (w.conflict) {
      existing = await readFile(c, CFG_PATH);
      await writeFile(c, CFG_PATH, await encryptJSON(key, c), existing.sha, "Настройки синхронизации");
    }
    cfg = c; await saveCfg();
    remoteSha = null; remoteEtag = null;
    await startSync();
    if (sync.state === "error") throw new Error(sync.error);
  }

  /* ---------- dialogs (lock screen, sync setup) ---------- */
  var dialogCss = null;
  function ensureCss() {
    if (dialogCss) return;
    dialogCss = document.createElement("style");
    dialogCss.textContent =
      ".sv-wrap{position:fixed;inset:0;z-index:100;background:var(--bg,#f2f4f7);display:flex;align-items:center;justify-content:center;padding:20px;overflow:auto}" +
      ".sv-wrap.sv-dim{background:rgba(10,14,20,.5)}" +
      ".sv-wrap form{background:var(--surface,#fff);color:var(--ink,#131a26);border-radius:16px;box-shadow:0 10px 40px rgba(0,0,0,.15);padding:26px 22px;width:min(460px,100%);display:flex;flex-direction:column;gap:13px;max-height:100%;overflow:auto}" +
      ".sv-wrap h1{font-family:var(--font-display,Georgia,serif);font-weight:400;font-size:25px;margin:0}" +
      ".sv-wrap p,.sv-wrap ol{margin:0;color:var(--muted,#596273);font-size:14px;line-height:1.5}.sv-wrap ol{padding-left:20px}" +
      ".sv-wrap a{color:var(--accent,#1d4a9e)}" +
      ".sv-wrap input[type=password],.sv-wrap input[type=text]{font:inherit;font-size:16px;padding:11px 12px;border:1px solid var(--line,#dce1e9);border-radius:10px;background:var(--surface,#fff);color:var(--ink,#131a26);width:100%}" +
      ".sv-wrap label{display:flex;gap:8px;align-items:center;font-size:14px}.sv-wrap .lab{display:block;font-size:12.5px;color:var(--muted,#596273);font-weight:500;margin-bottom:4px}" +
      ".sv-wrap .row{display:grid;grid-template-columns:1fr 1fr;gap:10px}" +
      ".sv-wrap .btns{display:flex;gap:8px}.sv-wrap .btns button{flex:1}" +
      ".sv-wrap button{font:inherit;font-weight:600;padding:12px;border:0;border-radius:10px;background:var(--accent,#1d4a9e);color:var(--on-accent,#fff);cursor:pointer}" +
      ".sv-wrap button.sec{background:var(--neutral-bg,#eceef2);color:var(--ink,#131a26)}" +
      ".sv-wrap button:disabled{opacity:.6}.sv-wrap .err{color:var(--bad,#b02e2e);font-size:14px;min-height:1.2em}";
    document.head.appendChild(dialogCss);
  }
  function esc(s) { return String(s == null ? "" : s).replace(/[&<>"']/g, function (ch) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]; }); }

  function lockScreen() {
    return new Promise(function (resolve) {
      ensureCss();
      var wrap = document.createElement("div");
      wrap.className = "sv-wrap"; wrap.id = "lock";
      wrap.innerHTML = '<form autocomplete="on"><h1>Учёт винтажа</h1><p>Введите пароль, чтобы открыть данные.</p>' +
        '<input type="text" name="username" value="uchet" autocomplete="username" hidden>' +
        '<input type="password" id="lockPw" autocomplete="current-password" placeholder="Пароль" aria-label="Пароль" required>' +
        '<label><input type="checkbox" id="lockRemember"> Запомнить на этом устройстве</label>' +
        '<div class="err" id="lockErr" role="alert"></div><button type="submit">Открыть</button></form>';
      document.body.appendChild(wrap);
      var form = wrap.querySelector("form"), pw = wrap.querySelector("#lockPw"), err = wrap.querySelector("#lockErr"), btn = wrap.querySelector("button");
      pw.focus();
      form.addEventListener("submit", async function (e) {
        e.preventDefault();
        if (!pw.value) return;
        btn.disabled = true; err.textContent = "Проверка…";
        try {
          var k = await deriveKey(pw.value, unb64(seedInfo.salt), seedInfo.iter);
          if (!(await tryUnlock(k))) { err.textContent = "Неверный пароль"; btn.disabled = false; pw.select(); return; }
          if (wrap.querySelector("#lockRemember").checked) lsSet(LS_KEY, b64(await crypto.subtle.exportKey("raw", k)));
          wrap.remove(); resolve();
        } catch (e3) { err.textContent = "Ошибка: " + (e3 && e3.message || e3); btn.disabled = false; }
      });
    });
  }
  async function tryUnlock(k) {
    var stored = null;
    try { stored = JSON.parse(lsGet(LS_DATA) || "null"); } catch (e) {}
    try {
      if (stored) data = norm(await decryptJSON(k, stored));
      else { data = norm(await decryptJSON(k, seedInfo)); key = k; await saveLocal(); }
      key = k; return true;
    } catch (e) { return false; }
  }

  function syncSetup() {
    ensureCss();
    var g = (cfg && { owner: cfg.owner, repo: cfg.repo }) || guessRepo() || { owner: "", repo: "" };
    var wrap = document.createElement("div");
    wrap.className = "sv-wrap sv-dim";
    wrap.innerHTML = '<form><h1>Синхронизация</h1>' +
      '<p>Данные хранятся в вашем репозитории GitHub в зашифрованном виде, и все устройства видят одни и те же данные. Настраивается один раз — на других устройствах достаточно пароля.</p>' +
      '<ol><li>Откройте <a href="https://github.com/settings/personal-access-tokens/new" target="_blank" rel="noopener">github.com → Settings → Fine-grained tokens</a>.</li>' +
      '<li>Repository access: <b>Only select repositories</b> → этот репозиторий.</li>' +
      '<li>Permissions → Repository → <b>Contents: Read and write</b>.</li>' +
      '<li>Expiration: на год. Нажмите <b>Generate token</b> и вставьте его ниже.</li></ol>' +
      '<div class="row"><div><span class="lab">Владелец (логин GitHub)</span><input type="text" id="syOwner" value="' + esc(g.owner) + '" autocapitalize="off" spellcheck="false"></div>' +
      '<div><span class="lab">Репозиторий</span><input type="text" id="syRepo" value="' + esc(g.repo) + '" autocapitalize="off" spellcheck="false"></div></div>' +
      '<div><span class="lab">Токен</span><input type="password" id="syToken" placeholder="github_pat_…" autocomplete="off" value="' + esc(cfg ? cfg.token : "") + '"></div>' +
      '<div class="err" id="syErr" role="alert"></div>' +
      '<div class="btns"><button type="button" class="sec" id="syCancel">Отмена</button><button type="submit" id="syOk">Подключить</button></div></form>';
    document.body.appendChild(wrap);
    var err = wrap.querySelector("#syErr"), ok = wrap.querySelector("#syOk");
    wrap.querySelector("#syCancel").onclick = function () { wrap.remove(); };
    wrap.addEventListener("click", function (e) { if (e.target === wrap) wrap.remove(); });
    wrap.querySelector("form").addEventListener("submit", async function (e) {
      e.preventDefault();
      var c = { owner: wrap.querySelector("#syOwner").value.trim(), repo: wrap.querySelector("#syRepo").value.trim(), token: wrap.querySelector("#syToken").value.trim() };
      if (!c.owner || !c.repo || !c.token) { err.textContent = "Заполните все три поля."; return; }
      ok.disabled = true; err.textContent = "Подключение…";
      try { await connect(c); wrap.remove(); }
      catch (e2) { err.textContent = "Не удалось: " + (e2 && e2.message || e2); ok.disabled = false; }
    });
    wrap.querySelector(g.owner ? "#syToken" : "#syOwner").focus();
  }

  /* ---------- startup ---------- */
  var ready = (async function () {
    if (!window.crypto || !crypto.subtle) throw new Error("Браузер не поддерживает шифрование (нужен HTTPS).");
    var r = await fetch("seed.enc.json", { cache: "no-store" });
    seedInfo = await r.json();
    var remembered = lsGet(LS_KEY);
    var unlocked = false;
    if (remembered) {
      try {
        var k = await crypto.subtle.importKey("raw", unb64(remembered), { name: "AES-GCM" }, true, ["encrypt", "decrypt"]);
        unlocked = await tryUnlock(k);
      } catch (e) {}
      if (!unlocked) lsDel(LS_KEY);
    }
    if (!unlocked) {
      if (document.readyState === "loading") await new Promise(function (r2) { document.addEventListener("DOMContentLoaded", r2); });
      await lockScreen();
    }
    initSync();
  })();

  /* ---------- db interface used by the app ---------- */
  var META = { fromCache: false, hasPendingWrites: false };
  function snapDoc(col, id) { var v = (data[col] || {})[id]; return { id: id, exists: !!v, data: function () { return v; }, metadata: META }; }
  function snapCol(col) {
    var docs = Object.keys(data[col] || {}).map(function (id) { return snapDoc(col, id); });
    return { docs: docs, size: docs.length, empty: !docs.length, metadata: META, docChanges: function () { return []; } };
  }
  function notify(col) {
    listeners.slice().forEach(function (l) {
      if (l.col !== col) return;
      try { l.fn(l.id ? snapDoc(col, l.id) : snapCol(col)); } catch (e) { console.error(e); }
    });
  }
  function ref(col, id) {
    return {
      id: id, path: col + "/" + id,
      set: async function (v) {
        await ready;
        var d = clone(v); d._ts = Date.now();
        data[col][id] = d; delete data._deleted[col + "/" + id];
        notify(col); await saveLocal(); markDirty();
      },
      delete: async function () {
        await ready;
        delete data[col][id]; data._deleted[col + "/" + id] = Date.now();
        notify(col); await saveLocal(); markDirty();
      },
      onSnapshot: function (fn) {
        var l = { col: col, id: id, fn: fn }; listeners.push(l);
        ready.then(function () { fn(snapDoc(col, id)); });
        return function () { var i = listeners.indexOf(l); if (i >= 0) listeners.splice(i, 1); };
      }
    };
  }
  function newId() { return Date.now().toString(36) + Math.random().toString(36).slice(2, 8); }
  var db = {
    collection: function (col) {
      return {
        path: col,
        doc: function (id) { return ref(col, id || newId()); },
        onSnapshot: function (fn) {
          var l = { col: col, fn: fn }; listeners.push(l);
          ready.then(function () { fn(snapCol(col)); });
          return function () { var i = listeners.indexOf(l); if (i >= 0) listeners.splice(i, 1); };
        }
      };
    },
    doc: function (p) { var s = p.split("/"); return ref(s[0], s[1]); }
  };
  var downloads = {
    save: async function (req) {
      var type = /\.json$/.test(req.filename) ? "application/json" : "text/csv;charset=utf-8";
      var blob = req.data instanceof Blob ? req.data : new Blob([req.data], { type: type });
      var url = URL.createObjectURL(blob), a = document.createElement("a");
      a.href = url; a.download = req.filename; document.body.appendChild(a); a.click(); a.remove();
      setTimeout(function () { URL.revokeObjectURL(url); }, 3000);
      return { status: "saved" };
    }
  };
  var user = { can: async function () { return true; }, isOwner: function () { return true; }, canEdit: function () { return true; } };

  window.claude = {
    use: async function (name) {
      if (name === "db") { await ready; return db; }
      return name === "downloads" ? downloads : name === "user" ? user : null;
    }
  };
  window.__store = {
    ready: ready,
    mode: "local",
    sync: sync,
    syncSetup: syncSetup,
    syncNow: function () { return syncNow(); },
    exportAll: function () { var d = clone(data); delete d._deleted; COLS.forEach(function (c) { for (var id in d[c]) delete d[c][id]._ts; }); return d; },
    importAll: async function (obj) {
      await ready;
      var incoming = norm(clone(obj)), now = Date.now();
      COLS.forEach(function (c) {
        Object.keys(data[c]).forEach(function (id) { if (!incoming[c][id]) data._deleted[c + "/" + id] = now; });
        Object.keys(incoming[c]).forEach(function (id) { incoming[c][id]._ts = now; delete data._deleted[c + "/" + id]; });
      });
      incoming._deleted = data._deleted;
      data = incoming;
      COLS.forEach(notify); await saveLocal(); markDirty();
    },
    lock: function () { lsDel(LS_KEY); location.reload(); }
  };
})();
