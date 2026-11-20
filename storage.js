/* Storage adapter — GitHub Pages edition.
   No server: data lives in this browser (localStorage), encrypted with the password.
   The starting data (seed.enc.json) is encrypted too: AES-GCM 256, key from PBKDF2-SHA256. */
(function () {
  "use strict";
  var COLS = ["boxes", "items", "ledger", "meta"];
  var LS_DATA = "uchet-vintazha-enc-v1";
  var LS_KEY = "uchet-vintazha-key-v1";
  var mode = "local";
  var data = empty();
  var listeners = [];
  var key = null;
  var seedInfo = null;

  function empty() { return { boxes: {}, items: {}, ledger: {}, meta: {} }; }
  function norm(d) { var o = empty(); COLS.forEach(function (c) { if (d && d[c] && typeof d[c] === "object") o[c] = d[c]; }); return o; }
  function clone(o) { return JSON.parse(JSON.stringify(o)); }
  function b64(buf) { var s = "", b = new Uint8Array(buf); for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); return btoa(s); }
  function unb64(str) { var s = atob(str), b = new Uint8Array(s.length); for (var i = 0; i < s.length; i++) b[i] = s.charCodeAt(i); return b; }

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

  /* ---------- local persistence (encrypted) ---------- */
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

  /* ---------- lock screen ---------- */
  function lockScreen() {
    return new Promise(function (resolve) {
      var css = document.createElement("style");
      css.textContent =
        "#lock{position:fixed;inset:0;z-index:100;background:var(--bg,#f2f4f7);display:flex;align-items:center;justify-content:center;padding:20px}" +
        "#lock form{background:var(--surface,#fff);border-radius:16px;box-shadow:0 10px 40px rgba(0,0,0,.12);padding:28px 24px;width:min(380px,100%);display:flex;flex-direction:column;gap:14px}" +
        "#lock h1{font-family:var(--font-display,Georgia,serif);font-weight:400;font-size:26px;margin:0}" +
        "#lock p{margin:0;color:var(--muted,#596273);font-size:14px}" +
        "#lock input[type=password]{font-size:16px;padding:11px 12px;border:1px solid var(--line,#dce1e9);border-radius:10px;background:var(--surface,#fff);color:var(--ink,#131a26)}" +
        "#lock label{display:flex;gap:8px;align-items:center;font-size:14px}" +
        "#lock button{font:inherit;font-weight:600;padding:12px;border:0;border-radius:10px;background:var(--accent,#1d4a9e);color:var(--on-accent,#fff);cursor:pointer}" +
        "#lock button:disabled{opacity:.6}#lock .err{color:var(--bad,#b02e2e);font-size:14px;min-height:1.2em}";
      document.head.appendChild(css);
      var wrap = document.createElement("div");
      wrap.id = "lock";
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
          var ok = await tryUnlock(k);
          if (!ok) { err.textContent = "Неверный пароль"; btn.disabled = false; pw.select(); return; }
          if (wrap.querySelector("#lockRemember").checked) {
            try { localStorage.setItem(LS_KEY, b64(await crypto.subtle.exportKey("raw", k))); } catch (e2) {}
          }
          wrap.remove(); css.remove(); resolve();
        } catch (e3) { err.textContent = "Ошибка: " + (e3 && e3.message || e3); btn.disabled = false; }
      });
    });
  }
  async function tryUnlock(k) {
    var stored = null;
    try { stored = JSON.parse(localStorage.getItem(LS_DATA) || "null"); } catch (e) {}
    try {
      if (stored) data = norm(await decryptJSON(k, stored));
      else { data = norm(await decryptJSON(k, seedInfo)); key = k; await saveLocal(); }
      key = k; return true;
    } catch (e) { return false; }
  }

  var ready = (async function () {
    if (!window.crypto || !crypto.subtle) throw new Error("Браузер не поддерживает шифрование (нужен HTTPS).");
    var r = await fetch("seed.enc.json", { cache: "no-store" });
    seedInfo = await r.json();
    var remembered = null;
    try { remembered = localStorage.getItem(LS_KEY); } catch (e) {}
    if (remembered) {
      try {
        var k = await crypto.subtle.importKey("raw", unb64(remembered), { name: "AES-GCM" }, true, ["encrypt", "decrypt"]);
        if (await tryUnlock(k)) return;
      } catch (e) {}
      try { localStorage.removeItem(LS_KEY); } catch (e) {}
    }
    if (document.readyState === "loading") await new Promise(function (r2) { document.addEventListener("DOMContentLoaded", r2); });
    await lockScreen();
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
  function notifyAll() { COLS.forEach(notify); }
  function ref(col, id) {
    return {
      id: id, path: col + "/" + id,
      set: async function (v) { await ready; data[col][id] = clone(v); notify(col); await saveLocal(); },
      delete: async function () { await ready; delete data[col][id]; notify(col); await saveLocal(); },
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
    get mode() { return mode; },
    exportAll: function () { return clone(data); },
    importAll: async function (obj) { await ready; data = norm(clone(obj)); notifyAll(); await saveLocal(); },
    lock: function () { try { localStorage.removeItem(LS_KEY); } catch (e) {} location.reload(); }
  };
})();
