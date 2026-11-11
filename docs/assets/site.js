/* AI-Security-Audit-Skills landing behaviour | Rise With VJ | MIT. No external calls except the GitHub star count (fails gracefully). */
(function () {
  "use strict";
  var REPO = "risewithvj/AI-Security-Audit-Skills";

  /* ---------- analytics-safe event push (loads nothing; analytics.js consumes dataLayer) ---------- */
  window.dataLayer = window.dataLayer || [];
  function track(name, params) {
    var ev = { event: name };
    if (params) for (var k in params) ev[k] = params[k];
    window.dataLayer.push(ev);
  }
  // Delegate clicks carrying data-event
  document.addEventListener("click", function (e) {
    var el = e.target.closest ? e.target.closest("[data-event]") : null;
    if (!el) return;
    var p = {};
    for (var i = 0; i < el.attributes.length; i++) {
      var a = el.attributes[i];
      if (a.name.indexOf("data-p-") === 0) p[a.name.slice(7)] = a.value;
    }
    track(el.getAttribute("data-event"), p);
  });

  /* ---------- theme ---------- */
  var root = document.documentElement;
  var saved = null;
  try { saved = localStorage.getItem("aisa-theme"); } catch (e) {}
  if (saved) root.setAttribute("data-theme", saved);
  var themeBtn = document.getElementById("theme-btn");
  function syncTheme() {
    var t = root.getAttribute("data-theme") === "light" ? "light" : "dark";
    if (themeBtn) { themeBtn.textContent = t === "light" ? "☾" : "☀"; themeBtn.setAttribute("aria-label", "Switch to " + (t === "light" ? "dark" : "light") + " mode"); }
  }
  if (themeBtn) themeBtn.addEventListener("click", function () {
    var t = root.getAttribute("data-theme") === "light" ? "dark" : "light";
    root.setAttribute("data-theme", t);
    try { localStorage.setItem("aisa-theme", t); } catch (e) {}
    syncTheme();
  });
  syncTheme();

  /* ---------- mobile menu ---------- */
  var menuBtn = document.getElementById("menu-btn");
  var navLinks = document.getElementById("nav-links");
  if (menuBtn && navLinks) {
    menuBtn.addEventListener("click", function () {
      var open = navLinks.classList.toggle("open");
      menuBtn.setAttribute("aria-expanded", open ? "true" : "false");
    });
    navLinks.addEventListener("click", function (e) { if (e.target.tagName === "A") navLinks.classList.remove("open"); });
  }

  /* ---------- live GitHub star count (graceful) ---------- */
  (function () {
    var el = document.getElementById("star-count");
    if (!el || !window.fetch) return;
    fetch("https://api.github.com/repos/" + REPO, { headers: { Accept: "application/vnd.github+json" } })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) {
        if (d && typeof d.stargazers_count === "number") {
          var n = d.stargazers_count;
          el.textContent = n >= 1000 ? (n / 1000).toFixed(1).replace(/\.0$/, "") + "k" : String(n);
        }
      })
      .catch(function () { /* leave the static star glyph */ });
  })();

  /* ---------- copy helper with "Copied ✓" ---------- */
  function flash(btn) {
    var base = btn.getAttribute("data-label") || btn.innerHTML;
    if (!btn.getAttribute("data-label")) btn.setAttribute("data-label", base);
    btn.innerHTML = "Copied ✓"; btn.classList.add("ok");
    setTimeout(function () { btn.innerHTML = btn.getAttribute("data-label"); btn.classList.remove("ok"); }, 1600);
  }
  function copy(text, btn) {
    function fb() {
      var ta = document.createElement("textarea");
      ta.value = text; ta.style.position = "fixed"; ta.style.top = "-1000px";
      document.body.appendChild(ta); ta.select();
      try { document.execCommand("copy"); flash(btn); } catch (e) { btn.textContent = "Copy failed"; }
      document.body.removeChild(ta);
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () { flash(btn); }, fb);
    } else fb();
  }
  // generic copy buttons (install commands etc.)
  Array.prototype.forEach.call(document.querySelectorAll("[data-copy]"), function (btn) {
    btn.addEventListener("click", function () { copy(btn.getAttribute("data-copy"), btn); });
  });

  /* ---------- prompt picker ---------- */
  var DATA = window.AISA_PROMPTS || { prompts: [], deep_pack: [] };
  var byId = {};
  (DATA.prompts || []).forEach(function (p) { byId[p.id] = p; });

  var ICONS = {
    auto: "M12 2a10 10 0 100 20 10 10 0 000-20zm0 3v7l5 3",
    webapp: "M3 4h18v14H3zM3 9h18M7 21h10",
    api: "M4 7l-3 5 3 5M20 7l3 5-3 5M14 4l-4 16",
    wordpress: "M12 2a10 10 0 100 20 10 10 0 000-20zm-7 10l4 10M12 6l4 12",
    appsscript: "M8 4h8l4 8-4 8H8l-4-8z",
    mobile: "M7 2h10v20H7zM11 18h2",
    "ai-app": "M12 2v4M5 8h14v10H5zM9 12h.01M15 12h.01M9 15h6",
    extension: "M4 4h7v4a2 2 0 104 0V4h5v5h-4a2 2 0 100 4h4v7H4z",
    ecommerce: "M3 3h2l2 13h11l2-9H6M9 21h.01M18 21h.01",
    baas: "M4 6c0-2 4-3 8-3s8 1 8 3-4 3-8 3-8-1-8-3zM4 6v12c0 2 4 3 8 3s8-1 8-3V6",
    dpdp: "M12 2l8 4v6c0 5-3.5 8-8 10-4.5-2-8-5-8-10V6z"
  };
  var CAT_DESC = {
    auto: "Lets the AI detect your stack and apply the matching focus.",
    webapp: "Sessions, auth, XSS, CSRF, access control, client-side tampering.",
    api: "AuthN/Z, object-level access, injection, rate limits, editable bodies.",
    wordpress: "Plugins/themes, nonces, capabilities, unsafe option/meta handling.",
    appsscript: "google.script.run exposure, scopes, web-app access settings.",
    mobile: "Hardcoded secrets, insecure storage, transport, API trust.",
    "ai-app": "Prompt injection, tool abuse, secret leakage, unsafe output.",
    extension: "Permissions, content-script injection, message-passing trust.",
    ecommerce: "Prices, coupons, roles, limits trusted from the client; payments.",
    baas: "Row-level security / rules, exposed keys, over-broad client access.",
    dpdp: "India DPDP: notice, consent, retention, erasure, rights, transfers."
  };
  var CAT_NAME = {
    auto: "Auto-detect", webapp: "Web app", api: "API / backend", wordpress: "WordPress",
    appsscript: "Apps Script", mobile: "Mobile app", "ai-app": "AI / LLM app",
    extension: "Browser extension", ecommerce: "E-commerce", baas: "Supabase / Firebase", dpdp: "DPDP only"
  };
  function icon(name) {
    var d = ICONS[name] || ICONS.auto;
    return '<svg class="ico" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="' + d + '"/></svg>';
  }
  function promptText(type, mode) {
    var p = byId[type + "-" + mode];
    return p ? p.text : "";
  }

  var grid = document.getElementById("cat-grid");
  var deepWrap = document.getElementById("deep-grid");
  var tabs = document.querySelectorAll(".tab");
  var topPanel = document.getElementById("picker-top");
  var topPre = document.getElementById("picker-pre");
  var topMode = document.getElementById("picker-mode");
  var topType = document.getElementById("picker-type");
  var topCopy = document.getElementById("picker-copy");
  var state = { mode: "pro", type: "auto" };

  function renderTop() {
    if (!topPre) return;
    topPre.textContent = promptText(state.type, state.mode);
    if (topMode) topMode.textContent = state.mode;
    if (topType) topType.textContent = state.type;
    if (topCopy) { topCopy.setAttribute("data-p-mode", state.mode); topCopy.setAttribute("data-p-type", state.type); }
  }
  function renderCats() {
    if (!grid) return;
    grid.innerHTML = "";
    (DATA.types || []).forEach(function (type) {
      var card = document.createElement("div");
      card.className = "cat-card glass";
      var text = promptText(type, state.mode);
      card.innerHTML =
        '<div class="ch"><span class="ic">' + icon(type) + '</span><h3>' + (CAT_NAME[type] || type) + "</h3></div>" +
        '<div class="mt">' + state.mode.toUpperCase() + " · TYPE=" + type + "</div>" +
        "<p>" + (CAT_DESC[type] || "") + "</p>";
      var b = document.createElement("button");
      b.className = "copy sm"; b.type = "button"; b.textContent = "Copy prompt";
      b.setAttribute("data-event", "prompt_copy");
      b.setAttribute("data-p-mode", state.mode); b.setAttribute("data-p-type", type);
      b.addEventListener("click", function () { copy(text, b); });
      card.appendChild(b);
      grid.appendChild(card);
    });
  }
  function renderDeep() {
    if (!deepWrap) return;
    deepWrap.innerHTML = "";
    (DATA.deep_pack || []).forEach(function (d) {
      var el = document.createElement("div"); el.className = "deep-card glass";
      var head = document.createElement("div"); head.className = "dh";
      head.innerHTML = '<h3><span class="pn">Pass ' + d.pass + " of 4</span>" + d.title + "</h3>";
      var b = document.createElement("button");
      b.className = "copy sm"; b.type = "button"; b.textContent = "Copy pass " + d.pass;
      b.setAttribute("data-event", "prompt_copy");
      b.setAttribute("data-p-mode", "deep"); b.setAttribute("data-p-type", "pass" + d.pass);
      b.addEventListener("click", function () { copy(d.text, b); });
      head.appendChild(b);
      var pre = document.createElement("pre"); pre.className = "prompt"; pre.textContent = d.text;
      el.appendChild(head); el.appendChild(pre);
      deepWrap.appendChild(el);
    });
  }
  function selectTab(mode) {
    var deep = mode === "deep";
    tabs.forEach(function (t) { t.setAttribute("aria-selected", t.getAttribute("data-mode") === mode ? "true" : "false"); });
    if (topPanel) topPanel.style.display = deep ? "none" : "";
    if (grid) grid.style.display = deep ? "none" : "";
    if (deepWrap) deepWrap.style.display = deep ? "" : "none";
    if (!deep) { state.mode = mode; renderTop(); renderCats(); }
  }
  tabs.forEach(function (t) {
    t.addEventListener("click", function () { selectTab(t.getAttribute("data-mode")); });
    t.addEventListener("keydown", function (e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); selectTab(t.getAttribute("data-mode")); } });
  });
  if (topCopy) topCopy.addEventListener("click", function () { copy(topPre.textContent, topCopy); });

  // initial render (no empty boxes)
  renderDeep();
  selectTab("pro");
})();
