/* AI-Security-Audit-Skills landing | Vijaya Kumar L (Rise With VJ) | github.com/risewithvj | MIT */
(function () {
  "use strict";
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };
  var DATA = window.AISA_PROMPTS || { prompts: [], types: [], deep_pack: [] };
  window.dataLayer = window.dataLayer || [];
  function track(name, params) { var o = { event: name }; for (var k in params) o[k] = params[k]; window.dataLayer.push(o); }

  /* ---------- analytics delegation ---------- */
  document.addEventListener("click", function (e) {
    var el = e.target.closest && e.target.closest("[data-event]");
    if (!el || el.id === "copy" || el.classList.contains("copy")) return; // copies tracked on success
    track(el.getAttribute("data-event"), { link: el.getAttribute("href") || "" });
  });

  /* ---------- theme ---------- */
  var root = document.documentElement;
  $("#theme").addEventListener("click", function () {
    var t = root.getAttribute("data-theme") === "light" ? "dark" : "light";
    root.setAttribute("data-theme", t);
    try { localStorage.setItem("aisa-theme", t); } catch (e) {}
  });

  /* ---------- header: scroll state, mobile menu, dropdown, active link ---------- */
  var hdr = $("#hdr"), nav = $("#nav"), burger = $("#burger");
  function onScroll() { hdr.classList.toggle("scrolled", window.scrollY > 8); }
  window.addEventListener("scroll", onScroll, { passive: true }); onScroll();
  burger.addEventListener("click", function () {
    var open = !nav.classList.contains("open");
    nav.classList.toggle("open", open);
    burger.setAttribute("aria-expanded", String(open));
    burger.setAttribute("aria-label", open ? "Close menu" : "Open menu");
  });
  nav.addEventListener("click", function (e) {
    if (e.target.closest("a")) { nav.classList.remove("open"); burger.setAttribute("aria-expanded", "false"); }
  });
  var dd = $(".dd"), ddBtn = $(".dd-btn");
  ddBtn.addEventListener("click", function (e) {
    e.stopPropagation();
    var open = !dd.classList.contains("open");
    dd.classList.toggle("open", open); ddBtn.setAttribute("aria-expanded", String(open));
  });
  document.addEventListener("click", function (e) { if (!dd.contains(e.target)) { dd.classList.remove("open"); ddBtn.setAttribute("aria-expanded", "false"); } });
  document.addEventListener("keydown", function (e) {
    if (e.key !== "Escape") return;
    dd.classList.remove("open"); ddBtn.setAttribute("aria-expanded", "false");
    nav.classList.remove("open"); burger.setAttribute("aria-expanded", "false"); closeLb();
  });
  if ("IntersectionObserver" in window) {
    var links = $$('.nav>a[href^="#"]');
    var map = {}; links.forEach(function (a) { map[a.getAttribute("href").slice(1)] = a; });
    var io = new IntersectionObserver(function (ents) {
      ents.forEach(function (en) {
        if (en.isIntersecting && map[en.target.id]) { links.forEach(function (a) { a.classList.remove("active"); }); map[en.target.id].classList.add("active"); }
      });
    }, { rootMargin: "-45% 0px -50% 0px" });
    Object.keys(map).forEach(function (id) { var s = document.getElementById(id); if (s) io.observe(s); });
  }

  /* ---------- GitHub stars ---------- */
  if (window.fetch) {
    fetch("https://api.github.com/repos/risewithvj/AI-Security-Audit-Skills")
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) { if (d && typeof d.stargazers_count === "number") $("#stars").textContent = "★ " + d.stargazers_count; })
      .catch(function () {});
  }

  /* ---------- toast + copy ---------- */
  var toastT;
  function toast(msg) { var t = $("#toast"); t.textContent = msg; t.classList.add("show"); clearTimeout(toastT); toastT = setTimeout(function () { t.classList.remove("show"); }, 1800); }
  function copyText(text, btn, evt, params) {
    function done() {
      if (btn) { var l = btn.getAttribute("data-label") || btn.textContent; btn.setAttribute("data-label", l); btn.textContent = "Copied ✓"; btn.classList.add("ok"); setTimeout(function () { btn.textContent = l; btn.classList.remove("ok"); }, 1600); }
      toast("Copied. Paste it into your AI with your zip.");
      if (evt) track(evt, params || {});
    }
    function fallback() {
      var ta = document.createElement("textarea"); ta.value = text; ta.setAttribute("readonly", ""); ta.style.position = "fixed"; ta.style.opacity = "0";
      document.body.appendChild(ta); ta.select(); try { document.execCommand("copy"); done(); } catch (e) { toast("Press Ctrl+C to copy"); } document.body.removeChild(ta);
    }
    if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(text).then(done, fallback); else fallback();
  }
  $$("[data-copy]").forEach(function (b) {
    b.addEventListener("click", function () { copyText(b.getAttribute("data-copy"), b, b.getAttribute("data-event"), { os: b.getAttribute("data-os") || "" }); });
  });

  /* ---------- prompt studio ---------- */
  var TYPES = [
    ["auto", "Not sure (auto-detect)"], ["webapp", "Web app"], ["api", "API / backend"], ["ecommerce", "E-commerce / payments"],
    ["baas", "Supabase / Firebase"], ["ai-app", "AI / LLM / chatbot"], ["wordpress", "WordPress"], ["appsscript", "Google Apps Script"],
    ["mobile", "Mobile app"], ["extension", "Browser extension"], ["dpdp", "DPDP audit only"]
  ];
  var NOTES = {
    lite: "Free AIs. Top risks only, one-page report. Quick and light on usage.",
    pro: "Paid AIs. Full VAPT plus browser-console tampering, hardening notes, and DPDP when personal data is found.",
    god: "Paid AIs. Everything in Pro plus a self-refutation pass, risk chains, an impact scenario and a fix-priority roadmap.",
    deep: "Paid AIs, best coverage. Four focused passes in the same chat. Send pass 1, then reply “next” after each report."
  };
  var byId = {}; (DATA.prompts || []).forEach(function (p) { byId[p.id] = p; });
  var state = { type: "auto", mode: "pro" };
  try { var saved = JSON.parse(localStorage.getItem("aisa-picker") || "null"); if (saved && saved.type && saved.mode) state = saved; } catch (e) {}

  var typesEl = $("#types");
  TYPES.forEach(function (t) {
    var b = document.createElement("button");
    b.type = "button"; b.className = "chip"; b.setAttribute("role", "radio"); b.setAttribute("data-type", t[0]); b.textContent = t[1];
    b.addEventListener("click", function () { state.type = t[0]; render(); });
    typesEl.appendChild(b);
  });
  $$("#modes button").forEach(function (b) { b.addEventListener("click", function () { state.mode = b.getAttribute("data-mode"); render(); }); });
  $("#pname").addEventListener("input", function () { render(true); });

  function withName(text) {
    var n = ($("#pname").value || "").trim().replace(/[<>]/g, "");
    return text.replace(/Prepared by:[^\n]*/i, "Prepared by: " + (n || "Requested by user") + ".");
  }
  function current() {
    if (state.mode === "deep") return null;
    var p = byId[state.type + "-" + state.mode] || byId["auto-" + state.mode];
    return p ? withName(p.text) : "";
  }
  function deepText(p) {
    var t = p.text;
    if (state.type !== "auto" && p.pass === 1) t = t.replace("TYPE=auto", "TYPE=" + state.type);
    return t;
  }
  function render(onlyText) {
    if (!onlyText) {
      $$("#types .chip").forEach(function (c) { c.setAttribute("aria-checked", String(c.getAttribute("data-type") === state.type)); });
      $$("#modes button").forEach(function (b) { b.setAttribute("aria-selected", String(b.getAttribute("data-mode") === state.mode)); });
      $("#mode-note").textContent = NOTES[state.mode];
      try { localStorage.setItem("aisa-picker", JSON.stringify(state)); } catch (e) {}
    }
    var out = $("#out"), label = (TYPES.filter(function (t) { return t[0] === state.type; })[0] || TYPES[0])[1];
    if (state.mode === "deep") {
      $("#out-title").textContent = "Deep 4-pass · " + label;
      $("#copy").textContent = "Copy pass 1"; $("#copy").setAttribute("data-label", "Copy pass 1");
      out.innerHTML = "";
      (DATA.deep_pack || []).forEach(function (p) {
        var box = document.createElement("div"); box.className = "deep-pass";
        var hd = document.createElement("div"); hd.className = "dp-hd";
        var h = document.createElement("b"); h.textContent = "Pass " + p.pass + " · " + p.title;
        var btn = document.createElement("button"); btn.type = "button"; btn.className = "btn sm ghost"; btn.textContent = "Copy";
        var txt = deepText(p);
        btn.addEventListener("click", function () { copyText(txt, btn, "prompt_copy", { mode: "deep", type: state.type, pass: p.pass }); });
        hd.appendChild(h); hd.appendChild(btn);
        var pre = document.createElement("pre"); pre.className = "prompt"; pre.textContent = txt;
        box.appendChild(hd); box.appendChild(pre); out.appendChild(box);
      });
    } else {
      $("#out-title").textContent = label + " · " + ({ lite: "Lite", pro: "Pro", god: "God Mode" })[state.mode];
      $("#copy").textContent = "Copy prompt"; $("#copy").setAttribute("data-label", "Copy prompt");
      if (!$("#prompt")) { out.innerHTML = '<pre class="prompt" id="prompt" tabindex="0"></pre>'; }
      $("#prompt").textContent = current() || "Prompt not found. Use the paste-in versions below.";
    }
  }
  $("#copy").addEventListener("click", function () {
    var text = state.mode === "deep" ? deepText((DATA.deep_pack || [])[0] || { text: "" }) : current();
    copyText(text, $("#copy"), "prompt_copy", { mode: state.mode, type: state.type });
  });
  $("#dl").addEventListener("click", function () {
    var text = state.mode === "deep"
      ? (DATA.deep_pack || []).map(function (p) { return "===== PASS " + p.pass + ": " + p.title + " =====\n" + deepText(p); }).join("\n\n")
      : current();
    var a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
    a.download = "aisa-prompt-" + state.type + "-" + state.mode + ".txt";
    document.body.appendChild(a); a.click(); setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 500);
    track("prompt_download", { mode: state.mode, type: state.type });
  });
  render();

  /* ---------- lightbox ---------- */
  var lb = $("#lb"), lbImg = $("#lb-img"), lastFocus = null;
  function openLb(src, cap) { lastFocus = document.activeElement; lbImg.src = src; lbImg.alt = cap; $("#lb-cap").textContent = cap; lb.hidden = false; $(".lb-x").focus(); document.body.style.overflow = "hidden"; }
  function closeLb() { if (lb.hidden) return; lb.hidden = true; lbImg.src = ""; document.body.style.overflow = ""; if (lastFocus) lastFocus.focus(); }
  $$(".th").forEach(function (b) { b.addEventListener("click", function () { openLb(b.getAttribute("data-full"), b.getAttribute("data-cap")); track("report_preview", { page: b.getAttribute("data-cap") }); }); });
  $(".lb-x").addEventListener("click", closeLb);
  lb.addEventListener("click", function (e) { if (e.target === lb) closeLb(); });

  /* ---------- reveal + bars ---------- */
  var rv = $$(".sec .card, .ob, .it, .stat");
  if ("IntersectionObserver" in window && !window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    rv.forEach(function (el) { el.classList.add("rv"); });
    var io2 = new IntersectionObserver(function (ents) {
      ents.forEach(function (en) { if (en.isIntersecting) { en.target.classList.add("in"); io2.unobserve(en.target); } });
    }, { rootMargin: "0px 0px -8% 0px" });
    rv.forEach(function (el) { io2.observe(el); });
  } else { $(".bench").classList.add("in"); }
})();
