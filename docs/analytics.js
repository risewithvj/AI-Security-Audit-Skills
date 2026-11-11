/* Analytics loader — Google Tag Manager + Consent Mode v2.
   Reads site-config.json (located next to this script, so it works on every page
   under docs/: landing, scorecard, etc.). GTM loads once per page with all consent
   signals DENIED by default; Accept grants analytics_storage only (ads stay denied).
   The choice is remembered in localStorage. If no GTM/GA4 id is set, nothing loads.
   See docs/ANALYTICS.md. | Rise With VJ | MIT */
(function () {
  "use strict";
  window.dataLayer = window.dataLayer || [];
  function gtag() { window.dataLayer.push(arguments); }
  var CONSENT_KEY = "aisa-analytics-consent";

  // Resolve site-config.json relative to THIS script's own URL (robust across pages).
  var me = document.currentScript ||
    (function () { var s = document.getElementsByTagName("script"); return s[s.length - 1]; })();
  var base = (me && me.src) ? me.src.replace(/[^/]*$/, "") : "";

  var gtmLoaded = false;
  function loadGTM(id) {
    if (gtmLoaded) return;            // once per page, never twice
    gtmLoaded = true;

    // Consent Mode v2 — DENIED by default, set BEFORE GTM loads.
    gtag("consent", "default", {
      ad_storage: "denied",
      ad_user_data: "denied",
      ad_personalization: "denied",
      analytics_storage: "denied",
      wait_for_update: 500
    });
    // Honor a remembered Accept immediately (ads stay denied).
    var prior = null;
    try { prior = localStorage.getItem(CONSENT_KEY); } catch (e) {}
    if (prior === "accepted") gtag("consent", "update", { analytics_storage: "granted" });

    // Standard GTM snippet (gtm.js).
    window.dataLayer.push({ "gtm.start": +new Date(), event: "gtm.js" });
    var s = document.createElement("script");
    s.async = true;
    s.src = "https://www.googletagmanager.com/gtm.js?id=" + id;
    document.head.appendChild(s);

    // Standard GTM <noscript> iframe, inserted right after <body>, once.
    if (!document.getElementById("gtm-ns")) {
      var ns = document.createElement("noscript"); ns.id = "gtm-ns";
      var f = document.createElement("iframe");
      f.src = "https://www.googletagmanager.com/ns.html?id=" + id;
      f.height = "0"; f.width = "0"; f.style.display = "none"; f.style.visibility = "hidden";
      ns.appendChild(f);
      document.body.insertBefore(ns, document.body.firstChild);
    }
  }

  function grant() { gtag("consent", "update", { analytics_storage: "granted" }); }

  function showBanner() {
    var el = document.getElementById("consent");
    if (!el) return;                 // page has no banner markup -> leave denied
    el.classList.add("show");
    var acc = el.querySelector(".accept"), dec = el.querySelector(".decline");
    if (acc) acc.addEventListener("click", function () {
      try { localStorage.setItem(CONSENT_KEY, "accepted"); } catch (e) {}
      grant(); el.classList.remove("show");
    });
    if (dec) dec.addEventListener("click", function () {
      try { localStorage.setItem(CONSENT_KEY, "declined"); } catch (e) {}
      el.classList.remove("show");   // stays denied
    });
  }

  if (!window.fetch) return;
  fetch(base + "site-config.json", { cache: "no-store" })
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (cfg) {
      if (!cfg) return;
      var id = cfg.gtm || cfg.ga4;   // prefer GTM; GA4 would also route here if ever set
      if (!id) return;               // OFF: nothing loads, no banner
      loadGTM(id);                   // loads with consent DENIED by default (privacy-safe)
      var choice = null;
      try { choice = localStorage.getItem(CONSENT_KEY); } catch (e) {}
      if (choice !== "accepted" && choice !== "declined") showBanner();
    })
    .catch(function () {});
})();
