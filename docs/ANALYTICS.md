# Analytics — Google Tag Manager + Consent Mode v2

Analytics are **ON** via Google Tag Manager container **`GTM-W488FK5H`**
(configured in `docs/site-config.json`). GA4 lives **inside** the container, so
there is no GA4 ID on the page (`ga4` stays empty).

## How it behaves on the site

- `docs/analytics.js` loads GTM **once per page** on every page under `docs/`
  (landing, scorecard, anything else that includes it). It finds
  `site-config.json` next to itself, so it works from any folder depth.
- **Consent Mode v2:** before GTM loads, all signals are set to **denied**
  (`ad_storage`, `ad_user_data`, `ad_personalization`, `analytics_storage`).
  The container still loads (privacy-safe), but tags gated on consent collect
  nothing until granted.
- A **consent banner** (Accept / Decline) shows once. **Accept** →
  `analytics_storage = granted` (ads stay denied); **Decline** → stays denied.
  The choice is remembered in `localStorage` (`aisa-analytics-consent`).
- The standard GTM `<noscript>` iframe is inserted right after `<body>`.

## Events pushed to `dataLayer` (wire these as triggers in GTM)

| Event name | Fires when | Extra keys |
|---|---|---|
| `prompt_copy` | a prompt / deep-pass is copied | `mode`, `type` |
| `install_copy` | a CLI install command is copied | `os` |
| `scorecard_open` | a scorecard link is opened | — |
| `pdf_download` | the executive PDF is opened | — |
| `github_click` | a GitHub link is clicked | — |
| `issue_click` | "Report an issue" is clicked | — |

## Set up the container (do this once in the GTM UI, then Publish)

1. **GA4 Configuration tag**
   - Tags → New → **Google Analytics: GA4 Configuration**.
   - Measurement ID: your `G-XXXXXXXXXX`.
   - Trigger: **Initialization - All Pages** (or All Pages).
   - (Consent: it already respects Consent Mode; collection waits for
     `analytics_storage = granted`.)

2. **One GA4 Event tag per custom event** (six total)
   For each row in the table above:
   - Tags → New → **Google Analytics: GA4 Event**.
   - Configuration tag: the GA4 Configuration tag from step 1.
   - Event Name: the event name (e.g. `prompt_copy`).
   - Event Parameters: add the extra keys as **Data Layer Variables** —
     e.g. for `prompt_copy` add parameters `mode` → `{{DLV - mode}}` and
     `type` → `{{DLV - type}}`; for `install_copy` add `os` → `{{DLV - os}}`.
   - Trigger: a **Custom Event** trigger whose "Event name" equals the event
     (e.g. `prompt_copy`).

   Create the Data Layer Variables once (Variables → New → Data Layer Variable):
   `mode`, `type`, `os`. Reuse them across the event tags.

3. **Custom Event triggers** (six)
   Triggers → New → **Custom Event**, "Event name" = `prompt_copy`,
   `install_copy`, `scorecard_open`, `pdf_download`, `github_click`,
   `issue_click` (one each). Fires on: All Custom Events.

4. **Publish** the container (Submit → Publish). Use **Preview** first to confirm
   the GA4 tags fire on copy/click and that consent flips to granted after Accept.

## To change or disable

- Different container: edit `gtm` in `docs/site-config.json` and push.
- Turn everything off: blank both `ga4` and `gtm` in `site-config.json` and push —
  `analytics.js` then loads nothing and shows no banner.

## Privacy stance

Advertising storage/personalization are **never** granted. Only anonymous usage
(which prompts/links are clicked) is measured, and only after Accept. The page
still runs no code on your source and sends your code nowhere.
