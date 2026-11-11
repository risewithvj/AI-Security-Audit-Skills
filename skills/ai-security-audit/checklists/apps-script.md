<!--
  AI-Security-Audit-Skills
  Author   : Vijaya Kumar L  (Rise With VJ)
  GitHub   : https://github.com/risewithvj
  LinkedIn : https://www.linkedin.com/in/vijayakumarl/
  License  : MIT
-->

# Google Apps Script checklist

Auto-selected when `apps_script` is detected (an `appsscript.json` manifest). Apps Script (`.gs`) runs server-side on Google's infrastructure with the deploying user's authority, so an over-shared web app or a broad scope can expose Sheets/Drive data and act as that user. Every item is a lead to verify from source.

## 1. Web app exposure (appsscript.json)
- **`webapp.access`**: `ANYONE_ANONYMOUS` (no login) or `ANYONE` makes `doGet`/`doPost` callable by the public. Confirm it must be, and that the handlers authorise each action themselves.
- **`webapp.executeAs`**: `USER_DEPLOYING` means every anonymous request runs **as you**, with your access to the bound Sheet/Drive. Prefer `USER_ACCESSING` unless the deployer's authority is truly required.
- **API executable / add-on** deployments with broad access.

## 2. Request handling in doGet/doPost
- `e.parameter` / `e.parameters` / `e.postData` is untrusted input. Do not trust it for identity or authorization.
- **XSS**: `HtmlService.createHtmlOutput(... + e.parameter ...)` or templated `<?!= ?>` printing scriptlets of request input without escaping. Use `<?= ?>` (contextual escaping) or `HtmlService.createTemplateFromFile` with escaped substitutions, and avoid `createHtmlOutput` on concatenated user input.
- **`setXFrameOptionsMode(ALLOWALL)`** removes clickjacking protection on served HTML.

## 3. Authorization
- **`google.script.run` exposes every server global**: any non-underscore top-level function is callable from the client through `google.script.run.fnName()`, **bypassing `doGet`/`doPost`**. Each such function must authorise the caller itself. Name internal helpers `_private` (a leading underscore makes them non-callable), and treat every `google.script.run.<fn>` call site as a reachable, unauthenticated entry point.
- `Session.getActiveUser().getEmail()` is **empty** for `ANYONE_ANONYMOUS` web apps and may be blank across domains — do not use it as the sole auth check. Use an explicit allow-list, a shared secret in `PropertiesService`, or require Google sign-in (`access: DOMAIN`/`MYSELF`).
- **`getActiveUser` vs `getEffectiveUser`**: `Session.getEffectiveUser()` returns the user the script *runs as* — the **deployer** for an "Execute as me" (`USER_DEPLOYING`) web app — not the caller, so it is **never** an authorization check (it is always the deployer). `getActiveUser()` is the caller but is empty for anonymous web apps. Using effective-user as identity is a common and dangerous mix-up.
- A write path (append row, send email, change sharing) reachable from an anonymous `doPost` with no token.

## 4. Secrets and scopes
- **Secrets in code**: API keys/tokens as literals in `.gs`. Keep them in `PropertiesService` (Script or User properties), never in source (the script is shared with every editor/collaborator).
- **`oauthScopes`**: request the narrowest scopes. `.../auth/drive` or `.../spreadsheets` (full) where `.../drive.file` or a readonly scope would do; `script.external_request` (UrlFetchApp) only if outbound calls are needed.

## 5. Outbound and data sharing
- **SSRF**: `UrlFetchApp.fetch(e.parameter.url)` — outbound request to a caller-supplied URL. Allow-list hosts.
- **SSRF via settings/properties**: `UrlFetchApp.fetch(...)` to a URL read from `PropertiesService` (Script/User/Document properties) or a settings object, with no host allow-list. Anyone with edit access to the script or its properties can repoint it to an internal or attacker host. Validate the host against an allow-list before fetching.
- **Over-sharing in code**: `DriveApp` / `Spreadsheet` `setSharing(DriveApp.Access.ANYONE, ...)` or `ANYONE_WITH_LINK` (including as a fallback), or creating link-shared files programmatically. Confirm the file holds no personal or confidential data; prefer per-user sharing.
- **Concurrent writes**: appending to a Sheet from a public endpoint without `LockService` can corrupt or interleave rows (and lets a flood of requests race).

## What never passes (Apps Script-specific)
- "Web app is public" with no reachable action that leaks or changes data — note it; it is a finding when an anonymous call reads/writes data or acts as the deployer.
- A broad scope that the code does not actually exercise — report as minimisation/hardening.
