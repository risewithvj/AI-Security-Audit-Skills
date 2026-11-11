<!--
  AI-Security-Audit-Skills
  Author   : Vijaya Kumar L  (Rise With VJ)
  GitHub   : https://github.com/risewithvj
  LinkedIn : https://www.linkedin.com/in/vijayakumarl/
  License  : MIT
-->

# Secrets and configuration

Always loaded. Detailed framework tables live in [vibe-coded/secrets-and-env.md](vibe-coded/secrets-and-env.md) and [vibe-coded/deployment.md](vibe-coded/deployment.md); this file is the audit procedure.

## 1. Where secrets leak (check every one that exists)

| Place | How to check | Confirmed when |
|---|---|---|
| Source files | Gitleaks and Trivy secret results; grep `password`, `secret`, `api_key`, `token`, `Bearer `, `-----BEGIN`, `AKIA`, `sk_live_`, `rzp_live_`, `ghp_`, `xox[bp]-`, `AIza` | Real-looking value used by runtime code or config, not a placeholder |
| Git history | `gitleaks detect` covers history when `.git` exists | Any real credential ever committed. Deleting the file does not fix it: rotation is required |
| Client bundle | Env vars with `NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `EXPO_PUBLIC_`, `NUXT_PUBLIC_`, `PUBLIC_` (SvelteKit/Astro), `GATSBY_` prefixes; values imported into client components | A secret-class key (service_role, Stripe/Razorpay secret, DB URL, admin SDK key, LLM provider key) reaches browser or mobile code |
| Mobile apps | `google-services.json`, `GoogleService-Info.plist`, hardcoded keys in `*.kt`, `*.swift`, `*.dart`, JS bundles, `app.json`/`app.config.*` `extra` fields | Key grants more than the public client scope |
| Containers | `Dockerfile` `ENV`/`ARG` with secrets, `COPY .env`, secrets in `docker-compose.yml` committed | Secret ends up in an image layer or a committed file |
| CI/CD | Secrets echoed in workflow logs, `pull_request_target` with secrets and checkout of PR code, plain-text secrets in workflow YAML | Secret exposed to untrusted code or logs (see [supply-chain-and-release.md](supply-chain-and-release.md)) |
| Logs and errors | Logging of request bodies, headers, tokens, OTPs, passwords; stack traces returned to clients | Sensitive value written to logs or sent to a client |
| Source maps | `productionBrowserSourceMaps`, `sourcemap: true` for production builds, `.map` files in `public/` | Full source with comments shipped to users. Low on its own; higher if it reveals secrets or hidden routes |
| IaC and cloud config | Keys in Terraform variables defaults, `*.tfvars` committed, Kubernetes `Secret` manifests with base64 values, Helm values | Real credential committed |

**Placeholder test.** `changeme`, `xxx`, `<your-key>`, `sk_test_` with no live access, `.env.example` values, docs and test fixtures are not findings unless runtime code actually uses them, or they are real test keys that unlock real resources (a test Stripe key can still create charges in test mode against a real account; report as Low unless it reaches real data).

**Reporting.** Never print the value. Record type, location, first 4 characters and length, whether it is in history only, and the rotation step.

## 2. Key classes by danger

| Danger | Examples | Typical severity if exposed |
|---|---|---|
| Bypasses all access control | Supabase `service_role`, Firebase Admin SDK JSON, DB connection string with write access, cloud root/admin keys | Critical |
| Moves money or sends messages | Stripe/Razorpay/PayU secret keys, Twilio/Exotel/MSG91 auth tokens, SMTP credentials | Critical to High |
| Spends money | OpenAI, Anthropic, Gemini and other LLM keys, Google Maps unrestricted keys, SMS gateway keys | High (operator spend, data in prompts) |
| Reads third-party data | GitHub tokens, Slack tokens, CRM (Zoho, HubSpot, Salesforce) tokens | High |
| Public by design | Stripe publishable key, Supabase anon key, Firebase web config, Razorpay `key_id` | Not a finding by itself. The question becomes whether RLS / security rules / server checks hold (see [baas-database-rules.md](baas-database-rules.md)) |

## 3. Production configuration

Confirm from files in the repo, not assumptions:

- Debug and dev modes: `DEBUG = True`, `app.debug`, `NODE_ENV` checks, `ASPNETCORE_ENVIRONMENT=Development`, Laravel `APP_DEBUG=true`, Spring Boot actuator exposure, Django `ALLOWED_HOSTS = ['*']` with debug. Can a request header, query param or cookie turn debug on?
- Default or seeded admin accounts and passwords in migrations, seeders or fixtures that also run in production.
- Error handling that returns stack traces, SQL, file paths or env values to clients.
- CORS: `*` with credentials, origin reflection, regex that matches attacker domains (`.*example.com`), `null` origin allowed.
- Cookies holding sessions without `HttpOnly`, `Secure`, `SameSite`. Report only when the cookie is security-sensitive and a reachable attack uses the gap.
- Security headers. Missing headers alone are not findings; report them as a hardening note, or as part of a confirmed finding they enable (for example missing frame protection on a confirmed one-click sensitive action).
- `.gitignore` coverage for `.env*`, keys, uploads, local databases (`*.sqlite`, `*.db`), backups (`*.sql`, `*.bak`, `*.dump`).
- Committed database dumps, backups, CSV exports containing real personal data. Treat as a data exposure finding; describe the data types, never the data.

If a decisive setting lives only in a hosting dashboard (Vercel, Netlify, Cloudflare, Supabase, Firebase console, AWS), the verdict is `needs_validation` naming that setting.
