<!--
  AI-Security-Audit-Skills
  Author   : Vijaya Kumar L  (Rise With VJ)
  GitHub   : https://github.com/risewithvj
  LinkedIn : https://www.linkedin.com/in/vijayakumarl/
  License  : MIT
  Original text.
-->

# Insecure defaults

Always loaded, run by one dedicated hunter. The question for every item: **what happens when the setting is missing, empty, wrong or the dependency is down?** Code that fails open is the finding.

## 1. Fallback secrets

- `process.env.JWT_SECRET || 'secret'`, `os.getenv("SECRET_KEY", "dev")`, `config.get('key', 'changeme')`, hardcoded HMAC keys used when env is unset.
- Encryption keys or IVs with a default value, or derived from something guessable (app name, hostname, timestamp).
- Default admin or service passwords in seeders, Docker images, Helm values, or setup scripts that also run in production.

Confirmed when the fallback is reachable in a production code path (no hard failure on missing config) and an attacker who knows the fallback gains something: forged tokens, decrypted data, admin login.

## 2. Fail-open checks

- `try { verify(token) } catch { return next() }`, or an error in the auth/permission service treated as "allowed".
- Permission lookups that return `true` on a cache miss, null role or unknown action.
- Feature flags or kill-switches that default to "security off".
- Webhook signature checks skipped when the signing secret env var is empty.
- Rate limiter that allows everything when Redis is unreachable. This is usually a business decision; report only when the protected flow is sensitive (OTP, login, payments) and the code path is reachable.
- `if (process.env.NODE_ENV !== 'production') skipAuth()` where the env var may be unset in production builds.

## 3. Debug and development features

- Debug toolbars, verbose error pages, GraphQL playground or introspection, Swagger UI with "try it out" and no auth, Spring actuator, Django debug, Rails web-console, PHP `display_errors`, `phpinfo()` routes.
- Test or backdoor routes: `/test`, `/debug`, `/seed`, `/reset`, `/impersonate`, `/login-as`, magic query params (`?admin=1`, `?debug=true`), special headers (`X-Debug`, `X-Internal: 1`) that skip checks.
- Mock auth providers or "dev login" buttons compiled into production bundles.

Confirmed when the feature is reachable in a production build (check build config, route registration and env gates) and gives an attacker something.

## 4. Permissive access defaults

- Storage buckets, Firebase rules, Supabase tables, S3 policies created open "for now": `allow read, write: if true`, RLS disabled, `public-read` ACLs, `Principal: "*"`.
- New tables, collections or routes that start public until a policy is added, with no policy in the repo.
- Default-allow CORS, default-allow CSP, wildcard `ALLOWED_HOSTS`.
- Kubernetes pods running as root, privileged containers, `hostPath` mounts, no network policy, by default.
- Database users with superuser rights for the app connection.

## 5. Weak crypto defaults

- Password hashing with MD5, SHA-1, SHA-256 without a slow KDF, low bcrypt cost (< 10), PBKDF2 with low iterations. Use the platform default (bcrypt, scrypt, Argon2id).
- `Math.random()`, `random.random()`, `rand()`, `new Random()` for tokens, OTPs, reset links, session IDs, file names of private documents.
- AES-ECB, static IVs, unauthenticated encryption (CBC without MAC), custom crypto.
- TLS verification disabled: `rejectUnauthorized: false`, `verify=False`, `InsecureSkipVerify: true`, `ServicePointManager.ServerCertificateValidationCallback = ... => true`, trusting all certs in mobile apps.
- JWT libraries configured to accept `none` or to accept both HS and RS algorithms with the public key as an HMAC secret.

## 6. Defaults in AI and agent code

- Agents or MCP servers that run shell commands, write files or call APIs without an allowlist or confirmation step, by default.
- LLM calls with no output length or cost limit on public endpoints.
- System prompts holding secrets ("the admin password is...").

## Smallest fixes

- Fail hard at startup when a required secret is missing; delete the fallback.
- Default deny: unknown role, missing policy, error in the check all mean "no".
- Gate debug features at build time, not by a runtime flag the client can set; delete test routes.
- Use the framework's standard crypto; delete custom code.
