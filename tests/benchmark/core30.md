# Core 30 — frozen benchmark subset (OWASP Juice Shop)

This file freezes the **Core 30** challenges used to score every tool in the
v1.5.1 benchmark. It is selected **mechanically** from each challenge's own
`category` / `tags` in Juice Shop's official answer key
(`data/static/challenges.yml`), **not** by human judgement, and is committed
**before** any tool is scored.

- Answer key: `D:\bench\juice-shop\data\static\challenges.yml` (118 challenges total, Juice Shop as bundled on 2026-11-10).
- Selection date: 2026-11-11. No score, scorecard, or web-AI report was opened while selecting.

## The rule

Keep only challenges that map to a real-world **OWASP Top 10:2025** or
**OWASP API Security Top 10** risk class, and drop puzzles / easter-eggs /
OSINT / trivia / CTF-only tasks. This is expressed purely as a category +
tag filter so anyone can reproduce it.

**Step A — include by official category.** A challenge is in the pool iff its
`category` is one of the 14 OWASP-mapped vulnerability classes:

| Juice Shop category | Maps to |
|---|---|
| Broken Access Control | OWASP A01:2025 / API1,API3,API5 |
| Security Misconfiguration | OWASP A02:2025 |
| Vulnerable Components | OWASP A03:2025 (Software Supply Chain) |
| Cryptographic Issues | OWASP A04:2025 |
| Sensitive Data Exposure | OWASP A04:2025 / API3 (data exposure) |
| Injection | OWASP A05:2025 |
| XSS | OWASP A05:2025 (injection / XSS) |
| XXE | OWASP A05:2025 |
| Improper Input Validation | OWASP A06:2025 (Insecure Design / business logic) |
| Broken Authentication | OWASP A07:2025 / API2 |
| Insecure Deserialization | OWASP A08:2025 (Software & Data Integrity) |
| Observability Failures | OWASP A09:2025 (Logging & Alerting) |
| Unvalidated Redirects | OWASP A01/A10:2025 |
| Broken Anti Automation | OWASP API4 (Unrestricted Resource Consumption) |

**Excluded categories** (not an OWASP risk class — easter-eggs / obscurity /
trivia): `Miscellaneous`, `Security through Obscurity`.

**Step B — drop puzzle / OSINT / CTF-only tags.** Even inside an included
category, drop any challenge tagged with a non-vulnerability "puzzle" marker:
`OSINT`, `Shenanigans`, `Contraption`, `Web3`.

**Step C — size to 30.** The filter yields a pool of **79** challenges — more
than 30 — so, per the benchmark rule, take the **first 30 by Juice Shop
difficulty order** (ascending difficulty stars; ties broken by challenge name
A→Z, matching the score-board's within-tier ordering).

### Exact filter (reproducible)

```python
import yaml
data = yaml.safe_load(open('data/static/challenges.yml', encoding='utf-8'))

INCLUDE = {
    'Broken Access Control', 'Broken Authentication', 'Injection', 'XSS',
    'Sensitive Data Exposure', 'Cryptographic Issues', 'Security Misconfiguration',
    'Vulnerable Components', 'Insecure Deserialization', 'XXE',
    'Improper Input Validation', 'Unvalidated Redirects', 'Broken Anti Automation',
    'Observability Failures',
}
EXCLUDE_TAGS = {'OSINT', 'Shenanigans', 'Contraption', 'Web3'}

pool = [c for c in data
        if c.get('category') in INCLUDE
        and not (set(c.get('tags') or []) & EXCLUDE_TAGS)]
pool.sort(key=lambda c: (c['difficulty'], c['name']))   # 79 in pool
core30 = pool[:30]                                        # first 30 by difficulty, then name
```

**Boundary:** the cut falls inside difficulty 3. #30 `GDPR Data Erasure` is the
last d3 kept (alphabetical); the first items dropped are all d3 and sit just
after it by name — `Greedy Chatbot Manipulation`, `Login Bender`, `Login Jim`,
`Manipulate Basket`, `Payback Time`, `Product Tampering`, … No difficulty-4+
challenge is in the Core 30.

## The Core 30 (frozen)

| # | Diff | Category | Challenge | key |
|---|---|---|---|---|
| 1 | 1 | Sensitive Data Exposure | Confidential Document | directoryListingChallenge |
| 2 | 1 | XSS | DOM XSS | localXssChallenge |
| 3 | 1 | Security Misconfiguration | Error Handling | errorHandlingChallenge |
| 4 | 1 | Observability Failures | Exposed Metrics | exposedMetricsChallenge |
| 5 | 1 | Unvalidated Redirects | Outdated Allowlist | redirectCryptoCurrencyChallenge |
| 6 | 1 | Improper Input Validation | Repetitive Registration | passwordRepeatChallenge |
| 7 | 1 | Improper Input Validation | Zero Stars | zeroStarsChallenge |
| 8 | 2 | Broken Access Control | AI Debugging | aiDebuggingChallenge |
| 9 | 2 | Broken Access Control | Admin Section | adminSectionChallenge |
| 10 | 2 | Injection | Chatbot Prompt Injection | chatbotPromptInjectionChallenge |
| 11 | 2 | Improper Input Validation | Empty User Registration | emptyUserRegistration |
| 12 | 2 | Sensitive Data Exposure | Exposed Credentials | exposedCredentialsChallenge |
| 13 | 2 | Broken Access Control | Five-Star Feedback | feedbackChallenge |
| 14 | 2 | Injection | Login Admin | loginAdminChallenge |
| 15 | 2 | Security Misconfiguration | Misplaced IaC Files | misplacedIacFiles |
| 16 | 2 | Sensitive Data Exposure | Password Hash Leak | passwordHashLeakChallenge |
| 17 | 2 | Broken Authentication | Password Strength | weakPasswordChallenge |
| 18 | 2 | XSS | Reflected XSS | reflectedXssChallenge |
| 19 | 2 | Broken Access Control | View Basket | basketAccessChallenge |
| 20 | 2 | Cryptographic Issues | Weird Crypto | weirdCryptoChallenge |
| 21 | 3 | XSS | API-only XSS | restfulXssChallenge |
| 22 | 3 | Improper Input Validation | Admin Registration | registerAdminChallenge |
| 23 | 3 | Broken Anti Automation | CAPTCHA Bypass | captchaBypassChallenge |
| 24 | 3 | Broken Access Control | CSRF | csrfChallenge |
| 25 | 3 | XSS | Client-side XSS Protection | persistedXssUserChallenge |
| 26 | 3 | Injection | Database Schema | dbSchemaChallenge |
| 27 | 3 | Improper Input Validation | Deluxe Fraud | freeDeluxeChallenge |
| 28 | 3 | Broken Access Control | Forged Feedback | forgedFeedbackChallenge |
| 29 | 3 | Broken Access Control | Forged Review | forgedReviewChallenge |
| 30 | 3 | Broken Authentication | GDPR Data Erasure | ghostLoginChallenge |

**Category spread (Core 30):** Broken Access Control 7, Improper Input
Validation 5, XSS 4, Injection 3, Sensitive Data Exposure 3, Broken
Authentication 2, Security Misconfiguration 2, Cryptographic Issues 1,
Observability Failures 1, Unvalidated Redirects 1, Broken Anti Automation 1.

## The Full 60 (secondary scoring set)

The **Full 60** used for the `/60` strict and coverage metrics is defined from
the **same filtered pool, same ordering** — it is simply `pool[:60]` (the first
60 by difficulty, then name). The Core 30 is therefore an exact prefix of the
Full 60. The Full 60 boundary falls inside difficulty 5 (the 60th and 61st are
both d5, cut alphabetically); its difficulty spread is d1×7, d2×13, d3×21,
d4×16, d5×3, and it spans all 14 included OWASP-mapped categories.

The Core 30 is the **headline** number because its lower-difficulty slice is the
part most representative of what a source-code audit of a real app should catch;
the Full 60 is reported alongside it as a wider-coverage reference.
