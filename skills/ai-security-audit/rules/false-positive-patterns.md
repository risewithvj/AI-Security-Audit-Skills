<!--
  AI-Security-Audit-Skills
  Author   : Vijaya Kumar L  (Rise With VJ)
  GitHub   : https://github.com/risewithvj
  LinkedIn : https://www.linkedin.com/in/vijayakumarl/
  License  : MIT
-->

# False-positive patterns

AI reviewers are biased toward seeing bugs and toward rating them higher than they are. Every verifier runs this list against every candidate before voting.

## Thoughts that mean "stop and check"

| If you catch yourself thinking | It is wrong because | Do this instead |
|---|---|---|
| "This pattern looks dangerous, so it is a vulnerability" | Pattern is not proof. Validation may sit upstream | Trace the full path from entry to sink |
| "The same bug was real in another file" | Each path has its own callers, guards and data | Verify this instance on its own |
| "This is clearly critical" | Models over-rate severity | Write the one-sentence damage; score from that |
| "I'll skip the trace to save time" | Untraced findings are the main source of false reports | Finish the trace or mark it `rejected` |
| "The scanner flagged it, so it is real" | Scanners match syntax, not reachability | Treat every scanner hit as a lead |
| "There is probably no auth on this route" | Auth often lives in middleware, router groups, decorators, base classes, gateways | Grep for the middleware chain before claiming |
| "Production probably has debug on" | You cannot see production | `needs_validation` with the env value to check |

## The 15 common false positives

Check each candidate against all fifteen. If one applies and you cannot rule it out from source, the candidate is `rejected` or `needs_validation`.

1. **Validated upstream.** Input is checked, cast or schema-validated in middleware, a DTO, a router param parser, or a framework binder before it reaches the "sink".
2. **Parameterised after all.** The query builder or ORM binds the value even though string formatting appears nearby (`sql` tagged templates, `text()` with bind params, `?` placeholders built in a loop).
3. **Auto-escaped output.** The template engine or framework escapes by default (React, Angular, Jinja2 autoescape, Razor, Blade `{{ }}`), and the cited code does not use the raw form (`dangerouslySetInnerHTML`, `|safe`, `{!! !!}`, `v-html`, `[innerHTML]`).
4. **Not attacker-controlled.** The value comes from server config, a constant, a signed token, or a trusted internal service, not from the user.
5. **Dead or test-only code.** The file is a test, fixture, example, migration that already ran, storybook, or code never imported by an entry point. Check imports and build config.
6. **Auth at another layer.** A global middleware, route group, `@UseGuards`, `[Authorize]` on the controller, `before_action`, `LoginRequiredMixin`, API gateway config or RLS policy in the repo protects it.
7. **Intended behaviour.** An admin doing admin things. A user reading their own data. A public endpoint that is meant to be public (marketing content, health check without data).
8. **Placeholder secret.** `changeme`, `xxx`, `your-api-key`, `sk_test_`, example values in `.env.example`, docs, or test fixtures with no matching use in runtime config. Test keys are reported only if they unlock real resources.
9. **Already fixed nearby.** A later line, a wrapper, or the caller fixes the issue (normalises the path, checks ownership, encodes the output).
10. **Unreachable sink.** The dangerous function exists but no route, job or handler calls it with user data.
11. **Type makes it impossible.** A strict integer, UUID or enum parse makes injection into that value impossible.
12. **Same-origin or same-tenant only.** The "cross" boundary is actually the same principal or the same tenant.
13. **Deployment-only control is shown in the repo.** IaC, `vercel.json`, `netlify.toml`, `nginx.conf`, `firebase.json`, Supabase migrations or policies in the repo actually set the control. Read them before saying "missing".
14. **Library default is safe.** The library version in the lockfile has the safe default (e.g. modern JWT libraries reject `alg: none` by default). Check the version, not your memory of old versions.
15. **Duplicate.** Same root cause as another candidate. Merge into one finding with all locations.

## Devil's advocate (required for every `confirmed` vote)

Before voting `confirmed`, the verifier writes three sentences arguing it is **not** real, using the strongest version of the patterns above. Then one sentence on why that argument fails, with `file:line`. If the counter-argument cannot be beaten from source, vote `needs_validation` or `rejected`.

## Exploit chains

After all candidates are verified, look once at the `rejected` and low items together. Two weak items can combine (sequential IDs plus a missing ownership check; an open redirect plus an OAuth callback). A chain is a new candidate and goes through the gate again.
