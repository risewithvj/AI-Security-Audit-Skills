<!--
  AI-Security-Audit-Skills
  Author   : Vijaya Kumar L  (Rise With VJ)
  GitHub   : https://github.com/risewithvj
  LinkedIn : https://www.linkedin.com/in/vijayakumarl/
  License  : MIT
-->

# Desktop, Mobile, and Local IPC Hunting

> **Reading from source, not running it.** This skill never launches the target. Whenever a check below mentions an "emulator run", a "local fixture", or a "bounded test", decide the question by reading the code. If the code alone cannot decide it, the verdict is `needs_validation` and you name the one fact you are missing. Reference sibling checklists by their `checklists/...` path and gate every finding through `rules/evidence-gate.md`.

## What this file is for

Open this checklist when the artifact under review runs on a user's own machine or phone and talks to local or remote parties: Electron and native desktop apps, auto-updaters, privileged helpers and daemons, WebView hosts, browser native-messaging hosts, deep-link and custom-scheme handlers, and anything that is a client or server over a local IPC channel.

The point that decides every finding here is *who the attacker is*. Do not flatten all local principals into one. The realistic adversary might be:

- a downloaded document the user double-clicks (an HR team opening a vendor's `offer-letter.pdf`),
- remote web content loaded into a WebView,
- a second app installed on the same device,
- a different OS user on a shared workstation,
- a sandboxed child process, or
- a lower-privilege account on a managed laptop.

Pick the starting privilege explicitly and keep it fixed through the whole chain. A payload that only harms the account and authority it already holds is not a boundary crossing.

**Where other files take over**

| Concern | Go to |
| --- | --- |
| Browser-side behaviour of WebView content itself | `client-side.md` |
| Native memory corruption, loaders, parsing after a file is open | `memory-safety-and-binary.md` |
| Authenticity of the update stream / release pipeline | `supply-chain-and-release.md` |

---

## Discipline to carry into every subagent prompt for this domain

Paste the equivalent of this into each agent you dispatch here:

```
- Fix the real attacker first: a second app, another OS user, a sandboxed child,
  a hostile document, or a remote web origin. An action a principal takes against
  its own data and privilege is not a vulnerability.
- Treat file paths, process names, bundle IDs, package names, and any "sender"
  field in the payload as attacker-controlled hints, never as authentication.
  Authenticate with OS peer credentials, code-signing identity, capability
  handles, or protected channel state instead.
- A native bridge or privileged helper must re-authorise each call AND the final
  resource it resolves, after parsing. A trusted UI shell upstream does not
  launder attacker-influenced arguments.
- Sandbox policy, code signing, entitlements, runtime permissions, keychain
  ACLs, exported-component rules, and consent prompts are genuine controls, but
  only when you can see them pinned in the code or manifest.
- Mark `confirmed` only with source evidence plus, where relevant, a bounded
  emulator/local observation. Mark `needs_validation` when the answer depends on
  signing, a merged manifest, the OS build, device/MDM policy, installer ACLs,
  or packaging you cannot see from source.
```

---

## Family 1 — Links, callbacks, and navigation targets (subagent_type: `general`)

**Scheme and deep-link ambiguity.** A foreign app or web page fires a route that changes state, imports records, finishes a login, or picks an account — and the handler never binds that route to the current session plus a single-use callback token. Look at how the URI is normalised, whether duplicate query keys are collapsed safely, how scheme/host/path are matched, what the exported-handler policy is, and whether old or replayed links still work. *Example:* a payroll app registers `payrollapp://approve-revision?empId=…` and a chat message carrying that link silently approves a salary revision because the handler trusts the URI alone.

**Handoff landing on the wrong place.** A returning callback — think device-pairing, invite, passwordless login, magic-link, payment confirmation, SSO, or OAuth — re-enters the wrong installed app, the wrong profile, the wrong tenant, or an unrelated pending transaction. The callback state must be tied to the app identity that started it, the live session, the account, the provider, the specific operation, and an expiry.

**File-open / intent authority confusion.** An associated file type, a share intent, a drag-and-drop item, a clipboard or pasteboard record, a notification action, or an OS open-file event kicks off a privileged operation without first confirming the content type, the sender's trust level where that applies, the user's actual intent, and the real final target.

---

## Family 2 — WebViews and native bridges (subagent_type: `general`)

**Remote navigation reaching a packaged-content bridge.** A JS-to-native bridge is meant only for the app's own bundled pages, but attacker-controlled frames can reach it. The origin must be re-checked *at the moment the bridge is called* and after every navigation, redirect, new subframe, popup, and error/fallback page. A URL-prefix check or a one-time check at initial load is not enough — remote content can navigate away afterwards.

**A bridge that exposes too much.** Through one generic bridge method, web content can pick arbitrary files, run commands, call internal IPC methods, read credentials, or trigger system actions. Verify there is a method allowlist, that arguments are normalised, that the caller's user/tenant authority is enforced, that destructive actions need a gesture or confirmation, and that return values do not over-disclose.

**File and universal access inside the WebView.** Remote pages gain reach into internal origins, privileged custom schemes, or files local to the app once a debug interface, mixed content, universal access, file-access permission, or a custom protocol handler quietly merged origins. Note the distinction: a missing hardening flag with no reachable protected content behind it is hardening, not a finding.

---

## Family 3 — Local IPC and exported components (subagent_type: `general`)

**No real peer check on the channel.** A transport — RPC, native messaging, D-Bus, Binder, XPC, a named pipe, a Unix domain socket, shared memory, or a loopback listener — accepts a lower-trust peer without verifying OS credentials, code identity, a sandbox token, or ownership of the channel, and a meaningful method or data disclosure sits behind it.

**Channel identity vs. claimed principal.** The connected process or channel genuinely belongs to app A or user A, but a field in the request selects a *different* user, tenant, profile, or capability. Each method and each resource must be bound to the verified peer credential, not to an identifier the caller typed into the message. *Example:* a desktop HR agent authenticates the socket but then trusts `requestedEmpId` in the payload, letting a standard employee pull a colleague's PF/ESI record.

**Exported service / activity / receiver / provider doing too much.** Reachable from outside, a local automation endpoint or a mobile component carries out an action that only the app itself should carry out. Read the *final merged* manifest, the intent filters, the permission or signature level, path-permission grants, and any alias that re-exports the same component. If the post-packaging manifest state is unknown, that is `needs_validation`.

**Lifecycle and correlation slips.** Guessable request IDs, recycled handles, stale channels, file descriptors inherited across a fork, a world-writable socket path, or restart behaviour lets one peer answer, cancel, or replay another peer's operation. Check the permissions used when sockets, locks, ports, and shared mappings are created, and whether they are cleaned up afterwards.

---

## Family 4 — Privileged helpers and local files (subagent_type: `general`)

**The helper as a confused deputy.** A low-privilege caller gets to choose a privileged command, a file, a service, a target user, or a system setting with no per-operation authorisation. Review the sudo/polkit/UAC/XPC-helper rules and confirm the helper independently validates the *normalised* arguments rather than trusting the caller's framing.

**Trust in install / update / repair paths.** A privileged installer or helper consumes repair state, working directories, symlinks, packages, scripts, or manifests that a lower-trust actor can still write *after* authorisation is granted. Authorisation must be bound to immutable content and to a safe, fixed destination path.

**TOCTOU and file ownership.** Having validated a path or file, the app then — during a privileged read or write — follows a replacement, a symlink, a mount, or a case/normalisation change to a different target. Prefer descriptor-relative operations and verify the final ownership of what was actually opened. Parsing of the bytes *after* the file is open belongs to `memory-safety-and-binary.md`.

**Secrets readable across a boundary.** A keychain/keystore item, a token file, a backup, a log line, a clipboard entry, a notification preview, or a local config is reachable by another app, profile, or user with less authority. Plaintext that only the same intended OS account can read is not automatically a vulnerability — state the specific lower-trust reader and how powerful the leaked credential is (an Aadhaar/PAN token in a world-readable log is a very different weight from a UI-theme preference).

---

## Family 5 — App state and device lifecycle (subagent_type: `general`)

**Leakage across logout, account switch, and restore.** Background tasks, local databases, notifications, widgets, WebView storage, cached data, or a remembered biometric approval outlives a logout or an account change and then surfaces under a later account. Look at backup/restore behaviour and multi-profile handling — a shared tablet at a branch office where one HR user logs out and the next logs in is the canonical case.

**Pending action vs. what the user saw.** A notification, widget, shortcut, share-sheet entry, biometric prompt, or deferred operation ends up authorising a different action than the one displayed, runs after it should have expired, or reuses another profile's pending state. Bind the confirmation to the normalised action, the resource, the account, and the current foreground state.

---

## Moves that apply across all five families

- **Inventory everything that can be addressed.** Each helper, WebView origin, file association, URI scheme, local endpoint, app component, and process. For each, record its OS identity, its runtime privilege, who can call it, and what it can do when called.
- **Read the real packaging inputs, not the source intent.** Entitlements and the merged manifest, the registration for protocol handlers, the registration for native messaging, installer rules, and the ACLs used at creation time. A clean-looking source declaration can be overwritten downstream by a build step, a merge, or a flavour.
- **If you do observe locally, stay bounded.** Use throwaway profiles and non-sensitive fixtures on an isolated machine or emulator. Never touch another user's app, real credentials, or any production service.

---

## Before you report anything from this file

1. **Spell out the crossing.** Name the attacker's starting capability, the OS/app principal that gets crossed, the entry channel, the argument or state that was accepted, and the unauthorised operation or disclosure that resulted.
2. **Account for the defences.** Confirm which of sandboxing, peer-credential checks, signing, entitlements, runtime permissions, user consent, and installer controls actually apply. Anything about packaging or runtime you cannot see from source becomes `needs_validation`.
3. **Cite both halves of the chain.** For a WebView bridge, show the navigation/origin control *and* the privileged native sink. For IPC, show the peer authentication *and* the per-resource authorisation. For a helper, verify the final normalised destination.
4. **Keep proof minimal.** If you test, use dummy content and dummy accounts, and stop the moment the boundary result is demonstrated — do not push on into persistence or wider system changes.
5. **Verdict rule.** `confirmed` only when the source (and, where needed, bounded local) evidence chain is complete. Otherwise `needs_validation`, naming the precise device-lifecycle, ACL, signing, manifest, or OS detail you still need.
