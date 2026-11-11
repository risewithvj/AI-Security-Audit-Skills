<!--
  AI-Security-Audit-Skills
  Author   : Vijaya Kumar L  (Rise With VJ)
  GitHub   : https://github.com/risewithvj
  LinkedIn : https://www.linkedin.com/in/vijayakumarl/
  License  : MIT
-->

# Mobile App Security (React Native / Expo)

A mobile binary is not a server you control — it is a file sitting on a device the
attacker fully owns. Anything baked into the bundle can be unpacked, and any logic
that decides "is this user allowed" can be tampered with if it runs on the handset.
AI-generated mobile code consistently gets this boundary wrong, especially for
HR/payroll apps where the phone holds salary data, PAN, UAN and KYC artefacts.

Source-only reminder: we inspect the JS/TS, native config and build manifests. Where
a claim depends on runtime behaviour on a rooted device, it is `needs_validation`
until a human confirms it.

## The core principle: the bundle is public

Treat the shipped app bundle the way you treat view-source on a website. Everything
in it is readable. Three audit axes follow from that: **what you put in the bundle**,
**where you store data on the device**, and **what you trust the device to decide**.

## 1. Nothing secret in the bundle

Hermes bytecode is not encryption. Strings survive decompilation, so any key compiled
into the app is extractable.

- `EXPO_PUBLIC_*` variables are inlined at build time — public by definition.
- `react-native-config` values are compiled in — public.
- Anything injected through `eas.json` or `app.config.js` that lands in the JS/TS
  bundle — public.

The fix is architectural, not cosmetic: a **server-side proxy** holds every secret
key, and the app talks only to your own backend using a short-lived user token.

```ts
// WRONG — eKYC provider key compiled into the handset
await fetch("https://api.kyc-provider.in/v1/pan/verify", {
  method: "POST",
  headers: { Authorization: `Bearer ${KYC_API_KEY}` },  // extractable
  body: JSON.stringify({ pan }),
});

// RIGHT — the app hits your backend; the backend holds the KYC key
await fetch("https://api.example.in/kyc/pan", {
  method: "POST",
  headers: { Authorization: `Bearer ${userSessionToken}` },
  body: JSON.stringify({ pan }),
});
```

Flag a secret-looking key in the bundle (`sk_`, provider tokens, signing secrets) as
`confirmed`. See [secrets-and-env.md](secrets-and-env.md) for the key-classification table.

## 2. Where tokens and PII live on the device

| Storage used | Encrypted at rest? | Verdict for an auth token or PII |
|--------------|--------------------|----------------------------------|
| `AsyncStorage` | No — plaintext file | `confirmed` leak on a rooted/jailbroken device |
| `expo-secure-store` (Expo) | Yes — Keychain/Keystore | Acceptable |
| `react-native-keychain` (bare RN) | Yes — hardware-backed | Acceptable |

On a rooted phone, an `AsyncStorage` file holding the session token or a cached
payslip is read with a file browser. Keep auth tokens and any employee PII
(salary, PAN, UAN) in the secure store only.

```ts
// WRONG — plaintext on disk
await AsyncStorage.setItem("authToken", token);

// RIGHT — OS-backed encrypted store
await SecureStore.setItemAsync("authToken", token);
```

Also check for PII in plaintext logs (`console.log(employee)`), screenshots cached by
the OS task-switcher on sensitive screens, and clipboard writes of salary/PAN values.

## 3. Deep links are untrusted input

A deep link such as `hrmsapp://approve?reqId=5521` can be fired by any other app or a
web page. Treat its parameters exactly like query strings from an anonymous caller.

- Validate and sanitise every parameter; never assume the handler was reached by
  your own UI.
- Put no sensitive material in the link itself (tokens, raw user IDs that grant access,
  PAN).
- Gate destructive or approval actions behind explicit confirmation — a salary-revision
  **approval** must never happen just because a crafted link was opened.

## 4. Don't let the client decide authorisation

The recurring vibe-coded flaw is trusting a boolean the device computed.

- **Biometric unlock.** A plain `isAuthenticated = true` after Face ID can be patched
  out with Frida on a jailbroken device. Real biometric auth is cryptographic:
  1. the server issues a random, single-use challenge (nonce);
  2. the device signs that nonce using a key kept in hardware — Secure Enclave on iOS, StrongBox-backed Keystore on Android;
  3. the server checks the returned signature before trusting the session.
  Bypassing the fingerprint prompt then buys nothing, because the signature can't be forged.
- **Hidden endpoints are not access control.** An "internal" API that the app happens
  to call must still enforce authorisation server-side; see
  [authentication.md](authentication.md) and [data-access.md](data-access.md).
- **Price, role, and limits** (e.g. leave balance, salary band, approver flag) must be
  resolved on the server, never read from a value the client supplied.

## Audit checklist

- [ ] No secret keys in the JS/TS bundle; all secret calls proxied through a backend.
- [ ] Auth tokens and PII stored only in `expo-secure-store` / `react-native-keychain`.
- [ ] No PII in logs, clipboard, or task-switcher snapshots.
- [ ] Deep-link parameters validated; no secrets in links; approvals confirmed.
- [ ] Biometrics backed by a server challenge/signature, not a client boolean.
- [ ] Server re-checks every authorisation and sensitive value the client sends.

Confirmed findings need file-and-line proof per
[../../rules/evidence-gate.md](../../rules/evidence-gate.md); runtime-only concerns on a
rooted device stay `needs_validation`.
