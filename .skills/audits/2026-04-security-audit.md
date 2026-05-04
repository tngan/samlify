# Security audit — 2026-04

- **Auditor:** *(maintainer / Claude Code pair)*
- **Scope:** `src/`, dependency tree, dependabot alerts at HEAD `a3b4530`
- **Companion PR:** `security/audit-2026-04`

## Summary

| Severity | Finding | Status |
| --- | --- | --- |
| High | Dependabot — `vite` arbitrary file read via dev-server WebSocket (`GHSA-p9ff-h696-f583`, CVE-2026-39363) | **Fixed** — yarn resolution forces `vite ^6.4.2`. |
| Moderate | Dependabot — `vite` path traversal in `.map` handling (`GHSA-4w7w-66w2-5vf9`, CVE-2026-39365) | **Fixed** — same resolution. |
| High | `setDOMParserOptions({})` silently disables the XXE-safe error handlers | **Fixed** — `XXE_SAFE_OPTIONS` is now merged in as a baseline; callers must opt out explicitly. |
| High | `libsaml.getSigningScheme` falls back to RSA-SHA1 for unknown algorithms — verification-time downgrade | **Fixed** — unknown algorithms now throw `ERR_UNSUPPORTED_SIGNATURE_ALGORITHM`; default is RSA-SHA256. |
| Medium | No enforcement of `<AudienceRestriction>` against the SP's `entityID` | **Open** — tracked separately. See *Open findings* below. |
| Medium | No `InResponseTo` enforcement against an open AuthnRequest cache | **Open** — tracked separately. |
| Low | `KeyEncryptionAlgorithm` defaults include `rsa-1_5` (Bleichenbacher-vulnerable padding) | **Open** — tracked separately. |

`yarn audit` reports **0 vulnerabilities** post-patch.

## Spec reference

- `saml-sec-consider §6.3.1` — XXE protections required of the parser.
- `saml-sec-consider §6.5` — algorithm-agility and depreciation of SHA-1 / RSA-1.5.
- `xmldsig-core §6.4` — algorithm registry.
- `saml-core §2.5.1.4` — `<AudienceRestriction>` MUST be enforced when present.
- `saml-profiles §4.1.4.5` — `InResponseTo` binding to the original AuthnRequest.
- `xmlenc-core §5.2` — RSA-OAEP recommendation over PKCS#1 v1.5.

## Findings — fixed

### F-1. Dependabot vite alerts

`vitepress` (1.6.4) and `vitest` (3.2.4) both transitively pull `vite`. Upstream HEAD shipped two security advisories applying to vite ≤ 6.4.1:

- **GHSA-p9ff-h696-f583** (HIGH, CVE-2026-39363): WebSocket bypass of `server.fs` allow-list. Reachable when `--host` exposes the dev server to the network and a request arrives without an `Origin` header.
- **GHSA-4w7w-66w2-5vf9** (MODERATE, CVE-2026-39365): `.map` path traversal under the optimized-deps URL prefix. Reachable when the dev server is exposed to the network and a sensitive `.map` file exists outside the project root.

Production users are not affected — vite is a dev-only dependency and the npm package's `files` allowlist excludes it. Maintainers running `yarn docs:dev --host` in untrusted networks are.

**Patch.** `package.json` resolutions forced `vite ^6.4.2` for the vitest and vitepress paths. The peer-dep mismatch warning from vitepress (`^5.4.14`) is benign — vite 6.x is API-compatible with 5.x for the vitepress consumer surface; tests and `vitepress build` both succeed.

### F-2. `setDOMParserOptions` XXE bypass

`setDOMParserOptions(options = {})` previously instantiated a fresh `DOMParser` from the caller's options alone. The XXE-safe error handlers in the module-level `XXE_SAFE_OPTIONS` were lost. A caller invoking `setDOMParserOptions()` (e.g. to tune locator settings) silently disabled XXE protection — a regression to the pre-`8c2f743` posture.

**Fix.** `XXE_SAFE_OPTIONS` is merged in as a baseline:

```ts
context.dom = new Dom({
  ...XXE_SAFE_OPTIONS,
  ...options,
  errorHandler: options.errorHandler ?? XXE_SAFE_OPTIONS.errorHandler,
});
```

A caller can still opt out by supplying its own `errorHandler`, but the silent disable path is closed. Regression test: `test/units.ts` parses a `<!DOCTYPE>`-laden document after the caller passes `{}` and asserts it throws.

### F-3. SHA-1 algorithm downgrade in signature verification

`getSigningScheme(sigAlg?)` previously returned `pkcs1-sha1` when `sigAlg` was undefined or unrecognised. The fallback was reachable from `verifyMessageSignature` (called by `flow.redirectFlow` and `flow.postSimpleSignFlow` with the `SigAlg` query parameter). An attacker supplying a malformed or unknown `SigAlg` value coerced verification onto SHA-1, which is collision-broken.

**Fix.** Unknown algorithms now throw `ERR_UNSUPPORTED_SIGNATURE_ALGORITHM`. The default (when `sigAlg` is genuinely omitted, e.g. signing without explicit algorithm) is RSA-SHA256, matching the recommendation in `xmldsig-core §6.4` and `saml-bindings §3.4.4.1`.

**Behaviour change.** Callers of `libsaml.constructMessageSignature(... )` that previously relied on the SHA-1 default now get RSA-SHA256. The `test/index.ts:'sign a SAML message with RSA-SHA1'` test was updated to pass `signatureAlgorithms.RSA_SHA1` explicitly. Documented as a breaking change in the PR.

Regression tests: explicit algorithm-rejection tests for both `verifyMessageSignature` and `constructMessageSignature`.

## Findings — open

### F-4. `<AudienceRestriction>` not enforced

`extractor.loginResponseFields` extracts the `audience` attribute from `<saml:Conditions><saml:AudienceRestriction><saml:Audience>`, but `flow.ts` never compares it to the SP's `entityID`. Per `saml-core §2.5.1.4`:

> If a SAML relying party determines that an assertion is intended for a security domain to which it does not belong, then the assertion MUST be rejected.

A login response captured by an attacker for one SP can be replayed against another SP that shares an IdP. **Mitigation while the fix is pending:** SP integrators should add an `audience` check inside their `parseLoginResponse` `.then(...)` handler.

**Proposed fix:** add a default check in `flow.ts` that compares `extractedProperties.audience` against `self.entityMeta.getEntityID()` and rejects with `ERR_AUDIENCE_MISMATCH`. Behind a `wantAudienceCheck` option (default `true`) for backwards compatibility; warn the first call when disabled. Tracked as a follow-up — out of scope for this PR because the fix changes accept/reject behaviour for any SP whose `entityID` doesn't match the IdP's `<Audience>` value (would surface real misconfigurations as breakages).

### F-5. `InResponseTo` not bound to an open request

The SP currently extracts `InResponseTo` from the response but does not check it against an outstanding AuthnRequest ID. A captured response can be replayed against the same SP after the original user's session expires, or substituted across users. Per `saml-profiles §4.1.4.5`:

> The service provider MUST NOT process a Response unless it can match each \<SubjectConfirmationData\> to a previously initiated request.

**Proposed fix:** introduce a request cache (keyed by AuthnRequest ID, time-bounded) populated in `createLoginRequest` and consumed in `parseLoginResponse`. Cache backend is pluggable (in-memory default, Redis adapter for clusters). Out of scope here — non-trivial API surface.

### F-6. RSA-1.5 in default key-encryption algorithm list

`src/urn.ts:155` advertises `rsa-1_5` (PKCS#1 v1.5) under `algorithms.encryption.key`. The default in `entity.ts:60` is `RSA_OAEP_MGF1P`, but `rsa-1_5` is reachable via configuration. PKCS#1 v1.5 is vulnerable to Bleichenbacher-style oracle attacks.

**Proposed fix:** mark `rsa-1_5` as deprecated in JSDoc, emit a one-time `console.warn` when an entity is configured with it, and remove it entirely in v3. Out of scope for this PR — the field is caller-controlled and breaking change.

## Methodology notes

1. **Dependabot triage.** `gh api /repos/tngan/samlify/dependabot/alerts` enumerated 2 open alerts, both vite. `yarn audit` confirmed.
2. **Dep patching.** Resolutions in `package.json` (yarn 1 syntax) at the `vitest/vite`, `vitest/vite-node/vite`, `vitepress/vite`, and `vitepress/@vitejs/plugin-vue/vite` paths. `rm -rf node_modules yarn.lock && yarn install` to materialise. `npm ls vite` confirms `6.4.2` deduped across all consumers; `yarn audit` reports 0 vulnerabilities.
3. **Source review** focused on the SAML attack surface:
   - XML parsing (XXE — `api.ts`)
   - Signature verification (algorithm allow-list, wrapping attacks, signed-references — `libsaml.ts`)
   - Encryption (algorithm allow-list, default — `urn.ts`, `libsaml.ts`)
   - Assertion validation (audience, time, InResponseTo — `flow.ts`, `validator.ts`)
   - XPath construction (injection — `extractor.ts`, `libsaml.ts`)

## Future work checklist

- [ ] F-4 — default audience check (separate PR)
- [ ] F-5 — InResponseTo cache + binding (separate PR; design RFC needed)
- [ ] F-6 — deprecate `rsa-1_5` (v3 removal)
- [ ] Add a CI step running `yarn audit --level=high` on every PR (currently only enforced in `yarn build` script).
- [ ] Add fuzzing for the XPath extractor (`jsfuzz` or equivalent).
