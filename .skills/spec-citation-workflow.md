# Skill — Spec citation workflow

## Purpose

Make every change to samlify traceable to the SAML 2.0 / W3C normative
documents it implements, fixes, or extends. This raises the floor on
review quality, catches accidental drift from the standard, and makes the
project easier to audit.

## When to apply

Apply this skill when **any** of the following are true:

- The PR touches a file under `src/`.
- The PR adds, removes, or changes externally observable behaviour
  (binding output, signature placement, validation rules, error codes).
- The PR fixes a bug whose root cause is a deviation from the spec.
- The PR changes documentation that describes spec-defined behaviour.

It does **not** apply to:

- Pure tooling / dev-experience changes (CI, dependencies, lint config,
  test scaffolding, formatting).
- Changes outside `src/` and `docs/` (e.g. `.skills/` itself, `README.md`,
  CONTRIBUTING).

## Procedure

### 1. Identify the relevant spec section(s)

Use [`saml-spec-references.md`](./saml-spec-references.md) — start from
the **module → spec map**, then narrow down to the smallest section that
governs the behaviour being changed.

### 2. Cite in the PR description

The PR template enforces a **Spec reference** section. Fill it in with:

```markdown
## Spec reference
- `saml-bindings §3.4.4.1` — octet string construction for the
  HTTP-Redirect binding signature.
- `xmldsig-core §6.5.1` — RSA-SHA256 algorithm identifier.
```

If a change is genuinely standards-orthogonal, write *"N/A — internal
refactor, no observable behaviour change"* and explain why.

### 3. Cite in the commit message

The first body paragraph of the commit message should restate the spec
reference. Reviewers and `git blame` readers should not need to open the
PR to see why the code looks the way it does.

### 4. Cite in code (when behaviour is non-obvious)

When the code path implements a specific normative requirement and the
intent isn't apparent from reading, add a single-line comment:

```ts
// saml-bindings §3.4.4.1: RelayState is excluded from the octet string
// when the value is empty.
```

Do **not** copy spec prose into comments. Cite the section, summarise
the constraint in your own words, and let the reader follow the link if
they want depth.

### 5. Tests must pin the cited behaviour

Each new behaviour rule cited in the PR should have at least one test
that would fail if that rule were violated. The test name should
mention the rule (e.g. *"omits RelayState from octet string when empty
(saml-bindings §3.4.4.1)"*).

## Per-change-type checklist

### Feature / new binding / new profile

- [ ] Spec section(s) cited in PR body, commit message, and any
      non-obvious code.
- [ ] At least one test per normative MUST/SHOULD requirement
      introduced.
- [ ] Module → spec map in `saml-spec-references.md` updated if a new
      file under `src/` was added.
- [ ] Conformance impact noted: does this change which profiles the
      library claims to implement (`saml-conformance`)?

### Bug fix

- [ ] PR body identifies the spec rule the previous code violated.
- [ ] Regression test references the section in its name.
- [ ] If the bug surfaced through a SAML peer (Okta, OneLogin, ADFS,
      etc.), call out the interop case alongside the spec citation.

### Refactor

- [ ] PR body asserts that no spec-observable behaviour changed.
- [ ] If a refactor *also* fixes a spec deviation it discovered, split
      the fix into a separate commit so it's reviewable independently.
- [ ] Test coverage thresholds (`vitest.config.ts`) still pass.

### Security fix

- [ ] Spec section in `saml-sec-consider` cited if applicable.
- [ ] Threat model paragraph in the PR body: which attack vector is
      closed.
- [ ] CHANGELOG / advisory note drafted before the PR is marked ready
      for review.

### Documentation change

- [ ] If documenting spec-defined behaviour, link to the spec section
      from the doc page itself, not just the PR.

## Examples

A passing PR body looks like:

> ## Summary
> Closes #584. Add the `simpleSign` branch to
> `Entity#createLogoutRequest` and `Entity#createLogoutResponse`.
>
> ## Spec reference
> - `saml-binding-simplesign §2` — HTTP-POST-SimpleSign binding,
>   octet-string construction and `Signature` form field.
> - `saml-bindings §3.5` — base form-post envelope inherited by
>   SimpleSign.
> - `saml-profiles §4.4` — Single Logout Profile processing rules.
>
> ## Test plan
> - [x] Logout request envelope under simpleSign.
> - [x] Detached signature emitted when target advertises
>       `wantLogoutRequestSigned`.
> - [x] Custom template callback path.

## When the spec is silent or ambiguous

Some behaviour samlify implements is interop-driven rather than
spec-mandated (e.g. tag-prefix handling for `<EncryptedAssertion>`).
In those cases:

- Cite the closest related section from the spec.
- Add a second citation to the IdP/SP behaviour you're matching (e.g.
  *"Okta interop: encryption namespace prefix `saml:` per
  https://help.okta.com/..."*).
- Note in the PR body that the change is interop-driven, not normative.
