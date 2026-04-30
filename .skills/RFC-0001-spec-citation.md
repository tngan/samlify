# RFC-0001: Mandatory SAML 2.0 spec citation for code-touching PRs

- **Status:** Draft
- **Author:** *(maintainer to fill in)*
- **Created:** 2026-04-29
- **Discussion:** *(GitHub PR link will go here once opened)*

## Summary

Introduce a `.skills/` directory that captures samlify's contribution
conventions in machine- and human-readable playbooks. Establish a
**spec citation workflow** that requires every PR touching `src/` to
cite the OASIS SAML 2.0 (or W3C XML-DSig / XML-Enc) section the change
implements, fixes, or extends.

## Motivation

samlify is a SAML 2.0 implementation. The library's correctness is
defined entirely by external normative documents:

- OASIS SAML 2.0 Core, Bindings, Profiles, Metadata, Conformance, and
  Security Considerations.
- W3C XML Signature, XML Encryption, and Canonicalization specs.

Today, contributors and reviewers reason about correctness from memory
or from prior code. This is fragile:

- Bug reports often turn out to be spec-conformance bugs, but the PR
  history rarely says so.
- It is easy to "fix" a perceived bug by introducing behaviour that
  satisfies one peer and violates the spec for everyone else.
- New contributors don't have a single place to learn which sections
  matter and where they're implemented.

A formalised workflow with low ceremony fixes all three problems and
costs reviewers ~30 seconds per PR.

## Proposal

### `.skills/` directory

Add a top-level `.skills/` directory containing:

| File | Purpose |
| --- | --- |
| `README.md` | Index. |
| `saml-spec-references.md` | Canonical URLs for every normative document samlify touches, plus a **module → spec map** that points each `src/` file at the section(s) it implements. |
| `spec-citation-workflow.md` | The skill itself: when it applies, what to cite, per-change-type checklists, examples. |
| `specs/` | Local-only PDF cache. Contents gitignored. |

### PR template

Add `.github/pull_request_template.md` with a required **Spec
reference** section. The template is enforced socially (reviewers
block PRs missing it) rather than via a CI gate, so that genuinely
spec-orthogonal PRs (CI tweaks, dependency bumps) can opt out by
explaining themselves.

### CONTRIBUTING.md pointer

Add a short pointer from `CONTRIBUTING.md` (creating one if absent) so
external contributors discover the skill before they open a PR.

## Non-goals

- **Not a CI gate.** False positives would frustrate maintainers more
  than they would catch real misses. A `block-on-missing-citation`
  workflow can be added later if review fatigue becomes the bottleneck.
- **Not a vendored spec corpus.** PDFs are large, copyrighted, and
  externally hosted. We cite, we don't bundle.
- **Not a process for non-code PRs.** Tooling, release plumbing, and
  cosmetic doc fixes don't need citations.

## Alternatives considered

1. **Vendor the spec PDFs into the repo.** Rejected — ~100 MB of
   binary churn, slow clones, no clear gain over canonical URLs.
2. **Inline the citations in JSDoc only.** Rejected — JSDoc citations
   are great but don't surface in PR review or `git log`. The skill
   complements rather than replaces JSDoc citations.
3. **Lint rule that requires a `@spec` JSDoc tag on exported
   functions.** Worth considering as a follow-up once the skill is
   bedded in. Out of scope for this RFC.

## Migration

- The first PR that lands this RFC ships:
  - The `.skills/` content.
  - The PR template.
  - A short CONTRIBUTING blurb.
- Existing files are **not** retroactively annotated; the skill applies
  to PRs opened after merge.
- The first three PRs to follow the new template should be reviewed
  with extra care to validate the workflow. If the template proves
  unwieldy, amend it via a follow-up PR.

## Open questions

1. Should `.skills/` be the canonical name, or should we use
   `.claude/skills/` (Claude Code's convention) or `docs/playbooks/`?
   Default: `.skills/` — tool-agnostic, discoverable via `ls`.
2. Do we want a stub script (`bash .skills/specs/fetch.sh`) to
   download all PDFs into the local cache? Default: yes, as a
   follow-up PR after this lands.
3. Should we require a citation for **bumping a dependency** when the
   bump is security-driven? Default: no — the bump's CHANGELOG link
   is sufficient.
