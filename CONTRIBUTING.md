# Contributing to samlify

Thanks for considering a contribution. samlify is a SAML 2.0 library, so
**correctness against the OASIS / W3C standards is the primary review
criterion**. Two short documents capture how we work:

- [`.skills/spec-citation-workflow.md`](./.skills/spec-citation-workflow.md)
  — what to cite, where, and per-change-type checklists.
- [`.skills/saml-spec-references.md`](./.skills/saml-spec-references.md)
  — canonical URLs for every normative document and a module → spec map.

The PR template (auto-loaded from `.github/pull_request_template.md`)
includes a required **Spec reference** section. Fill it in for any PR
touching `src/`.

## Quick start

```bash
yarn
yarn test
yarn coverage   # must stay ≥90% on every metric
```

## Bug reports and questions

Please open an issue with:

- The samlify version (`npm ls samlify`).
- The peer IdP / SP product if relevant (Okta, OneLogin, ADFS, …).
- A minimal repro and the relevant SAML message (redact secrets).
- The spec section you believe applies, if you've identified one.
