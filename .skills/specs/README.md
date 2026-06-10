# Local spec cache (gitignored)

Drop downloaded PDF / XSD copies of the OASIS SAML 2.0 and W3C normative
documents here for offline reference. The `.gitignore` in this directory
ensures they are never committed.

To populate this directory, run the helper script (or copy the URLs from
[`../saml-spec-references.md`](../saml-spec-references.md)):

```bash
# from the repo root
bash .skills/specs/fetch.sh   # if/when added
```

## Why aren't these vendored in the repo?

- Combined size is ~100 MB across all OASIS + W3C deliverables.
- They're stable, externally hosted, and have canonical URLs that don't
  rot. There is no benefit to vendoring them and a real cost to clone
  size and history bloat.
- Citations in PRs and commit messages reference section anchors, not
  byte-level artefacts, so contributors don't need a local copy unless
  they're working offline.
