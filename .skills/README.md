# `.skills/` — samlify development playbooks

Skills are short, focused playbooks that capture conventions and workflows
specific to maintaining samlify. They are intended to be readable by both
human contributors and AI assistants (e.g. Claude Code, GitHub Copilot
Workspace) so that the project's standards are applied consistently across
PRs.

## Index

| Skill | When to invoke |
| --- | --- |
| [`spec-citation-workflow.md`](./spec-citation-workflow.md) | Every PR that touches `src/` (feature, bug fix, refactor) — cite the SAML 2.0 / W3C section the change implements or fixes. |
| [`saml-spec-references.md`](./saml-spec-references.md) | Reference: canonical URLs for all OASIS SAML 2.0 documents, W3C XML-DSig / XML-Enc / canonicalization, plus a module → spec map for samlify itself. |
| [`RFC-0001-spec-citation.md`](./RFC-0001-spec-citation.md) | The proposal that introduced these skills. |
| [`audits/`](./audits/) | Dated security-audit reports. The most recent is [`audits/2026-04-security-audit.md`](./audits/2026-04-security-audit.md). |

## How to add a skill

1. Create a new file under `.skills/<short-kebab-name>.md`.
2. Use the structure: **Purpose**, **When to apply**, **Procedure**, **Checklist**.
3. Add a row to the index above.
4. Open a PR with the `skill:` prefix in the title so reviewers can spot it.

## Spec sources (offline)

The `specs/` subdirectory is a *local-only* cache for PDF copies of the
normative documents. Its contents are gitignored — see `specs/.gitignore`.
Use the canonical URLs in `saml-spec-references.md` to download a copy when
you need offline access.
