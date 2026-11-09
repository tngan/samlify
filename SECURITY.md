# Security policy

## Reporting

Report vulnerabilities privately at
https://github.com/tngan/samlify/security/advisories/new.
Do not use public issues, pull requests or discussions.

We also accept reports forwarded through HackerOne (samlify has no program
of its own). They are tracked as GitHub advisories under the same rules;
any reward is set by the HackerOne program.

Before reporting, check the [published advisories](https://github.com/tngan/samlify/security/advisories)
and the known findings in [`.skills/audits/`](.skills/audits/).

## Reproduction test (required)

Reports without a test are not accepted. The test is the starting point
for the fix. It must:

- be a vitest test that runs in this repository (e.g. `npx vitest run test/report.ts`),
  using the keys and metadata under `test/`
- fail on the current `master` and pass once fixed
- need no network access or external services

Include it in your report, not in a pull request. We may rewrite it as a
regression test.

Also include the affected versions, the impact, and a suggested fix if you
have one.

## Supported versions

| Version | Supported |
|---------|-----------|
| 2.15.x  | Yes       |
| < 2.15  | No        |

## Response

- Acknowledged within 3 days. If you have not heard from us, comment on your report.
- Confirmed or declined within 7 days.
- Fixed privately and published as a GitHub Security Advisory with the
  release. Several advisories may be released together.
- Keep details private until the advisory is published. If a fix takes more
  than 7 days after confirmation, we will explain why and agree on a
  disclosure date with you.

## Fixes

Fixes must be backward compatible, with no breaking interface changes
wherever possible. If a fix rejects input that was accepted before, we add
an opt-out, or warn first and change the default in the next major version.
Unavoidable breaking changes are listed in the release notes.

## Credit

Reporters are credited on the advisory and in the release notes, under the
name they choose.

- Independent private reports of the same issue are each credited.
- Issues that were already public, for example in our audit notes, are not credited.
- A new aspect of an existing issue is credited to its finder.

There is no bug bounty.

## Out of scope

- documented defaults that are scheduled to change, such as accepting unsigned
  logout messages (signed by default in v3)
- attacks that require control of trusted metadata or private keys
- dependency bugs that samlify does not expose; report these upstream
- the schema validator plugins (separate repositories) and the documentation site
