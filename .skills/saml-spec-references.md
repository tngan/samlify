# SAML 2.0 — Spec references

Canonical sources every samlify contributor should be able to cite. Anchor
links point at the OASIS / W3C copies.

## OASIS SAML 2.0 (March 2005, OASIS Standard)

| Short name | Full title | URL |
| --- | --- | --- |
| `saml-core` | *Assertions and Protocols for the OASIS Security Assertion Markup Language (SAML) v2.0* | <https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf> |
| `saml-bindings` | *Bindings for the OASIS Security Assertion Markup Language (SAML) v2.0* | <https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf> |
| `saml-profiles` | *Profiles for the OASIS Security Assertion Markup Language (SAML) v2.0* | <https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf> |
| `saml-metadata` | *Metadata for the OASIS Security Assertion Markup Language (SAML) v2.0* | <https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf> |
| `saml-conformance` | *Conformance Requirements for SAML v2.0* | <https://docs.oasis-open.org/security/saml/v2.0/saml-conformance-2.0-os.pdf> |
| `saml-sec-consider` | *Security and Privacy Considerations for SAML v2.0* | <https://docs.oasis-open.org/security/saml/v2.0/saml-sec-consider-2.0-os.pdf> |
| `saml-glossary` | *Glossary for SAML v2.0* | <https://docs.oasis-open.org/security/saml/v2.0/saml-glossary-2.0-os.pdf> |
| `saml-authn-context` | *Authentication Context for SAML v2.0* | <https://docs.oasis-open.org/security/saml/v2.0/saml-authn-context-2.0-os.pdf> |
| `saml-tech-overview` | *SAML v2.0 Technical Overview* (non-normative) | <https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0.html> |
| `saml-errata` | *Approved Errata for SAML v2.0* | <https://docs.oasis-open.org/security/saml/v2.0/sstc-saml-approved-errata-2.0.pdf> |

## OASIS post-2.0 deliverables (extensions)

| Short name | Full title | URL |
| --- | --- | --- |
| `saml-binding-simplesign` | *SAML 2.0 HTTP-POST-SimpleSign Binding* | <https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-binding-simplesign-cd-04.pdf> |
| `saml-metadata-iop` | *Metadata Interoperability Profile* | <https://docs.oasis-open.org/security/saml/Post2.0/sstc-metadata-iop-cs-01.pdf> |

## OASIS XSD schemas

Drop into `.skills/specs/` for offline use, or fetch on demand:

| Schema | URL |
| --- | --- |
| `saml-schema-protocol-2.0.xsd` | <https://docs.oasis-open.org/security/saml/v2.0/saml-schema-protocol-2.0.xsd> |
| `saml-schema-assertion-2.0.xsd` | <https://docs.oasis-open.org/security/saml/v2.0/saml-schema-assertion-2.0.xsd> |
| `saml-schema-metadata-2.0.xsd` | <https://docs.oasis-open.org/security/saml/v2.0/saml-schema-metadata-2.0.xsd> |
| `saml-schema-x500-2.0.xsd` | <https://docs.oasis-open.org/security/saml/v2.0/saml-schema-x500-2.0.xsd> |

## W3C dependencies (signature, encryption, canonicalization)

| Short name | Full title | URL |
| --- | --- | --- |
| `xmldsig-core` | *XML Signature Syntax and Processing Version 1.1* | <https://www.w3.org/TR/xmldsig-core1/> |
| `xmlenc-core` | *XML Encryption Syntax and Processing Version 1.1* | <https://www.w3.org/TR/xmlenc-core1/> |
| `xml-c14n` | *Canonical XML Version 1.0* | <https://www.w3.org/TR/xml-c14n> |
| `xml-exc-c14n` | *Exclusive XML Canonicalization Version 1.0* | <https://www.w3.org/TR/xml-exc-c14n/> |
| `xml-c14n11` | *Canonical XML Version 1.1* | <https://www.w3.org/TR/xml-c14n11/> |

## Module → spec map (samlify)

The table below maps source modules to the sections they implement. Use
these anchors when citing in a PR; add a row whenever you introduce or
move responsibilities between modules.

| samlify path | Implements / governed by |
| --- | --- |
| `src/binding-redirect.ts` | `saml-bindings §3.4` (HTTP-Redirect Binding); §3.4.4.1 (signature octet string construction) |
| `src/binding-post.ts` | `saml-bindings §3.5` (HTTP-POST Binding) |
| `src/binding-simplesign.ts` | `saml-binding-simplesign` (HTTP-POST-SimpleSign), `saml-bindings §3.5` for the form-post envelope |
| `src/libsaml.ts` (signing/verification) | `saml-core §5` (SAML and XML Signature Syntax and Processing); `xmldsig-core` |
| `src/libsaml.ts` (encryption/decryption) | `saml-core §6` (SAML and XML Encryption Syntax and Processing); `xmlenc-core` |
| `src/libsaml.ts` (`isValidXml`) | `saml-conformance §3` and the OASIS schemas |
| `src/extractor.ts` | `saml-core §2` (Assertions), §3 (Protocols) — XPath-driven extraction of fields defined therein |
| `src/flow.ts` | `saml-profiles §4` (SSO Profiles); `saml-bindings` (per-binding processing rules); `saml-core §3.2.2` (StatusResponseType) |
| `src/metadata.ts` / `metadata-idp.ts` / `metadata-sp.ts` | `saml-metadata` (entire); `saml-metadata-iop` for interop subset |
| `src/entity-idp.ts` | `saml-profiles §4.1` (Web Browser SSO Profile, IdP role) |
| `src/entity-sp.ts` | `saml-profiles §4.1` (Web Browser SSO Profile, SP role); `saml-profiles §4.4` (SLO) |
| `src/validator.ts` | `saml-core §2.5.1.2` (Conditions / NotBefore / NotOnOrAfter); `saml-core §2.7.2.2` (SubjectConfirmationData) |
| `src/urn.ts` | `saml-core §8` (URI Reference Conventions); `saml-bindings §3` (binding URIs); `saml-profiles §3` (status code URIs) |

## Citation format

Prefer the form `saml-<doc> §<section>` in commit messages, PR bodies,
and JSDoc comments. Examples:

- `saml-core §5.4.2` — Reference processing rules for assertion signatures.
- `saml-bindings §3.4.4.1` — Octet string construction for HTTP-Redirect.
- `saml-profiles §4.1.4.5` — Subject confirmation processing for Web SSO.
- `xmldsig-core §4.5` — `<KeyInfo>` element.
