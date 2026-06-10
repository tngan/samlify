# Receiving a SAML Response

When the SP sends a SAML request, the IdP replies with a SAML response containing the authentication result. The SAML specification does not require signed responses by default, but samlify strongly recommends that SPs accept only signed responses. This chapter begins with the simpler unsigned case.

The example below shows a typical SAML response. Responses are delivered via HTTP-POST rather than HTTP-Redirect because the assertion would exceed the URL length limits imposed by many browsers.

```xml
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6" Version="2.0" IssueInstant="2014-07-17T01:01:48Z" Destination="http://sp.example.com/demo1/index.php?acs" InResponseTo="_41e758fee373d51639552c4b040b1090e97f6685">
  <saml:Issuer>https://idp.example.com/metadata</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75" Version="2.0" IssueInstant="2014-07-17T01:01:48Z">
    <saml:Issuer>https://idp.example.com/metadata</saml:Issuer>
    <saml:Subject>
      <saml:NameID SPNameQualifier="https://sp.example.com/metadata" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="2024-01-18T06:21:48Z" Recipient="http://sp.example.com/demo1/index.php?acs" InResponseTo="_4fee3b046395c4e751011e97f8900b5273d56685"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2014-07-17T01:01:18Z" NotOnOrAfter="2024-01-18T06:21:48Z">
      <saml:AudienceRestriction>
        <saml:Audience>https://sp.example.com/metadata</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2014-07-17T01:01:48Z" SessionNotOnOrAfter="2024-07-17T09:01:48Z" SessionIndex="_be9967abd904ddcae3c0eb4189adbe3f71e327cf93">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="uid" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">test</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">test@example.com</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="eduPersonAffiliation" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">users</saml:AttributeValue>
        <saml:AttributeValue xsi:type="xs:string">examplerole1</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
```

When the assertion carries sensitive information, it may also be encrypted. See [Encrypted SAML Response](/encrypted-saml-response) for details.

Parsing and verifying the response is the SP's responsibility:

```javascript
router.post('/acs', (req, res) => {
  sp.parseLoginResponse(idp, 'post', req)
    .then(parseResult => {
      // Use parseResult to run your business logic.
    })
    .catch(console.error);
});
```

The handler is mounted at the Assertion Consumer Service (ACS) endpoint, the URL to which the IdP posts SAML responses. It must match the `Location` declared in the SP metadata:

```xml
<AssertionConsumerService
        isDefault="true"
        index="0"
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="http://localhost:4002/sso/acs"
/>
```

`sp.parseLoginResponse` parses the SAML response and extracts attributes, the NameID, and other fields so that application code can act on them. It also verifies the assertion signature when `WantAssertionsSigned` is declared in the SP metadata; see [Signed SAML Response](/signed-saml-response) for details.

Signature verification performed inside `sp.parseLoginResponse`:

- XML signature
- Issuer name

The promise resolves to a `parseResult` object. The `extract` member is
keyed by the field names declared in `src/extractor.ts:loginResponseFields`,
and inner attribute keys are camelCased (so `NotBefore` becomes `notBefore`).

```javascript
{
  samlContent: "<samlp:Response ...",
  extract: {
    response: {
      id: "_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6",
      issueInstant: "2015-10-26T11:41:43.500Z",
      destination: "https://sp.example.org/sso/acs",
      inResponseTo: "_4fee3b046395c4e751011e97f8900b5273d56685"
    },
    issuer: "https://idp.example.org/sso/metadata",
    nameID: "user@esaml2.com",
    audience: "https://sp.example.org/sso/metadata",
    conditions: {
      notBefore: "2015-10-26T11:41:43.500Z",
      notOnOrAfter: "2015-10-26T11:46:43.500Z"
    },
    sessionIndex: {
      authnInstant: "2015-10-26T11:41:43.500Z",
      sessionNotOnOrAfter: "2015-10-26T19:41:43.500Z",
      sessionIndex: "_be9967abd904ddcae3c0eb4189adbe3f71e327cf93"
    },
    attributes: {
      email: "user@esaml2.com",
      lastName: "Samuel",
      firstName: "E"
    }
  }
}
```

Status code validation runs inside `parseLoginResponse`. A non-success
top-level code rejects the promise with
`ERR_FAILED_STATUS with top tier code: ..., second tier code: ...`,
so the status code is not surfaced on the resolved `extract` object.

samlify performs baseline validation and leaves application-specific checks (time conditions, status codes, etc.) to the caller. See the [Advanced](/advanced) tutorial for more detail. The full set of SAML status codes is:

```javascript
statusCode: {
  // Permissible top-level status codes.
  success: 'urn:oasis:names:tc:SAML:2.0:status:Success',
  requester: 'urn:oasis:names:tc:SAML:2.0:status:Requester',
  responder: 'urn:oasis:names:tc:SAML:2.0:status:Responder',
  versionMismatch: 'urn:oasis:names:tc:SAML:2.0:status:VersionMismatch',
  // Second-level status codes.
  authFailed: 'urn:oasis:names:tc:SAML:2.0:status:AuthnFailed',
  invalidAttrNameOrValue: 'urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue',
  invalidNameIDPolicy: 'urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy',
  noAuthnContext: 'urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext',
  noAvailableIDP: 'urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP',
  noPassive: 'urn:oasis:names:tc:SAML:2.0:status:NoPassive',
  noSupportedIDP: 'urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP',
  partialLogout: 'urn:oasis:names:tc:SAML:2.0:status:PartialLogout',
  proxyCountExceeded: 'urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded',
  requestDenied: 'urn:oasis:names:tc:SAML:2.0:status:RequestDenied',
  requestUnsupported: 'urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported',
  requestVersionDeprecated: 'urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated',
  requestVersionTooHigh: 'urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh',
  requestVersionTooLow: 'urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow',
  resourceNotRecognized: 'urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized',
  tooManyResponses: 'urn:oasis:names:tc:SAML:2.0:status:TooManyResponses',
  unknownAttrProfile: 'urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile',
  unknownPrincipal: 'urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal',
  unsupportedBinding: 'urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding'
}
```
