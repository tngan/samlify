# Receive a SAML Response

SP sends out the SAML Request to IdP, IdP will send back a SAML Response telling the authentication result. In SAML specification, SP doesn't expect the returned response which includes signature by default. In our module, it's recommended to accept signed SAML Response. In this chapter, we begin with receiving a SAML Response without signature first.

The following is the sample Response XML, it must be sent using Post-Binding instead of Redirect-Binding. It would exceed the limitation of URL length because of the lengthy assertion.

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

The assertion can also be encrypted in case there exists sensitive information. See the chapter 'Encrypted SAML Response' for more detail.

By using this module, parsing and verifying this response is the job of SP. See the following code snippet:

```javascript
router.post('/acs', (req, res) => {
  sp.parseLoginResponse(idp, 'post', req)
  .then(parseResult => {
    // Use the parseResult can do customized action
  })
  .catch(console.error);
});
```

Here an endpoint for assertion consumer service (acs) is created, where the SAML Response is sent to. This URL must be same as the one specified in SP's metadata.

```xml
<AssertionConsumerService 
        isDefault="true" 
        index="0" 
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" 
        Location="http://localhost:4002/sso/acs"
/>
```
`sp.parseLoginResponse` is used to parse the SAML Response and extract the attributes, name ID, and other information from the SAML Response. Therefore, developer can write their own business logic by taking the parsed data. Also, this method also helps to do verification of signature if `WantAssertionSigned` is specified in SP's metadata. See 'Signed SAML Response' for more detail.

The verification is done inside `sp.parseLoginResponse`:
+ Signature
+ Issuer name

The callback function inside `sp.parseLoginResponse` returns an object named `parseResult`:

```javascript
{
  samlContent: "<samlp:Response ...",
  extract: {
    audience: "https://sp.example.org/sso/metadata",
    attribute: {
      email: "user@esaml2.com",
      lastName: "Samuel",
      firstName: "E"
    },
    conditions: {
      notbefore: "2015-10-26T11:41:43.500Z"
      notonorafter: "2015-10-26T11:46:43.500Z"
    },
    issuer: ['https://sp.example.org/sso/metadata'],
    nameID: "user@esaml2.com"
    signature: "<Signature ... </Signature>",
    statuscode: {
      value: "urn:oasis:names:tc:SAML:2.0:status:Success"
    }
  }
}
```

We do the basic checking and leave for developers to write their own callback. (e.g. verify the conditions, status code ... etc). See 'Advanced' tutorial for more detail. And some common status codes are shown in the list:

```javascript
statusCode: {
  // permissible top-level status codes
  success: 'urn:oasis:names:tc:SAML:2.0:status:Success',
  requester: 'urn:oasis:names:tc:SAML:2.0:status:Requester',
  responder: 'urn:oasis:names:tc:SAML:2.0:status:Responder',
  versionMismatch: 'urn:oasis:names:tc:SAML:2.0:status:VersionMismatch',
  // second-level status codes
  authFailed: 'urn:oasis:names:tc:SAML:2.0:status:AuthnFailed',
  invalidAttrNameOrValue: 'urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue',
  invalidNameIDPolicy: 'urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy',
  noAuthnContext:'urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext',
  noAvailableIDP:'urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP',
  noPassive:'urn:oasis:names:tc:SAML:2.0:status:NoPassive',
  noSupportedIDP:'urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP',
  partialLogout:'urn:oasis:names:tc:SAML:2.0:status:PartialLogout',
  proxyCountExceeded:'urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded',
  requestDenied:'urn:oasis:names:tc:SAML:2.0:status:RequestDenied',
  requestUnsupported:'urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported',
  requestVersionDeprecated:'urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated',
  requestVersionTooHigh:'urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh',
  requestVersionTooLow:'urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow',
  resourceNotRecognized:'urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized',
  tooManyResponses:'urn:oasis:names:tc:SAML:2.0:status:TooManyResponses',
  unknownAttrProfile:'urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile',
  unknownPrincipal:'urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal',
  unsupportedBinding:'urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding'
}
```

