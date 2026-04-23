# Signed SAML Request

samlify honours the signing preferences declared in metadata. When metadata does not specify otherwise, SAML requests are not signed by default.

In the IdP metadata, the `WantAuthnRequestsSigned` attribute controls whether the IdP requires signed requests. The default is `false`:

```xml
<IDPSSODescriptor
    WantAuthnRequestsSigned="true"
    ID="SM14a93e72cb19411b4fc4eec882c98b12dbf55cea68e"
    protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
```

In the SP metadata, the `AuthnRequestsSigned` attribute controls whether the SP signs its requests. The default is `false`:

```xml
<SPSSODescriptor
    AuthnRequestsSigned="true"
    protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
```

When the SP signs requests, its X.509 certificate must be included in the metadata:

```xml
<SPSSODescriptor
    AuthnRequestsSigned="true"
    WantAssertionsSigned="true"
    protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">

    <KeyDescriptor use="signing">
        <KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <X509Data>
                <X509Certificate>MIIDozCCAougAwIBAgIJAKN...</X509Certificate>
            </X509Data>
        </KeyInfo>
    </KeyDescriptor>
    ...
```

If the SP and IdP preferences do not agree, samlify throws an error at runtime so the mismatch can be diagnosed quickly.

If the IdP does not publish metadata, either request it or configure the IdP programmatically (see [IdP configuration](/idp-configuration)).

Metadata only declares preferences. To sign an XML document, samlify also needs the **private key** and the **signature algorithm**:

```javascript
const saml = require('samlify');

// Define the SP settings.
const setting = {
  privateKey: fs.readFileSync('./key/sp_key.pem'),
  privateKeyPass: 'KCkGOSjrcAuXFwU1pVH5RUiBcrsNA8px',
  requestSignatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',
  metadata: fs.readFileSync('./metadata_sp.xml')
};

// Construct the service provider.
const sp = saml.ServiceProvider(setting);
```

`privateKeyPass` is only required when the private key is encrypted. `requestSignatureAlgorithm` defaults to RSA-SHA256.

Supported signature algorithms:

```javascript
'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512'
```

Once the SP is configured, sending a signed SAML request uses the same entry point as the unsigned case:

```javascript
router.get('/spinitsso-redirect', (req, res) => {
  const { id, context } = sp.createLoginRequest(idp, 'redirect');
  return res.redirect(context);
});
```

## How the signature is generated

This section explains how samlify computes the signature for each binding. Skip it if you only need the API surface.

### HTTP-Redirect binding

- The canonical octet string is the URL-encoded concatenation of `SAMLRequest`, `RelayState`, and `SigAlg`: `SAMLRequest=xxx&RelayState=yyy&SigAlg=zzz`.
- The resulting signature is base64-encoded.
- `RelayState` is optional. When absent, it is omitted from the octet string: `SAMLRequest=xxx&SigAlg=zzz`.

### HTTP-POST binding

The binding uses an XML digital signature embedded inside the AuthnRequest:

```xml
<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="_809707f0030a5d00620c9d9df97f627afe9dcc24"
    Version="2.0"
    ProviderName="SP test"
    IssueInstant="2014-07-16T23:52:45Z"
    Destination="https://idp.example.org/SSOService"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    AssertionConsumerServiceURL="https://sp.example.org/sso/acs">

    <saml:Issuer ID="_0">https://sp.example.org/metadata</saml:Issuer>
    <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/>
        <samlp:RequestedAuthnContext Comparison="exact">
            <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
        </samlp:RequestedAuthnContext>

        <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
            <SignedInfo>
                <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
                <Reference URI="#_0">
                    <Transforms>
                        <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                    </Transforms>
                    <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                    <DigestValue>tQDisBXKTQ+9OXJO5r7KuJga+KI=</DigestValue>
                </Reference>
            </SignedInfo>
            <SignatureValue>oxRkvau7UvYgFEZ7YNAUNf3067V7Tn5C9XSIiet1aZw2FYevNW5bUy/0mxp3aj6AvfFjnmpzAb88BjdwAz2BErDTomRcuZB7Lb0fYTf31N2oZOX0MiPiQOH54I63qJW4Xo3VqdF7GBuFZZHyllfSBv7gfCtjJDwFSCzWK70B9r3cFMRJZLhCJ9oPen+4U9scSYO6g+szBZLl6AiJ06PHc8jzEKGwfQrcZk8kDKUlvNfJMULyq8dpx2VvUAx4p5ewfMOwB9W3Hl3PPa0dO77zZif3CglpcN06f+m6UYG/wnoTQEyKW9hOe+2vGM80W77eWu0dmiaPuqT1ok8LXPuq1A==</SignatureValue>
        </Signature>
</samlp:AuthnRequest>
```
