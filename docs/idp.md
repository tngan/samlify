# Identity Provider

Let's get started with entry point:
```javascript
const saml = require('samlify');
```

The following metadata is provided by the target identity provider.

```xml
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://app.onelogin.com/saml/metadata/486670">
  <IDPSSODescriptor xmlns:ds="http://www.w3.org/2000/09/xmldsig#" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>MIIEF...</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </KeyDescriptor>
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://esaml2.onelogin.com/trust/saml2/http-post/sso/486670"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://esaml2.onelogin.com/trust/saml2/http-post/sso/486670"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://esaml2.onelogin.com/trust/saml2/soap/sso/486670"/>
  </IDPSSODescriptor>
  <ContactPerson contactType="technical">
    <SurName>Support</SurName>
    <EmailAddress>support@onelogin.com</EmailAddress>
  </ContactPerson>
</EntityDescriptor>
```

Import the above metadata and get the identity provider ready. Previously, we only allow user to enter path to file and the module will read for users. Starting from v2, we have relaxed the configuration to accept string, it allows user importing their metadata, key and certificate files from different sources. For examples, read from database, file systems, online resources (public url for metadata) and even in-memory storage.

!> **API is changed since v2**

```javascript
// after v2
const idp = saml.IdentityProvider({
  metadata: fs.readFileSync('./metadata/onelogin_metadata_486670.xml')
});
// before v2 (deprecated)
// const idp = saml.IdentityProvider('./metadata/onelogin_metadata_486670.xml');
```
