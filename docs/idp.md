# Identity Provider

Import the library entry point:

```javascript
const saml = require('samlify');
```

The metadata document below is typical of what an identity provider publishes:

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

Import the metadata to construct the identity provider. Starting from v2, configuration accepts a string (or buffer), which allows metadata, keys, and certificates to be loaded from any source — a database, the filesystem, a public URL, or in-memory storage.

::: warning Breaking changes since v2
The API has changed. See the example below.
:::

```javascript
// v2 and later.
const idp = saml.IdentityProvider({
  metadata: fs.readFileSync('./metadata/onelogin_metadata_486670.xml')
});

// Before v2 (deprecated).
// const idp = saml.IdentityProvider('./metadata/onelogin_metadata_486670.xml');
```
