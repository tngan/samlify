# Service Provider

Import the library entry point:

```javascript
const saml = require('samlify');
```

Prepare the metadata document for the service provider:

```xml
<EntityDescriptor
 xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
 xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
 xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
 entityID="https://sp.example.org/metadata">
    <SPSSODescriptor WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <KeyDescriptor use="signing">
            <KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <X509Data>
                    <X509Certificate>MIID...</X509Certificate>
                </X509Data>
            </KeyInfo>
        </KeyDescriptor>
        <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
        <AssertionConsumerService isDefault="true" index="0" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.org/acs"/>
    </SPSSODescriptor>
</EntityDescriptor>
```

Import the metadata to construct the service provider. Starting from v2, configuration accepts a string (or buffer), which allows metadata, keys, and certificates to be loaded from any source — a database, the filesystem, a public URL, or in-memory storage.

::: warning Breaking changes since v2
The API has changed. See the example below.
:::

```javascript
// v2 and later.
const sp = saml.ServiceProvider({
  metadata: fs.readFileSync('./metadata/sp.xml')
});

// Before v2 (deprecated).
// const sp = saml.ServiceProvider('./metadata/sp.xml');
```
