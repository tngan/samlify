# Service Provider

Let's get started to get the entry point.

```javascript
const saml = require('samlify');
```

You should have prepared the metadata of service provider.

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

Import the above metadata and get the service provider ready. Previously, we only allow user to enter path to file and the module will read for users. Starting from v2, we have relaxed the configuration to accept string, it allows user importing their metadata, key and certificate files from different sources. For examples, read from database, file systems, online resources (public url for metadata) and even in-memory storage.

!> **API is changed since v2**

```javascript
// after v2
const sp = saml.ServiceProvider({
  metadata: fs.readFileSync('./metadata/sp.xml')
});
// before v2 (deprecated)
// const sp = saml.ServiceProvider('./metadata/sp.xml');
```
