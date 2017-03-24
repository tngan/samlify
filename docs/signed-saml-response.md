# Signed SAML Response

The configuration for the use case receiving signed SAML Response is very simple. First, developers have to make sure that Identity Provider would sign the response. Second, define the property `WantAssertionsSigned` in SP's metadata inside the `SPSSODescriptor` tag.

```xml
<SPSSODescriptor 
    AuthnRequestsSigned="true" 
    WantAssertionsSigned="true" 
    protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
```
Currently, we support the following algorithms:

**Signature algorithms**
* http://www.w3.org/2000/09/xmldsig#rsa-sha1 (Default in v1)
* http://www.w3.org/2001/04/xmldsig-more#rsa-sha256 (Default in v2)
* http://www.w3.org/2001/04/xmldsig-more#rsa-sha512
* http://www.w3.org/2000/09/xmldsig#hmac-sha1

**Hashing Algorithms**
* http://www.w3.org/2000/09/xmldsig#sha1 (Default in v1)
* http://www.w3.org/2001/04/xmlenc#sha256 (Default in v2)
* http://www.w3.org/2001/04/xmlenc#sha512

**Canonicalization and Transformation Algorithms**
* http://www.w3.org/2001/10/xml-exc-c14n#
* http://www.w3.org/2001/10/xml-exc-c14n#WithComments
* http://www.w3.org/2000/09/xmldsig#enveloped-signature

Credits to [yaronn/xml-crypto](https://github.com/yaronn/xml-crypto).
