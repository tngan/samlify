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
* http://www.w3.org/2000/09/xmldsig#rsa-sha1 (Default)
* http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
* http://www.w3.org/2001/04/xmldsig-more#rsa-sha512
* http://www.w3.org/2000/09/xmldsig#hmac-sha1

**Hashing Algorithms**
* http://www.w3.org/2000/09/xmldsig#sha1 (Default)
* http://www.w3.org/2001/04/xmlenc#sha256
* http://www.w3.org/2001/04/xmlenc#sha512

**Canonicalization and Transformation Algorithms**
* http://www.w3.org/2001/10/xml-exc-c14n#
* http://www.w3.org/2001/10/xml-exc-c14n#WithComments
* http://www.w3.org/2000/09/xmldsig#enveloped-signature

Credits to [yaronn/xml-crypto](https://github.com/yaronn/xml-crypto).

!> SAML Response must be signed if you use our API for creating identity providers.

We recommend user to accept signed response in their service provider. Therefore, our identity provider is RECOMMENDED to sign the response in order to maintain the confidentiality and message integrity [Section 4.1.3.5](http://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf).

There are different examples of signing scheme supported in samlify.

+ **Unsigned message, Signed assertion (wo/ encryption)**

To guarantee the setting in between idp-sp pair is synchronized, determination of assertion signature depends on the sp setting. Set `WantAssertionsSigned` to true in corresponding sp's metadata or `wantAssertionsSigned` in constructor if metadata is not set.

```javascript
const sp = ServiceProvider({
  // ...
  metadata: readFileSync('./sp-metadata.xml'),
  // must have if assertion signature fails validation
  // transformationAlgorithms: [
  //     'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
  //     'http://www.w3.org/2001/10/xml-exc-c14n#',
  // ],
});

const idp = IdentityProvider({
  // ...
  metadata: readFileSync('./idp-metatadata.xml'),
  privateKey: readFileSync('./mysecret.pem'),
  privateKeyPass: 'zzz', // if has
  // must have if metadata is not provided
  // signingCert: readFileSync('./signing.cer') 
});
```

The certificate of identity provider will be included in its metadata, or specify in constructor as `signingCert`.

+ **Unsigned message, Signed & Encrypted assertion**

SP's preparation is same as the first case. For encrpytion part, identity provider encrypts the assertion with sp's certificate (public key) and sp can decrypt the response using sp's private key.

IdP controls whether the response is encrypted or not.

```javascript
// create in sp side, private key for decryption is owned by sp only

const sp = ServiceProvider({
  // ...
  metadata: readFileSync('./sp-metadata.xml'),
  encPrivateKey: fs.readFileSync('./encryptKey.pem'),
  encPrivateKeyPass: 'yyy',
  // must have if metadata is not provided
  // signingCert: readFileSync('./signing.cer') 
  // encryptCert: readFileSync('./encrypt.cer')
});
```

```javascript
// create in idp side

const sp = ServiceProvider({
  // ...
  metadata: readFileSync('./sp-metadata.xml'),
});

const idp = IdentityProvider({
  // ...
  isAssertionEncrypted: true,
  metadata: readFileSync('./idp-metatadata.xml'),
  privateKey: readFileSync('./mysecret.pem'),
  privateKeyPass: 'xxx', // if has
  // must have if metadata is not provided
  // signingCert: readFileSync('./signing.cer') 
});
```

+ **Signed message, Unsigned assertion (w/wo encryption)**

There are two new properties added into the constructor method for idp starting from v2. `wantMessageSigned` and `signatureConfig` are used to enrich our signature scheme whereas `signatureConfig` is same as the configuration in [xml-crypto](https://
github.com/yaronn/xml-crypto#examples).

```javascript
const idp = IdentityProvider({
  // ...
  wantMessageSigned: true,
  signatureConfig: {
    prefix: 'ds',
    location: { 
      reference: '/samlp:Response/saml:Issuer', 
      action: 'after'
    }
  }
});
```

+ **Signed message, Signed assertion (wo/ encryption)**

See above signed message and signed assertion setting.

+ **Signed message, Signed & Encrypted assertion**

The most complex case, see above all.