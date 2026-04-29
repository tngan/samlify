# Signed SAML Response

Consuming a signed SAML response requires only a small amount of configuration. First, ensure that the identity provider signs the response. Second, declare `WantAssertionsSigned` inside the `SPSSODescriptor` of the SP metadata:

```xml
<SPSSODescriptor
    AuthnRequestsSigned="true"
    WantAssertionsSigned="true"
    protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
```

Supported algorithms:

**Signature algorithms**

- `http://www.w3.org/2000/09/xmldsig#rsa-sha1` *(default)*
- `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`
- `http://www.w3.org/2001/04/xmldsig-more#rsa-sha512`
- `http://www.w3.org/2000/09/xmldsig#hmac-sha1`

**Hashing algorithms**

- `http://www.w3.org/2000/09/xmldsig#sha1` *(default)*
- `http://www.w3.org/2001/04/xmlenc#sha256`
- `http://www.w3.org/2001/04/xmlenc#sha512`

**Canonicalization and transformation algorithms**

- `http://www.w3.org/2001/10/xml-exc-c14n#`
- `http://www.w3.org/2001/10/xml-exc-c14n#WithComments`
- `http://www.w3.org/2000/09/xmldsig#enveloped-signature`

XML signature operations are provided by [yaronn/xml-crypto](https://github.com/yaronn/xml-crypto).

::: warning
When samlify is used as the identity provider, SAML responses are always signed.
:::

samlify recommends that service providers accept only signed responses and that identity providers sign every response, in order to preserve confidentiality and message integrity (see [SAML Profiles §4.1.3.5](http://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf)).

The following signing schemes are supported.

### Unsigned message, signed assertion (no encryption)

The IdP-SP agreement on assertion signing comes from the SP configuration. Set `WantAssertionsSigned` to `true` in the SP metadata, or set `wantAssertionsSigned` in the constructor when no metadata document is supplied.

```javascript
const sp = ServiceProvider({
  // ...
  metadata: readFileSync('./sp-metadata.xml'),
  // Required if assertion signature validation fails.
  // transformationAlgorithms: [
  //   'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
  //   'http://www.w3.org/2001/10/xml-exc-c14n#',
  // ],
});

const idp = IdentityProvider({
  // ...
  metadata: readFileSync('./idp-metadata.xml'),
  privateKey: readFileSync('./mysecret.pem'),
  privateKeyPass: 'zzz', // Omit if the key has no passphrase.
  // Required if no metadata is supplied.
  // signingCert: readFileSync('./signing.cer'),
});
```

The IdP's signing certificate is read from its metadata, or from `signingCert` when metadata is not supplied.

### Unsigned message, signed and encrypted assertion

The SP configuration is identical to the previous case. For encryption, the IdP encrypts the assertion with the SP's public key so that only the SP (holder of the corresponding private key) can decrypt it. The IdP controls whether the response is encrypted.

```javascript
// SP side: the decryption private key never leaves the SP.
const sp = ServiceProvider({
  // ...
  metadata: readFileSync('./sp-metadata.xml'),
  encPrivateKey: fs.readFileSync('./encryptKey.pem'),
  encPrivateKeyPass: 'yyy',
  // Required if no metadata is supplied.
  // signingCert: readFileSync('./signing.cer'),
  // encryptCert: readFileSync('./encrypt.cer'),
});
```

```javascript
// IdP side.
const sp = ServiceProvider({
  // ...
  metadata: readFileSync('./sp-metadata.xml'),
});

const idp = IdentityProvider({
  // ...
  isAssertionEncrypted: true,
  metadata: readFileSync('./idp-metadata.xml'),
  privateKey: readFileSync('./mysecret.pem'),
  privateKeyPass: 'xxx', // Omit if the key has no passphrase.
  // Required if no metadata is supplied.
  // signingCert: readFileSync('./signing.cer'),
});
```

### Signed message, unsigned assertion (with or without encryption)

Starting from v2, the **service provider** can opt into a signed
top-level `<Response>` via `wantMessageSigned` together with
`signatureConfig`. `signatureConfig` accepts the same options as
[xml-crypto](https://github.com/yaronn/xml-crypto#examples). The IdP
honours these SP-side preferences when it builds the response.

```javascript
const sp = ServiceProvider({
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

const idp = IdentityProvider({
  // ...
  // No additional flags required: the IdP signs the message because
  // the SP requested it.
});
```

### Signed message, signed assertion (no encryption)

Combine the settings from *signed message* and *signed assertion* sections above.

### Signed message, signed and encrypted assertion

The most involved case — combine all of the above.
