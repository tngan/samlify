# Encrypted Assertion

According to the guideline of SAML, our module leaves some security options for developers. If the assertion contains some sensitive information, Identity Provider may want to do encryption. In IdP's construction, add the following settings as follow:

```javascript
const idp = IdentityProvider({
  isAssertionEncrypted: true,
  metadata: fs.readFileSync('./metadata_idp.xml'),
  dataEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc',
  keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-1_5' 
});
```

If you remember SP configuration for signing a request, there are two parameters in the setting object. They are `privateKey` and `privateKeyPass`. **Warning:** If you are applying our solution instead of another 3rd party IdP, it's suggested not to use same key for both signing and encryption.

In SP's metadata, the certificate must be included in order to allow idp to encrypt the assertion.

```xml
<KeyDescriptor use="encryption">
    <KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
            <X509Certificate>MIID6TCCAtGg...</X509Certificate>
        </X509Data>
    </KeyInfo>
</KeyDescriptor>
```

Now all you need to do is to use `sp.parseLoginResponse` again to parse and verify the response.

```javascript
router.post('/acs', (req, res) => {
  sp.parseLoginResponse(idp, 'post', req)
  .then(parseResult => {
    // Use the parseResult to do customized action
  })
  .catch(console.error);
});
```

Currently, we support the following encrpytion algorithms:

**Data encryption algorithms**
* http://www.w3.org/2001/04/xmlenc#tripledes-cbc
* http://www.w3.org/2001/04/xmlenc#aes128-cbc
* http://www.w3.org/2001/04/xmlenc#aes256-cbc
* http://www.w3.org/2009/xmlenc11#aes128-gcm

**Key encryption algorithms**
* http://www.w3.org/2001/04/xmlenc#rsa-1_5
* http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p

Credits to [auth0/node-xml-encryption](https://github.com/auth0/node-xml-encryption)
