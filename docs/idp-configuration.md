# IDP Configuration

You can use samlify as identity provider for testing/production purpose but you can also easily integrate samlify with the current identity provider setup.

#### Required Parameters

?> You can either choose to import from metadata plus optional paramters, or defined properties plus optional parameters.

- **metadata: String**<br/>
  IDP issued metadata to declare the structure and scope of the entity, as a common contract on how sso/slo should be proceeded.

```js
const idp = new IdentityProvider({
  // required
  metadata: readFileSync('./test/misc/idpmeta.xml'),
  // optional
  privateKey: readFileSync('./test/key/idp/privkey.pem'),
  privateKeyPass: 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW',
  encPrivateKey: readFileSync('./test/key/idp/encryptKey.pem'),
  encPrivateKeyPass: 'g7hGcRmp8PxT5QeP2q9Ehf1bWe9zTALN',
  isAssertionEncrypted: true,
});
```

OR

- **entityID: String**<br/> Entity identifier. It is used to identify your entity, and match the equivalence in each saml request/response.
  
- **signingCert: String**<br/>
  _Optional_: Specify the certificate used for signing purpose if you construct the idp without a metadata.

- **encryptCert: String**<br/>
  _Optional_: Specify the certificate used for encryption purpose if you construct the idp without a metadata.
  
- **singleSignOnService: SignOnService[]**<br/>
  _Optional_: Declare the single sign on service if you construct the idp without a metadata.

- **singleLogoutService: SignLogoutService[]**<br/>
  _Optional_: Declare the single logout service if you construct the idp without a metadata.

- **nameIDFormat: NameIDFormat[]**<br/>
  _Optional_: Declare the name id format that would respond if you construct the idp without a metadata.

```js
const idp = new IdentityProvider({
  // required
  entityID: 'http://hello-saml-idp.com/metadata',
  // optional parameters listed below
});
```

#### Optional Parameters

- **wantAuthnRequestsSigned: Boolean**<br/>
  Declare if idp guarantees the authn request sent from sp is signed, reflects to the `WantAuthnRequestsSigned` in idp metadata, default to `false`.

- **tagPrefix: {[key: TagPrefixKey]: string}**<br/>
  Declare the tag of specific xml document node. `TagPrefixKey` currently supports `encryptedAssertion` only. (See more [#220](https://github.com/tngan/samlify/issues/220))

- **loginResponseTemplate: {context: String, attributes: Attributes, additionalTemplates: LoginResponseAdditionalTemplates}**<br/>
  Customize the login response template, and user can reuse it in the callback function to do runtime interpolation. (See [more](/template)) 

- **wantLogoutResponseSigned: Boolean**<br/> 
  Declare if idp guarantees the logout response from sp is signed.

- **messageSigningOrder: SigningOrder**<br/>
  Declare the message signing order, either `sign-then-encrypt` (default) or `encrypt-then-sign`.

- **relayState: String**<br/>
  Specify the relayState of the request. 

  !> It will be deprecated soon and put into request level instead of entity level.

- **isAssertionEncrypted: Boolean**<br/>
  Decalre if idp would encrypt the assertion in the response.
  
  !> It will be deprecated soon, then samlify will automatically detect if the document is encrypted.
  
- **requestSignatureAlgorithm: SigningAlgorithm**<br/>
  The signature algorithm used in request. Default to `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`. We also support rsa-sha1 (not recommended) `http://www.w3.org/2000/09/xmldsig#rsa-sha1` and rsa-sha2 `http://www.w3.org/2001/04/xmldsig-more#rsa-sha512`.
  
- **dataEncryptionAlgorithm: EncryptionAlgorithm**<br/> 
  The encryption algorithm used in response. Default to `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`. We also support aes256 `http://www.w3.org/2001/04/xmlenc#aes256-cbc`, tripledes `http://www.w3.org/2001/04/xmlenc#tripledes-cbc` and aes128 `http://www.w3.org/2009/xmlenc11#aes128-gcm`.

- **keyEncryptionAlgorithm: KeyEncryptionAlgorithm**<br/>
  The key encryption algorithm. Default to rsa-1_5 `http://www.w3.org/2001/04/xmlenc#rsa-1_5`. We also support rsa-oaep-mgf1p `http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p`.

- **generateID: (): String**<br/>
  A function to generate the document identifier in root node. Default to `_${UUID_V4}`.
