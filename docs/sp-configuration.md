# SP Configuration

#### Required Parameters

?> You can either choose to import from metadata plus optional paramters, or defined properties plus optional parameters.

- **metadata: String**<br/>
  SP issued metadata to declare the structure and scope of the entity, as a common contract on how sso/slo should be proceeded.

```js
const sp = new ServiceProvider({
  // required
  metadata: readFileSync('./test/misc/spmeta.xml'),
  // optional
  privateKey: readFileSync('./test/key/sp/privkey.pem'),
  privateKeyPass: 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW',
  encPrivateKey: readFileSync('./test/key/sp/encryptKey.pem'),
  encPrivateKeyPass: 'g7hGcRmp8PxT5QeP2q9Ehf1bWe9zTALN'
});
```

OR

- **entityID: String**<br/> Entity identifier. It is used to identify your entity, and match the equivalence in each saml request/response.

- **authnRequestsSigned: Boolean**<br/>
  _Optional_: Declare if sp signs the authn request, reflects to the `AuthnRequestsSigned` in sp metadata, default to `false`.

- **wantAssertionsSigned: Boolean**<br/>
  _Optional_: Declare if sp wants the signed assertion, reflects to the `WantAssertionsSigned` in sp metadata, default to `false`.

- **wantMessageSigned: Boolean**<br/>
  _Optional_: Declare if sp wants the signed message, default to `false`.

- **signingCert: String**<br/>
  _Optional_: Specify the certificate used for signing purpose if you construct the sp without a metadata.

- **encryptCert: String**<br/>
  _Optional_: Specify the certificate used for encryption purpose if you construct the sp without a metadata.

- **elementsOrder: String[]**<br/>
  _Optional_: Define the DOM structure of xml document, default to `['KeyDescriptor', 'NameIDFormat', 'SingleLogoutService', 'AssertionConsumerService']`. (See more [#89](https://github.com/tngan/samlify/issues/89))

- **nameIDFormat: NameIDFormat[]**<br/>
  _Optional_: Declare the name id format that would respond if you construct the sp without a metadata. The request will always pick the first one if multiple formats are specified.

- **singleLogoutService: Service[]**<br/>
  _Optional_: Declare the single logout service if you construct the sp without a metadata.

- **assertionConsumerService: Service[]**<br/>
  _Optional_: Declare the asssertion consumer service where the saml response redirects to if you construct the sp without a metadata.

- **signatureConfig: SignatureConfig**<br/>
  _Optional_: Configure how the signature is being constructed. (See [more](/signed-saml-response))

```js
const sp = new ServiceProvider({
  // required
  entityID: 'http://hello-saml-sp.com/metadata',
  // optional parameters listed below
});
```

#### Optional Parameters

- **loginRequestTemplate: {context: String, attributes: Attributes}**<br/>
  Customize the login request template, and user can reuse it in the callback function to do runtime interpolation. (See [more](/template)) 

- **wantLogoutRequestSigned: Boolean**<br/> 
  Declare if sp guarantees the logout request from idp is signed.

- **relayState: String**<br/>
  Specify the relayState of the request. 

  !> It will be deprecated soon and put into request level instead g of entity level.
  
- **generateID: (): String**<br/>
  A function to generate the document identifier in root node. Default to `_${UUID_V4}`.

- **clockDrifts: [Number, Number]**<br/>
  A time range allowing for drifting the range that specified in the SAML document. The first one is for the `notBefore` time and the second one is for `notOnOrAfter`. Default value of both drift value is `0`. The unit is in `ms`.

  For example, if you set `[-5000, 3000]`. The value can be either positive or negative in order to take care of the flexibility.

  ```console
  # tolerated timeline
  notBefore - 5s >>>>>>> notBefore >>>>>>> notAfter ---- notAfter + 3s 

  # new valid time
  notBefore - 5s >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> notAfter + 3s 
  ```

  Another example, if you don't set, the default drift tolerance is `[0, 0]`. The valid range is trivial.

  ```console
  # valid time
  notBefore >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> notAfter
  ```

  ?> The flow will skip the validation when there is no `notBefore` and `notOnOrAfter` at the same time.

  ?> See [SAML Core P.19](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf) for more detail.
