# Configuration

Without importing a defined metadata, we also provide an advanced way to configure the entities. The metadata can also be created according to the parameters later on.

## Identity Provider

Currently, we suggest developers to use other 3rd party IdP even though we provide the basic API for identity provider.

## Service Provider

```javascript
/**
*
* Required parameters: 
*
* @param {array} assertionConsumerService
* @param {string} entityID
*
* Optional parameters:
*
* @param {boolean} allowCreate : Default is false
* @param {boolean} authnRequestsSigned : Default is false
* @param {string} dataEncryptionAlgorithm : Default is `http://www.w3.org/2001/04/xmlenc#aes256-cbc`
* @param {string} encryptCertFile : It is required if `isAssertionEncrypted` is set to `true`
* @param {function} generateID : It is used to generate the id of each request to perform extra validation and avoid conflict
* @param {boolean} isAssertionEncrypted : Default is false
* @param {string} keyEncryptionAlgorithm : Default is `http://www.w3.org/2001/04/xmlenc#rsa-1_5`
* @param {array} nameIDFormat : Default is an empty array
* @param {string} requestSignatureAlgorithm : Default is `http://www.w3.org/2000/09/xmldsig#rsa-sha1` 
* @param {string} signingCertFile : It is required if `authnRequestsSigned` is set to `true`
* @param {array} singleLogoutService : Default is an empty array
* @param {boolean} wantAssertionsSigned : Default is false
* @param {boolean} wantMessageSigned : Default is false
* @param {object} messageSignatureConfig: Contains information of prefix and location (xml-crypto)
* @param {boolean} wantLogoutResponseSigned : Default is false
* @param {boolean} wantLogoutRequestSigned : Default is false
* @param {string} metadata : Entity metadata
*
**/

const sp = new ServiceProvider({
  // see the following parameters 
});
```

### {array} assertionConsumerService

It is defined as an array, each element is with the following parameters.

```javascript
/**
* @param {string} Binding : SAML 2.0 Bindings
* @param {string} Location : Endpoint of assertion consumer service
**/

// Example
{
  // ...
  assertionConsumerService: [{
    Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
    Location: 'http://localhost:4002/sso/acs'
  }]
  // ...
}
```

### {string} entityID

Specifies the unique identifier of the entity whose metadata is described by the contents of element. See [P.11](https://www.oasis-open.org/committees/download.php/35391/sstc-saml-metadata-errata-2.0-wd-04-diff.pdf)

### {array} singleLogoutService

The configuration is same as `assertionConsumerService`.

```javascript
/**
* @param {string} Binding : SAML 2.0 Bindings
* @param {string} Location : Endpoint of single logout service
**/
```

## References

+ [Metadata for the OASIS Security Assertion Markup Language](https://www.oasis-open.org/committees/download.php/35391/sstc-saml-metadata-errata-2.0-wd-04-diff.pdf)
+ [SAML specification](http://saml.xml.org/saml-specifications)
