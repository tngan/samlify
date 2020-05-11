## Standalone code for running directly with Node.js REPL

```javascript
// playground setup for extractor
var samlify = require('./build/index');
var fs = require('fs');
var idpconfig = {
  privateKey: fs.readFileSync('./test/key/idp/privkey.pem'),
  privateKeyPass: 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW',
  isAssertionEncrypted: false,
  metadata: fs.readFileSync('./test/misc/idpmeta_rollingcert.xml')
};
var idp = samlify.IdentityProvider(idpconfig);

samlify.Extractor.extract(idp.entityMeta.xmlString, [
  {
    key: 'certificate',
    localPath: ['EntityDescriptor', '~SSODescriptor', 'KeyDescriptor'],
    index: ['use'],
    attributePath: ['KeyInfo', 'X509Data', 'X509Certificate'],
    attributes: []
  }
]) 

// construct response signature
const {
  IdPMetadata: idpMetadata,
  Utility: utility,
  SamlLib: libsaml,
} = require('./');
const fs = require('fs');
const metadata = idpMetadata(fs.readFileSync('./test/misc/idpmeta_rollingcert.xml'));
const _idpKeyFolder = './test/key/idp/';
const _idpPrivPem1 = String(fs.readFileSync(_idpKeyFolder + 'privkey.pem'));
const _idpPrivPem2 = String(fs.readFileSync(_idpKeyFolder + 'privkey2.pem'));
function writer(str) {
  fs.writeFileSync('nogit.xml', str);
}
writer(utility.base64Decode(libsaml.constructSAMLSignature({
  rawSamlMessage: String(fs.readFileSync('./test/misc/response.xml')),
  referenceTagXPath: libsaml.createXPath('Issuer'),
  signingCert: metadata.getX509Certificate('signing')[0],
  privateKey: _idpPrivPem1,
  privateKeyPass: 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW',
  signatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
  signatureConfig: {
    prefix: 'ds',
    location: { reference: "/*[local-name(.)='Response']/*[local-name(.)='Issuer']", action: 'after' },
  },
})));
```