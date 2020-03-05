## samlify

> High-level API library for Single Sign On with SAML 2.0

This module provides a library for scaling Single Sign On implementation. Developers can easily configure the entities by importing the metadata. 

We provide a simple interface that's highly configurable.

### Thanks

<div>Icons made by <a href="http://www.flaticon.com/authors/madebyoliver" title="Madebyoliver">Madebyoliver</a> from <a href="http://www.flaticon.com" title="Flaticon">www.flaticon.com</a> is licensed by <a href="http://creativecommons.org/licenses/by/3.0/" title="Creative Commons BY 3.0" target="_blank">CC 3.0 BY</a></div>


### Installation
To install the stable version

```console
$ npm install samlify
```

or

```console
$ yarn add samlify
```

### Use cases

+ IdP-initiated Single Sign On
+ IdP-initiated Single Log-out
+ SP-initiated Single Sign On
+ SP-initiated Single Log-out (in development)

Simple solution of Identity Provider is provided in this module for test and educational use. Work with other 3rd party Identity Provider is also supported.

### Glimpse of code

!> **API is changed since v2. All file attributes like metadata and keyFile, it's expected to be normalized as string. It allows easy integration with database storage and import from local file system.**

!> **The constructor of entity is also modified to accept a single configuration object instead of putting metadata and advanced configurations in separate arguments.**

```javascript
const saml = require('samlify');
// configure a service provider
const sp = saml.ServiceProvider({
  metadata: fs.readFileSync('./metadata_sp.xml')
});
// configure the corresponding identity provider
const idp = saml.IdentityProvider({
  metadata: fs.readFileSync('./metadata_idp.xml')
});
// parse when receive a SAML Response from IdP
router.post('/acs', (req, res) => {
  sp.parseLoginResponse(idp, 'post', req)
  .then(parseResult => {
    // Write your own validation and render function here
  })
  .catch(console.error);
});
```

Our default validation is to validate signature and the issuer name of Identity Provider. The code base is self explained. More use cases are provided in this documentation to fit in the real world application.

### License

MIT
