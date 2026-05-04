## samlify

> High-level API library for Single Sign-On with SAML 2.0.

This module provides a scalable implementation of Single Sign-On (SSO) with SAML 2.0. Entities are configured by importing a metadata document, and the library exposes a simple, highly configurable interface.

### Installation

Install the stable release via npm:

```console
$ npm install samlify
```

Or via yarn:

```console
$ yarn add samlify
```

### Supported use cases

- IdP-initiated Single Sign-On
- IdP-initiated Single Logout
- SP-initiated Single Sign-On
- SP-initiated Single Logout (in development)

A minimal identity provider implementation is included for testing and educational purposes. Integration with third-party identity providers is also supported.

### Quick start

::: warning Breaking changes since v2
File attributes such as `metadata` and `keyFile` must now be passed as strings (or buffers). This enables integration with database storage, in-memory sources, and the local filesystem through a single interface.

The entity constructor now accepts a single configuration object rather than separate metadata and configuration arguments.
:::

```javascript
const saml = require('samlify');

// Configure a service provider.
const sp = saml.ServiceProvider({
  metadata: fs.readFileSync('./metadata_sp.xml')
});

// Configure the corresponding identity provider.
const idp = saml.IdentityProvider({
  metadata: fs.readFileSync('./metadata_idp.xml')
});

// Parse an inbound SAML Response sent by the IdP.
router.post('/acs', (req, res) => {
  sp.parseLoginResponse(idp, 'post', req)
    .then(parseResult => {
      // Apply your own validation and rendering logic here.
    })
    .catch(console.error);
});
```

By default, the library verifies the XML signature and the issuer name of the identity provider. The code base is self-documenting; additional use cases are covered throughout this documentation.

### Credits

<div>Icons created by <a href="http://www.flaticon.com/authors/madebyoliver" title="Madebyoliver">Madebyoliver</a> from <a href="http://www.flaticon.com" title="Flaticon">www.flaticon.com</a>, licensed under <a href="http://creativecommons.org/licenses/by/3.0/" title="Creative Commons BY 3.0" target="_blank">CC 3.0 BY</a>.</div>

### License

MIT
