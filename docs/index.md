---
layout: home

hero:
  name: samlify
  text: Node.js SAML 2.0 API
  tagline: Node.js library for Single Sign-On with SAML 2.0
  image:
    src: /padlock.png
    alt: samlify
  actions:
    - theme: brand
      text: Get Started
      link: /prerequisite
    - theme: alt
      text: View on GitHub
      link: https://github.com/tngan/samlify

features:
  - title: Actively maintained
    details: A simple, well-documented API backed by an active community and regular releases.
  - title: IdP and SP in one package
    details: Ships with both Identity Provider and Service Provider implementations.
  - title: Highly configurable
    details: Flexible configuration options to fit a wide range of deployment scenarios.
---

## Installation

Install the stable release via npm:

```bash
npm install samlify
```

Or via yarn:

```bash
yarn add samlify
```

## Supported use cases

- IdP-initiated Single Sign-On
- IdP-initiated Single Logout
- SP-initiated Single Sign-On
- SP-initiated Single Logout (in development)

A minimal identity provider implementation is included for testing and educational purposes. Integration with third-party identity providers is also supported.

## Quick start

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

## License

MIT

---

<div style="font-size: 0.9em; color: #666;">
<a href="https://www.flaticon.com/free-icons/password" title="password icons">Password icons created by Pixel perfect — Flaticon</a>
</div>
