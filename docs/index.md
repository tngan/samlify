---
layout: home

hero:
  name: samlify
  text: Node.js SAML2 API
  tagline: Nodejs library for Single Sign On with SAML 2.0
  image:
    src: /padlock.png
    alt: samlify
  actions:
    - theme: brand
      text: Get Started
      link: /prerequistite
    - theme: alt
      text: View on GitHub
      link: https://github.com/tngan/samlify

features:
  - title: Simple and Active Maintenance
    details: Easy to use API with active community support and regular updates
  - title: Identity and Service Provider
    details: Includes both Identity Provider and Service Provider implementations
  - title: Highly Configurable
    details: Flexible configuration options to fit your specific use case
---

## Installation

To install the stable version

```bash
npm install samlify
```

or

```bash
yarn add samlify
```

## Use cases

- IdP-initiated Single Sign On
- IdP-initiated Single Log-out
- SP-initiated Single Sign On
- SP-initiated Single Log-out (in development)

Simple solution of Identity Provider is provided in this module for test and educational use. Work with other 3rd party Identity Provider is also supported.

## Glimpse of code

::: warning API Changes
**API is changed since v2. All file attributes like metadata and keyFile, it's expected to be normalized as string. It allows easy integration with database storage and import from local file system.**

**The constructor of entity is also modified to accept a single configuration object instead of putting metadata and advanced configurations in separate arguments.**
:::

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

## License

MIT

---

<div style="font-size: 0.9em; color: #666;">
<a href="https://www.flaticon.com/free-icons/password" title="password icons">Password icons created by Pixel perfect - Flaticon</a>
</div>

