# express-saml2

[![Release](https://img.shields.io/github/release/tngan/express-saml2.svg)](https://github.com/tngan/express-saml2/releases/latest)
[![Build Status](https://travis-ci.org/tngan/express-saml2.svg?branch=master)](https://travis-ci.org/tngan/express-saml2)

High-level API for Single Sign On (SAML 2.0)

### Description

This module provides high-level API for scalable Single Sign On (SSO) implementation. Developers can easily configure the Service Providers and Identity Providers by importing the corresponding metadata. SAML2.0 provides a standard guide but leaves a lot of options, so we provide a simple interface that's highly configurable.

### Installation
To install the stable version
```bash
$ npm install express-saml2
```

### Development
This project is now developed using TypeScript 2.0, also support Yarn which is a new package manager.
```bash
npm install typescript -g
yarn install
```

### Integrations
+ [OneLogin](https://www.onelogin.com/)

### Get Started
```javascript
const saml = require('express-saml2');
```
See full documentation [here](https://github.com/tngan/express-saml2/wiki)

### Support algorithms
Signature algorithms
* http://www.w3.org/2000/09/xmldsig#rsa-sha1
* http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
* http://www.w3.org/2001/04/xmldsig-more#rsa-sha512

Data encryption algorithms
* http://www.w3.org/2001/04/xmlenc#tripledes-cbc
* http://www.w3.org/2001/04/xmlenc#aes128-cbc
* http://www.w3.org/2001/04/xmlenc#aes256-cbc

Key encryption algorithms
* http://www.w3.org/2001/04/xmlenc#rsa-1_5
* http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p

### Demo

In the `/examples` folder, there are three entities (1 IdP and 2 SPs). They are at port 3001, 4002 and 4003.

Without using Single Sign On, users have to remember several pairs of username/password in order to log into different internal applications.

<img src="http://fat.gfycat.com/InexperiencedAdorableAntarcticgiantpetrel.gif" alt="normal-login" width="80%">

SAML proposes two ways to initiate Single Sign On, they are respectively Service Provider Initiated SSO and Identity Provider Initiated SSO. In SP-initated SSO, the user attempts to access SP but their federated identity is authenticated by IdP, so they first have to log on IdP, then IdP sends back a SAML assertion response to SP, and finally SP creates a session to user in order to access the resources.

<img src="http://giant.gfycat.com/BlissfulAppropriateDinosaur.gif" alt="spinit-sso" width="80%">

In the approach of IdP-initated SSO, IdP provides links which refers to the resources in service providers. In this use case, users don't need to visit SP first.

<img src="http://fat.gfycat.com/MarvelousKindheartedAlabamamapturtle.gif" alt="idpinit-sso" width="80%">

IdP-initiated Single Logout is also provided and relied on relay state. IdP provides a link refers to the single logout endpoints in one of those participated service providers (SP1). The selected SP sends back a logout response to IdP with relay state which is the logout endpoint URL of next participated service provider (SP2), user finally log out IdP when all participated SP is logged out.

<img src="http://fat.gfycat.com/DarlingGeneralAntlion.gif" alt="idpinit-slo" width="80%">

### Talks

[An introduction to Single Sign On](http://www.slideshare.net/TonyNgan/an-introduction-of-single-sign-on)

### License

[MIT](LICENSE)

### Copyright

Copyright (C) 2015-2016 Tony Ngan, released under the MIT License.
