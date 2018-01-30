# samlify &middot; [![Build Status](https://travis-ci.org/tngan/samlify.svg?branch=master)](https://travis-ci.org/tngan/samlify) [![npm version](https://img.shields.io/npm/v/samlify.svg?style=flat)](https://www.npmjs.com/package/samlify) [![Coverage Status](https://img.shields.io/coveralls/tngan/samlify/master.svg)](https://coveralls.io/github/tngan/samlify?branch=master)

Node.js API for Single Sign On (SAML 2.0)

### Welcome PRs

Welcome all PRs for maintaining this project, or provide a link to the repositories especially for use cases alongside with different frameworks.

### Description

This module provides high-level API for scalable Single Sign On (SSO) implementation. Developers can easily configure the Service Providers and Identity Providers by importing the corresponding metadata. SAML2.0 provides a standard guide but leaves a lot of options, so we provide a simple interface that's highly configurable.

### Installation
To install the stable version

For those using Windows, `windows-build-tools` should be installed globally before installing samlify.
```bash
yarn global add windows-build-tools
```

```bash
$ yarn add samlify
```

### Development
This project is now developed using TypeScript, also support Yarn which is a new package manager.

```bash
$ yarn global add typescript
$ yarn
```

### Get Started
```javascript
const saml = require('samlify');
```
See full documentation [here](https://samlify.js.org/)

### Examples (In progress)

[samlify-sp](https://github.com/passify/samlify-sp) Service provider example written with Next.js

[samlify-idp](https://github.com/passify/samlify-idp) Identity provider example written with Next.js

### Sponsor

| <img width="50" src="https://user-images.githubusercontent.com/83319/31722733-de95bbde-b3ea-11e7-96bf-4f4e8f915588.png"> | <div style="text-align: left;">If you want to quickly implement SAML SSO, feel free to check out Auth0's NodeJS SDK and free plan at [auth0.com/overview](https://auth0.com/overview?utm_source=GHsponsor&utm_medium=GHsponsor&utm_campaign=samlify&utm_content=auth).</div> |
|:-------------------------:|:-------------------------:|

### Talks

[An introduction to Single Sign On](http://www.slideshare.net/TonyNgan/an-introduction-of-single-sign-on)

### License

[MIT](LICENSE)

### Copyright

Copyright (C) 2016-present Tony Ngan, released under the MIT License.
