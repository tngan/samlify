# samlify

[![Build Status](https://img.shields.io/circleci/build/github/tngan/samlify?style=for-the-badge&logo=circleci)](https://app.circleci.com/pipelines/github/tngan/samlify)
[![npm version](https://img.shields.io/npm/v/samlify.svg?style=for-the-badge&logo=npm)](https://www.npmjs.com/package/samlify)
[![NPM](https://img.shields.io/npm/dm/samlify.svg?style=for-the-badge&logo=npm)](https://www.npmjs.com/package/samlify)
[![Coverage](https://img.shields.io/badge/coverage-%E2%89%A590%25-brightgreen?style=for-the-badge&logo=vitest)](./vitest.config.ts)

Node.js library for SAML SSO

### Installation

```console
npm install samlify
```

### Schema validation

samlify validates every incoming SAML message against the XML schema, so register a schema validator before anything else. Pick one of the validator modules:

```js
import * as samlify from 'samlify';
import * as validator from '@authenio/samlify-xsd-schema-validator'; // requires Java
// import * as validator from '@authenio/samlify-validate-with-xmllint'; // requires xmllint
// import * as validator from '@authenio/samlify-node-xmllint';

samlify.setSchemaValidator(validator);
```

You can also supply your own validator. Skipping validation means accepting messages that may be malicious, so only do this if you understand the risk:

```typescript
samlify.setSchemaValidator({
  validate: (response: string) => {
    /* implement your own, or always resolve to skip validation */
    return Promise.resolve('skipped');
  }
});
```

### Get Started

```javascript
const saml = require('samlify');
```

See the full documentation [here](https://samlify.js.org/).

### Example

[samlify-starter](https://github.com/tngan/samlify-starter) — starter example for getting up and running with samlify

### Development

```console
yarn
yarn test
```

PRs are welcome, as are links to examples that use samlify with other frameworks. See [CONTRIBUTING.md](CONTRIBUTING.md).

### Talks

[An introduction to Single Sign On](https://www.slideshare.net/TonyNgan/an-introduction-of-single-sign-on)

### License

[MIT](LICENSE)

### Copyright

Copyright (C) 2016-present Tony Ngan, released under the MIT License.
