# samlify · [![构建状态](https://img.shields.io/circleci/build/github/tngan/samlify?style=for-the-badge&logo=circleci)](https://app.circleci.com/pipelines/github/tngan/samlify) [![npm 版本](https://img.shields.io/npm/v/samlify.svg?style=for-the-badge&logo=npm)](https://www.npmjs.com/package/samlify) [![下载量](https://img.shields.io/npm/dm/samlify.svg?style=for-the-badge&logo=npm)](https://www.npmjs.com/package/samlify) [![覆盖率](https://img.shields.io/coveralls/tngan/samlify/master.svg?style=for-the-badge&logo=coveralls)](https://coveralls.io/github/tngan/samlify?branch=master)

---
[English Version](#README.md) | [中文版本](#readmeCN.md)
## 🔄 This repository is an improved fork of [samlify](https://github.com/tngan/samlify) by [tngan](https://github.com/tngan)

### Key Improvements

- 📦 Converted from CJS to ESModule
- ✅ Replaced `@authenio/xml-encryption` with `xml-encryption` and added support for sha256/512 encryption key OAEP digest methods
- ✅ Upgraded `@xmldom/xmldom` to the latest version
- 🛠️ Fixed encrypted assertion signature verification by adding `EncryptedAssertion` field extraction logic
- 📦 Added default `AttributeConsumingService` element generation for ServiceProvider
- 📦 Added partial Artifact binding support
- 🗑️ Removed custom template support for IdentityProvider and improved parameter passing
- 🔒 Upgraded default signature algorithm to SHA-256 and default encryption to AES_256_GCM
- 🧪 Added built-in XML XSD validator
- 🐛 Improved handling of HTTP-Redirect binding without DEFLATE compression
- 🔓 Automatic detection of encrypted assertions without explicit flags
- 📝 Added AttributeConsumingService to default elementsOrder
- ✅ Tested against Burp SAML Raider (XSW and XXE attacks)
- ⚡ Migrated tests to Vitest

---

## Welcome PRs

Contributions are welcome! Please feel free to submit pull requests or provide integration examples with other frameworks.

---

## How to use?

Refer to the `type/flows.test.ts` test cases and the original documentation at [https://samlify.js.org](https://samlify.js.org). Note that some parameters have been changed in this fork.

---

## Generating Keys

Use OpenSSL to generate keys and certificates for testing. Private keys can be password-protected (optional). Here are the commands:

```bash
openssl genrsa -passout pass:foobar -out encryptKey.pem 4096
openssl req -new -x509 -key encryptKey.pem -out encryptionCert.cer -days 3650
