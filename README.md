# samlify &middot; [![构建状态](https://img.shields.io/circleci/build/github/tngan/samlify?style=for-the-badge&logo=circleci)](https://app.circleci.com/pipelines/github/tngan/samlify) [![npm 版本](https://img.shields.io/npm/v/samlify.svg?style=for-the-badge&logo=npm)](https://www.npmjs.com/package/samlify) [![下载量](https://img.shields.io/npm/dm/samlify.svg?style=for-the-badge&logo=npm)](https://www.npmjs.com/package/samlify) [![覆盖率](https://img.shields.io/coveralls/tngan/samlify/master.svg?style=for-the-badge&logo=coveralls)](https://coveralls.io/github/tngan/samlify?branch=master)

# samlify &middot; [![Build Status](https://img.shields.io/circleci/build/github/tngan/samlify?style=for-the-badge&logo=circleci)](https://app.circleci.com/pipelines/github/tngan/samlify) [![npm version](https://img.shields.io/npm/v/samlify.svg?style=for-the-badge&logo=npm)](https://www.npmjs.com/package/samlify) [![NPM](https://img.shields.io/npm/dm/samlify.svg?style=for-the-badge&logo=npm)](https://www.npmjs.com/package/samlify) [![Coverage Status](https://img.shields.io/coveralls/tngan/samlify/master.svg?style=for-the-badge&logo=coveralls)](https://coveralls.io/github/tngan/samlify?branch=master)

高度可配置的 Node.js SAML 2.0 单点登录库

Highly configurable Node.js SAML 2.0 library for Single Sign On

---

## 🔄 本仓库为 [samlify](https://github.com/tngan/samlify) 的改进分支

## 🔄 This repository is a fork of [samlify](https://github.com/tngan/samlify) with the following improvements:

### 主要改进 / Key Improvements
- ✅ 将依赖包 `@authenio/xml-encryption` 替换为 `xml-encryption` 并升级版本，支持 SHA-256/512 加密和 OAEP 摘要方法  
  ✅ Replaced `@authenio/xml-encryption` with `xml-encryption` (latest version adds SHA-256/512 and OAEP support)

- 🛠️ 修复加密断言逻辑，支持 `EncryptedAssertion` 字段提取  
  🛠️ Fixed encrypted assertion logic to handle `EncryptedAssertion` field

- 📦 默认配置增加 `AttributeConsumingService` 和属性声明生成  
  📦 Added `AttributeConsumingService` to default elements and attribute value generation

- 🗑️ 移除自定义函数模板，通过 `AttributeStatement` 配置多值属性  
  🗑️ Removed custom templates, added multi-value attribute support via `AttributeStatement`

- 🔒 签名算法升级为 SHA-256+，默认加密算法 AES_256_GCM  
  🔒 Upgraded signature algorithm to SHA-256+, default encryption to AES_256_GCM

- 📦 将 CJS 模块打包转为 ESModule  
  📦 Migrated from CJS to ESModule packaging

- ⚙️ 将 `createLoginResponse` 改为对象传参，新增 `AttributeStatement` 参数  
  ⚙️ Refactored `createLoginResponse` to use object parameters with `AttributeStatement`

- ⬆️ 升级依赖版本，移除 `node-rsa`/`node-forge`，改用原生 `crypto` 模块  
  ⬆️ Upgraded dependencies, replaced `node-rsa`/`node-forge` with native `crypto`

- 🌐 将 `url` 库替换为 `URL` 原生 API  
  🌐 Replaced `url` library with native `URL` API

---

## 欢迎 PR / Welcome PRs
欢迎贡献代码或提供与其他框架集成的用例  
Welcome contributions or integration examples with frameworks

---

## 安装 / Installation
```js
import * as samlify from 'samlify';
import * as validator from '@authenio/samlify-xsd-schema-validator';

// 设置模式验证器 / Set schema validator
samlify.setSchemaValidator(validator);
```
