# samlify &middot; [![构建状态](https://img.shields.io/circleci/build/github/tngan/samlify?style=for-the-badge&logo=circleci)](https://app.circleci.com/pipelines/github/tngan/samlify) [![npm 版本](https://img.shields.io/npm/v/samlify.svg?style=for-the-badge&logo=npm)](https://www.npmjs.com/package/samlify) [![下载量](https://img.shields.io/npm/dm/samlify.svg?style=for-the-badge&logo=npm)](https://www.npmjs.com/package/samlify) [![覆盖率](https://img.shields.io/coveralls/tngan/samlify/master.svg?style=for-the-badge&logo=coveralls)](https://coveralls.io/github/tngan/samlify?branch=master)

高度可配置的 Node.js SAML 2.0 单点登录库
Highly configurable Node.js SAML 2.0 library for Single Sign On

---

## 🔄 本仓库为 [samlify](https://github.com/tngan/samlify) 的改进分支版本，原作者[tngan](https://github.com/tngan)

### 主要改进 / Key Improvements

- 📦 将 CJS模块打包转为 ESModule

- ✅ 将依赖包 `@authenio/xml-encryption` 替换为 `xml-encryption` 并升级版本对 sha256/512 加密密钥 OAEP 摘要方法的支持

- 🛠️ 修复加密断言验证签名函数 verifySignature 提取`Assertion` 字段的错误，增加对加密断言  `EncryptedAssertion` 字段提取逻辑

- 📦 ServiceProvider实例化函数 attributeConsumingService字段参函数， 生成默认的 `AttributeConsumingService` 元素和属性值

- 🗑️ 移除作为Idp使用 IdentityProvider 函数自定义函数模板loginResponseTemplate字段的支持，并改进了自定义函数替换。
  改进createLoginResponse函数签名改为对象的传参方式

- 🔒 默认签名算法升级为 SHA-256，Idp默认加密算法为 AES_256_GCM

- ⬆️ 升级所有能够升级的依赖版本，移除 `node-rsa`/`node-forge` 模块儿,改用原生nodejs `crypto` 模块实现。

- 🌐 将 `url` 库替换为 `URL` 原生 API
- 改进了如果响应为的绑定`urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect`,某些情况下未能DEFLATE压缩导致不能提取xml的异常情况的处理
- 现在如果遇到加密响应无需显示传递 `isAssertionEncrypted` 字段,也无需传递 `MessageSignatureOrder`
  字段。因为我认为是否加密应该是可以自动判断的，MessageSignatureOrder我修改了判断逻辑并在Keycloak 验证可以通过。使用前你应该自行验证这其中的风险
- 默认 elementsOrder 增加了 AttributeConsumingService 适配
- 我已经使用 Burp SAML Raider测试了 八种XSW都能良好的应对，以及XXE。你应该自行验证

---

## 欢迎 PR / Welcome PRs

欢迎贡献代码或提供与其他框架集成的用例  
Welcome contributions or integration examples with frameworks

---

## 安装 / Installation
您应该在使用的前提下首先设置验证其
```js

import * as validator from '@authenio/samlify-xsd-schema-validator';
import * as Saml from "samlesa";
import {Extractor,} from "samlesa";
import validator from '@authenio/samlify-node-xmllint'
// 设置模式验证器 / Set schema validator
Saml.setSchemaValidator(validator);


```

## 生成密钥

我们使用 openssl 生成密钥和证书用于测试。私钥可以使用密码保护，这是可选的。以下是生成私钥和自签名证书的命令。

> openssl genrsa -passout pass:foobar -out encryptKey.pem 4096
> openssl req -new -x509 -key encryptKey.pem -out encryptionCert.cer -days 3650

#
