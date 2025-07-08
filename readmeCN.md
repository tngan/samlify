# samlify · [![构建状态](https://img.shields.io/circleci/build/github/tngan/samlify?style=for-the-badge&logo=circleci)](https://app.circleci.com/pipelines/github/tngan/samlify) [![npm 版本](https://img.shields.io/npm/v/samlify.svg?style=for-the-badge&logo=npm)](https://www.npmjs.com/package/samlify) [![下载量](https://img.shields.io/npm/dm/samlify.svg?style=for-the-badge&logo=npm)](https://www.npmjs.com/package/samlify) [![覆盖率](https://img.shields.io/coveralls/tngan/samlify/master.svg?style=for-the-badge&logo=coveralls)](https://coveralls.io/github/tngan/samlify?branch=master)

---

[English Version](#README.md) | [中文版本](#readmeCN.md)

## 🔄 本仓库为 [samlify](https://github.com/tngan/samlify) 的改进分支版本，原作者[tngan](https://github.com/tngan)

### 主要改进

- 📦 将 CJS 模块打包转为 ESModule
- ✅ 将依赖包 `@authenio/xml-encryption` 替换为 `xml-encryption` 并添加对 sha256/512 加密密钥 OAEP 摘要方法的支持
- ✅ 将依赖包 `@xmldom/xmldom` 升级到最新版
- 🛠️ 修复加密断言验证签名函数，增加 `EncryptedAssertion` 字段提取逻辑
- 📦 ServiceProvider 实例化函数增加默认 `AttributeConsumingService` 元素生成
- 📦 增加部分 Artifact binding 支持
- 🗑️ 移除 Idp 自定义模板支持，改进参数传递方式
- 🔒 默认签名算法升级为 SHA-256，Idp 默认加密算法为 AES_256_GCM
- 🧪 内置 XML XSD 验证器
- 🐛 改进 HTTP-Redirect 绑定未压缩情况的处理
- 🔓 自动检测加密断言，无需显式标志
- 📝 默认 elementsOrder 增加 AttributeConsumingService 适配
- ✅ 通过 Burp SAML Raider 测试（XSW 和 XXE 攻击）
- ⚡ 测试用例迁移到 Vitest

---

## 欢迎 PR

欢迎贡献代码或提供与其他框架集成的用例！

---

## 如何使用？

请参考 `type/flows.test.ts` 测试用例以及原作者文档 [https://samlify.js.org](https://samlify.js.org)。注意此分支版本中部分参数已更改。

---

## 生成密钥

使用 OpenSSL 生成测试用的密钥和证书。私钥可以使用密码保护（可选）。命令如下：

```bash
openssl genrsa -passout pass:foobar -out encryptKey.pem 4096
openssl req -new -x509 -key encryptKey.pem -out encryptionCert.cer -days 3650
