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
宁应该在使用的前提下首先设置验证其
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

## 当您作为IDP的伪代码使用示例

```js
/** 本代码正对不同的绑定做出的方式伪代码*/
if (request.method === 'GET') {
	data = request.query
	bind = 'redirect'
	infoQuery.query = request.query
	let compressedResult = validateAndInflateSamlResponse(data.SAMLResponse)
	console.log(compressedResult);
	console.log("压缩结果---------------------")
	infoQuery.octetString = buildOctetStringFromQuery(request.query)
	dataResult = Extractor.extract(compressedResult.xml, loginResponseFields);
}
if (request.method === 'POST') {
	data = request.body
	bind = 'post'
	infoQuery.body = request.body
	dataResult = Extractor.extract(Base64.decode(decodeURIComponent(data.SAMLResponse)), loginResponseFields)
}
/** 宁应该自行实施根据响应提取出来的Issur去数据库查找元数据*/
// 1. 提取SAML发行者信息
if (!dataResult.issuer) {
	return reply.view('errorHtml.html', {
		errorMessage: `无效的发行者`, errorCode: StatusCode?.Responder, requestId: ""
	})
}

let result = await samlCollection.findOne({issuer:dataResult.issuer});
const idp = new Saml.IdentityProvider({
	metadata: result.metadata,
});

/** 检查断言*/
let extract = null
/** 先看数据库有没有*/
let bindType = 'post' //redirect post ......您应该自定判断 
let parseResult = await sp.parseLoginResponse(idp, bindType, infoQuery)

/**如果解析成功 你应该去验证元素结果中的 attribute 和 Audience issur是否是你期待的  inResponseTo检查  是否有必须的属性没有 都需要您进行严密的的考察 */

if(upaboveFieldCheckAllSuccess){
	return repla.view('success.ejs',{...your template data})
}
/*success.ejs template example */
/**/
<!-- 隐藏的 SAML 表单 -->
/*
<form id="saml-form" method="post" action="<%= entityEndpoint %>" style="display: none;">
	<input type="hidden" name="<%= type %>" value="<%= context %>" />
	<input type="hidden" name="RelayState" value="<%= relayState %>" />
</form>

<script>
	// 延迟 1.5 秒提交以展示加载效果

	document.getElementById('saml-form').submit();

	// 兼容性处理：若 5 秒后仍未跳转显示提示
	setTimeout(() => {
	document.querySelector('.loading-subtext').textContent =
		'跳转时间较长，请检查网络或联系系统管理员';
}, 1500);
</script>*/

```
