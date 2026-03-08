import { select, type SelectedValue } from 'xpath';
import { uniq, last, zipObject, notEmpty } from './utility.js';
import { getContext } from './api.js';
import camelCase from 'camelcase';

// 1. 扩展接口定义，支持 listMode (列表模式) 和 shortcut (快捷方式/子文档)
interface ExtractorField {
  key: string;
  localPath?: string[] | string[][]; // 改为可选，因为特殊逻辑可能不需要 path
  attributes?: string[];             // 改为可选
  index?: string[];
  attributePath?: string[];
  context?: boolean;
  listMode?: boolean;
  shortcut?: string;
}

export type ExtractorFields = ExtractorField[];

function buildAbsoluteXPath(paths: string[]) {
  if (!paths || paths.length === 0) return '';
  return paths.reduce((currentPath, name) => {
    let appendedPath = currentPath;
    const isWildcard = name.startsWith('~');
    if (isWildcard) {
      const pathName = name.replace('~', '');
      appendedPath = currentPath + `/*[contains(local-name(), '${pathName}')]`;
    } else {
      appendedPath = currentPath + `/*[local-name(.)='${name}']`;
    }
    return appendedPath;
  }, '');
}

function buildAttributeXPath(attributes: string[]) {
  if (!attributes || attributes.length === 0) {
    return '/text()';
  }
  if (attributes.length === 1) {
    return `/@${attributes[0]}`;
  }
  const filters = attributes.map(attribute => `name()='${attribute}'`).join(' or ');
  return `/@*[${filters}]`;
}

// ... (其他字段配置如 loginRequestFields 等保持不变，为节省篇幅此处省略，请保留你原有的所有 fields 定义) ...
// 为了完整性，这里假设你保留了之前所有的 fields 定义 (loginRequestFields, idpMetadataFields 等)
// 重点修正下方的 spMetadataFields 和 extract 函数

export const loginRequestFields: ExtractorFields = [
  { key: 'request', localPath: ['AuthnRequest'], attributes: ['ID', 'IssueInstant', 'Destination', 'AssertionConsumerServiceURL','ProtocolBinding','ForceAuthn','IsPassive','AssertionConsumerServiceIndex','AttributeConsumingServiceIndex'] },
  { key: 'issuer', localPath: ['AuthnRequest', 'Issuer'], attributes: [] },
  { key: 'nameIDPolicy', localPath: ['AuthnRequest', 'NameIDPolicy'], attributes: ['Format', 'AllowCreate'] },
  { key: 'authnContextClassRef', localPath: ['AuthnRequest', 'AuthnContextClassRef'], attributes: [] },
  { key: 'signature', localPath: ['AuthnRequest', 'Signature'], attributes: [], context: true }
];

export const artifactResolveFields: ExtractorFields = [
  { key: 'request', localPath: ['ArtifactResolve'], attributes: ['ID', 'IssueInstant','Version'] },
  { key: 'issuer', localPath: ['ArtifactResolve', 'Issuer'], attributes: [] },
  { key: 'Artifact', localPath: ['ArtifactResolve','Artifact'], attributes: [] },
  { key: 'signature', localPath: ['ArtifactResolve', 'Signature'], attributes: [], context: true },
];

export const artifactResponseFields: ExtractorFields = [
  { key: 'request', localPath: ['Envelope','Body','ArtifactResolve'], attributes: ['ID', 'IssueInstant','Version'] },
  { key: 'issuer', localPath: ['Envelope','Body','ArtifactResolve', 'Issuer'], attributes: [] },
  { key: 'Artifact', localPath: ['Envelope','Body','ArtifactResolve','Artifact'], attributes: [] },
  { key: 'signature', localPath: ['Envelope','Body','ArtifactResolve', 'Signature'], attributes: [], context: true },
];

export const loginResponseStatusFields: ExtractorFields = [
  { key: 'top', localPath: ['Response', 'Status', 'StatusCode'], attributes: ['Value'] },
  { key: 'second', localPath: ['Response', 'Status', 'StatusCode', 'StatusCode'], attributes: ['Value'] }
];

export const loginArtifactResponseStatusFields: ExtractorFields = [
  { key: 'top', localPath: ['Envelope','Body','ArtifactResponse', 'Status', 'StatusCode'], attributes: ['Value'] },
  { key: 'second', localPath: ['Envelope','Body','ArtifactResponse', 'Status', 'StatusCode', 'StatusCode'], attributes: ['Value'] }
];

export const logoutResponseStatusFields: ExtractorFields = [
  { key: 'top', localPath: ['LogoutResponse', 'Status', 'StatusCode'], attributes: ['Value'] },
  { key: 'second', localPath: ['LogoutResponse', 'Status', 'StatusCode', 'StatusCode'], attributes: ['Value'] }
];

export const loginResponseFields: ((assertion: any) => ExtractorFields) = assertion => [
  { key: 'conditions', localPath: ['Assertion', 'Conditions'], attributes: ['NotBefore', 'NotOnOrAfter'], shortcut: assertion },
  { key: 'response', localPath: ['Response'], attributes: ['ID', 'IssueInstant', 'Destination', 'InResponseTo','Version'] },
  { key: 'audience', localPath: ['Assertion', 'Conditions', 'AudienceRestriction', 'Audience'], attributes: [], shortcut: assertion },
  { key: 'issuer', localPath: ['Assertion', 'Issuer'], attributes: [], shortcut: assertion },
  { key: 'nameID', localPath: ['Assertion', 'Subject', 'NameID'], attributes: [], shortcut: assertion },
  { key: 'sessionIndex', localPath: ['Assertion', 'AuthnStatement'], attributes: ['AuthnInstant', 'SessionNotOnOrAfter', 'SessionIndex'], shortcut: assertion },
  { key: 'attributes', localPath: ['Assertion', 'AttributeStatement', 'Attribute'], index: ['Name'], attributePath: ['AttributeValue'], attributes: [], shortcut: assertion },
  { key: 'subjectConfirmation', localPath: ['Assertion', 'Subject', 'SubjectConfirmation', 'SubjectConfirmationData'], attributes: ['Recipient', 'InResponseTo', 'NotOnOrAfter'], shortcut: assertion },
  { key: 'oneTimeUse', localPath: ['Assertion', 'Conditions', 'OneTimeUse'], attributes: [], shortcut: assertion },
  { key: 'status', localPath: ['Response', 'Status', 'StatusCode'], attributes: ['Value'] },
];

export const logoutRequestFields: ExtractorFields = [
  { key: 'request', localPath: ['LogoutRequest'], attributes: ['ID', 'IssueInstant', 'Destination'] },
  { key: 'issuer', localPath: ['LogoutRequest', 'Issuer'], attributes: [] },
  { key: 'nameID', localPath: ['LogoutRequest', 'NameID'], attributes: [] },
  { key: 'sessionIndex', localPath: ['LogoutRequest', 'SessionIndex'], attributes: [] },
  { key: 'signature', localPath: ['LogoutRequest', 'Signature'], attributes: [], context: true }
];

export const logoutResponseFields: ExtractorFields = [
  { key: 'response', localPath: ['LogoutResponse'], attributes: ['ID', 'Destination', 'InResponseTo'] },
  { key: 'issuer', localPath: ['LogoutResponse', 'Issuer'], attributes: [] },
  { key: 'signature', localPath: ['LogoutResponse', 'Signature'], attributes: [], context: true }
];

// ============================================================================
// 增强版：IdP 元数据提取字段配置
// ============================================================================
export const idpMetadataFields: ExtractorFields = [
  // --- 1. 基础标识 ---
  {
    key: 'entityID',
    localPath: ['EntityDescriptor'],
    attributes: ['entityID']
  },
  {
    // 可选：提取整个 EntityDescriptor 的 validUntil 和 cacheDuration
    key: 'entityDescriptor',
    localPath: ['EntityDescriptor'],
    attributes: ['validUntil', 'cacheDuration']
  },

  // --- 2. IDPSSODescriptor 核心属性 ---
  {
    key: 'idpSSODescriptor',
    localPath: ['EntityDescriptor', 'IDPSSODescriptor'],
    attributes: [
      'protocolSupportEnumeration',
      'WantAuthnRequestsSigned', // IdP 是否希望 SP 对请求签名
      'cacheDuration'
    ]
  },

  // --- 3. 服务端点列表 (Endpoints) ---
  {
    // 单点登录服务 (SSO) - 核心
    key: 'singleSignOnService',
    localPath: ['EntityDescriptor', 'IDPSSODescriptor', 'SingleSignOnService'],
    attributes: ['Binding', 'Location', 'ResponseLocation'], // ResponseLocation 用于某些绑定
    listMode: true
  },
  {
    // 单点注销服务 (SLO)
    key: 'singleLogoutService',
    localPath: ['EntityDescriptor', 'IDPSSODescriptor', 'SingleLogoutService'],
    attributes: ['Binding', 'Location'],
    listMode: true
  },
  {
    // Artifact 解析服务 (如果使用 Artifact 绑定)
    key: 'artifactResolutionService',
    localPath: ['EntityDescriptor', 'IDPSSODescriptor', 'ArtifactResolutionService'],
    attributes: ['Binding', 'Location', 'index', 'isDefault'],
    listMode: true
  },
  {
    // ManageNameID 服务
    key: 'manageNameIDService',
    localPath: ['EntityDescriptor', 'IDPSSODescriptor', 'ManageNameIDService'],
    attributes: ['Binding', 'Location'],
    listMode: true
  },

  // --- 4. 名称 ID 格式 (NameID Formats) ---
  {
    // 提取所有支持的 NameID 格式 (文本内容)
    key: 'nameIDFormat',
    localPath: ['EntityDescriptor', 'IDPSSODescriptor', 'NameIDFormat'],
    attributes: []
    // 注意：如果 extract 函数未完全支持 text() 的 listMode，这里可能只返回第一个。
    // 如果需要数组，需确保 extract 逻辑完善，或者此处暂时只取主要的一个。
  },
  {
    // 获取主要的 NameID Policy 格式 (如果有显式声明)
    key: 'nameIDPolicyFormat',
    localPath: ['EntityDescriptor', 'IDPSSODescriptor', 'NameIDPolicy'],
    attributes: ['Format']
  },

  // --- 5. 组织信息 (Organization) ---
  {
    key: 'organizationName',
    localPath: ['EntityDescriptor', 'Organization', 'OrganizationName'],
    attributes: [] // 取文本内容
  },
  {
    key: 'organizationDisplayName',
    localPath: ['EntityDescriptor', 'Organization', 'OrganizationDisplayName'],
    attributes: []
  },
  {
    key: 'organizationURL',
    localPath: ['EntityDescriptor', 'Organization', 'OrganizationURL'],
    attributes: []
  },

  // --- 6. 联系人信息 (ContactPerson) ---
  {
    key: 'contactPerson',
    localPath: ['EntityDescriptor', 'ContactPerson'],
    attributes: ['contactType'],
    listMode: true
    // 局限：目前只能提取 contactType。如需提取 Email/GivenName，需扩展 extract 逻辑。
  },

  // --- 7. 证书与密钥信息 (Certificates & Keys) ---
  // 这些 key 会触发 extract 函数内部的硬编码逻辑，自动查找对应 @use 的证书

  // 7.1 签名证书 (IdP 用来签名响应/断言)
  {
    key: 'signingCert'
    // localPath 和 attributes 将被内部逻辑忽略
  },

  // 7.2 加密证书 (IdP 用来加密断言中的敏感信息，如果有)
  {
    key: 'encryptCert'
  },

  // 7.3 签名密钥名称 (KeyName)
  {
    key: 'signingKeyName'
  },

  // 7.4 加密密钥名称 (KeyName)
  {
    key: 'encryptionKeyName'
  },

  // --- 8. 其他扩展属性 (可选) ---
  {
    // 提取 AttributeConsumingService (如果 IdP 声明了它需要的属性)
    key: 'attributeConsumingService',
    localPath: ['EntityDescriptor', 'IDPSSODescriptor', 'AttributeConsumingService'],
    attributes: ['index', 'isDefault'],
    listMode: true
  }
];




// ============================================================================
// 修正后的 SP 元数据提取字段配置
// ============================================================================
export const spMetadataFields: ExtractorFields = [
  { key: 'entityID', localPath: ['EntityDescriptor'], attributes: ['entityID'] },
  { key: 'spSSODescriptor', localPath: ['EntityDescriptor', 'SPSSODescriptor'], attributes: ['protocolSupportEnumeration', 'AuthnRequestsSigned', 'WantAssertionsSigned'] },
  { key: 'assertionConsumerService', localPath: ['EntityDescriptor', 'SPSSODescriptor', 'AssertionConsumerService'], attributes: ['Binding', 'Location', 'index','isDefault'], listMode: true },
  { key: 'singleLogoutService', localPath: ['EntityDescriptor', 'SPSSODescriptor', 'SingleLogoutService'], attributes: ['Binding', 'Location'], listMode: true },
  { key: 'artifactResolutionService', localPath: ['EntityDescriptor', 'SPSSODescriptor', 'ArtifactResolutionService'], attributes: ['Binding', 'Location', 'index', 'isDefault'], listMode: true },
  { key: 'manageNameIDService', localPath: ['EntityDescriptor', 'SPSSODescriptor', 'ManageNameIDService'], attributes: ['Binding', 'Location'], listMode: true },
  { key: 'nameIDFormat', localPath: ['EntityDescriptor', 'SPSSODescriptor', 'NameIDFormat'], attributes: [] },
  { key: 'organizationName', localPath: ['EntityDescriptor', 'Organization', 'OrganizationName'], attributes: [] },
  { key: 'organizationDisplayName', localPath: ['EntityDescriptor', 'Organization', 'OrganizationDisplayName'], attributes: [] },
  { key: 'organizationURL', localPath: ['EntityDescriptor', 'Organization', 'OrganizationURL'], attributes: [] },
  { key: 'contactPerson', localPath: ['EntityDescriptor', 'ContactPerson'], attributes: ['contactType'], listMode: true },

  // 特殊字段：触发 extract 内部的硬编码逻辑
  // localPath 和 attributes 在这里不起作用，仅作为占位符
  { key: 'signingCert' },
  { key: 'encryptCert' },
  { key: 'signingKeyName' },
  { key: 'encryptionKeyName' }
];

export function extract(context: string, fields: ExtractorFields) {
  const { dom } = getContext();
  const rootDoc = dom.parseFromString(context, 'application/xml');

  return fields.reduce((result: any, field) => {
    const key = field.key;
    // 安全解构，防止 undefined
    const localPath = field.localPath || [];
    const attributes = field.attributes || [];
    const isEntire = field.context;
    const shortcut = field.shortcut;
    const index = field.index;
    const attributePath = field.attributePath;
    const listMode = field.listMode;

    let targetDoc = rootDoc;
    if (shortcut) {
      targetDoc = dom.parseFromString(shortcut, 'application/xml');
    }

    // ==========================================================================
    // 【核心修复】特殊处理：证书和 KeyName 提取 (Hardcoded logic)
    // 不再硬编码 IDPSSODescriptor 或 SPSSODescriptor，而是全局搜索 @use 属性
    // ==========================================================================
    if (key === 'signingCert' || key === 'encryptCert' || key === 'signingKeyName' || key === 'encryptionKeyName') {
      const isSigning = key.startsWith('signing');
      const useType = isSigning ? 'signing' : 'encryption';
      const isKeyName = key.endsWith('KeyName');

      // 通用 XPath：查找任意层级下符合 @use 条件的 KeyDescriptor
      const kdXPath = `//*[local-name(.)='KeyDescriptor' and @use='${useType}']`;

      let fullXPath = '';
      if (isKeyName) {
        // 提取 KeyName 文本
        fullXPath = `${kdXPath}/*[local-name(.)='KeyInfo']/*[local-name(.)='KeyName']/text()`;
      } else {
        // 提取 X509Certificate 文本
        fullXPath = `${kdXPath}/*[local-name(.)='KeyInfo']/*[local-name(.)='X509Data']/*[local-name(.)='X509Certificate']/text()`;
      }

      try {
        // @ts-ignore
        const nodes = select(fullXPath, targetDoc);

        if (isKeyName) {
          const keyNames = nodes.map((n: any) => n.nodeValue).filter(notEmpty);
          return {
            ...result,
            [key]: keyNames.length > 0 ? keyNames[0] : null
          };
        } else {
          const certs = nodes.map((n: any) => {
            const val = n.nodeValue || n.value;
            return val ? val.replace(/\r\n|\r|\n/g, '') : null;
          }).filter(notEmpty);

          return {
            ...result,
            [key]: certs.length > 0 ? certs[0] : null
          };
        }
      } catch (e) {
        console.error(`Error extracting ${key}:`, e);
        return { ...result, [key]: null };
      }
    }

    // 特殊 case: 多路径 (原有逻辑)
    if (Array.isArray(localPath) && localPath.length > 0 && Array.isArray(localPath[0])) {
      const multiXPaths = (localPath as string[][]).map(path => `${buildAbsoluteXPath(path)}/text()`).join(' | ');
      // @ts-ignore
      const nodes = select(multiXPaths, targetDoc);
      return {
        ...result,
        [key]: uniq(nodes.map((n: any) => n.nodeValue).filter(notEmpty))
      };
    }

    // 此时 localPath 必然是 string[]
    const currentLocalPath = localPath as string[];

    // 如果 localPath 为空数组（如特殊字段未定义 path），且未命中上面的特殊逻辑，则跳过
    if (currentLocalPath.length === 0 && !isEntire) {
      // 对于没有 path 且不是特殊处理的字段，返回 null 或跳过
      return { ...result, [key]: null };
    }

    const baseXPath = buildAbsoluteXPath(currentLocalPath);

    // --- 新增：列表模式处理 (用于 SSO Service, ACS 等) ---
    if (listMode && attributes.length > 0) {
      // @ts-ignore
      const nodes = select(baseXPath, targetDoc);

      const resultList = nodes.map((node: any) => {
        const attrResult: any = {};
        attributes.forEach(attr => {
          if (node.getAttribute) {
            const val = node.getAttribute(attr);
            if (val) {
              attrResult[camelCase(attr, { locale: 'en-us' })] = val;
            }
          }
        });
        return attrResult;
      });
      return {
        ...result,
        [key]: resultList
      };
    }

    const attributeXPath = buildAttributeXPath(attributes);

    // 特殊 case: 属性聚合 (原有逻辑 - Attributes with index)
    if (index && attributePath) {
      const indexPath = buildAttributeXPath(index);
      const fullLocalXPath = `${baseXPath}${indexPath}`;
      // @ts-ignore
      const parentNodes = select(baseXPath, targetDoc);
      // @ts-ignore
      const parentAttributes = select(fullLocalXPath, targetDoc).map((n: any) => n.value);

      const childXPath = buildAbsoluteXPath([last(currentLocalPath)].concat(attributePath));
      const childAttributeXPath = buildAttributeXPath(attributes);
      const fullChildXPath = `${childXPath}${childAttributeXPath}`;

      const childAttributes = parentNodes.map((node: any) => {
        const nodeDoc = dom.parseFromString(node.toString(), 'application/xml');
        if (attributes.length === 0) {
          // @ts-ignore
          const childValues = select(fullChildXPath, nodeDoc).map((n: any) => n.nodeValue);
          return childValues.length === 1 ? childValues[0] : childValues;
        }
        if (attributes.length > 0) {
          // @ts-ignore
          const childValues = select(fullChildXPath, nodeDoc).map((n: any) => n.value);
          return childValues.length === 1 ? childValues[0] : childValues;
        }
        return null;
      });

      const obj = zipObject(parentAttributes, childAttributes, false);
      return { ...result, [key]: obj };
    }

    // 特殊 case: 获取整个节点内容 (原有逻辑)
    if (isEntire) {
      // @ts-ignore
      const node = select(baseXPath, targetDoc);
      let value: string | string[] | null = null;
      if (node.length === 1) {
        value = node[0].toString();
      }
      if (node.length > 1) {
        value = node.map((n: any) => n.toString());
      }
      return { ...result, [key]: value };
    }

    // 特殊 case: 多属性对象 (原有逻辑，非 listMode)
    if (attributes.length > 1 && !listMode) {
      // @ts-ignore
      const baseNode = select(baseXPath, targetDoc).map((n: any) => n.toString());
      const childXPath = `${buildAbsoluteXPath([last(currentLocalPath)])}${attributeXPath}`;
      const attributeValues = baseNode.map((nodeStr: string) => {
        // @ts-ignore
        const nodeDoc = dom.parseFromString(nodeStr, 'application/xml');
        // @ts-ignore
        const values = select(childXPath, nodeDoc).reduce((r: any, n: any) => {
          r[camelCase(n.name, { locale: 'en-us' })] = n.value;
          return r;
        }, {});
        return values;
      });
      return {
        ...result,
        [key]: attributeValues.length === 1 ? attributeValues[0] : attributeValues
      };
    }

    // 特殊 case: 单个属性 (原有逻辑)
    if (attributes.length === 1 && !listMode) {
      const fullPath = `${baseXPath}${attributeXPath}`;
      // @ts-ignore
      const attributeValues = select(fullPath, targetDoc).map((n: any) => n.value);
      return { ...result, [key]: attributeValues[0] };
    }

    // 特殊 case: 无属性/文本内容 (原有逻辑)
    if (attributes.length === 0 && !listMode) {
      let attributeValue: SelectedValue[] | (string | null)[] | null = null;
      // @ts-ignore
      const node = select(baseXPath, targetDoc);
      if (node.length === 1) {
        const fullPath = `string(${baseXPath}${attributeXPath})`;
        // @ts-ignore
        attributeValue = select(fullPath, targetDoc);
      }
      if (node.length > 1) {
        attributeValue = node.filter((n: any) => n.firstChild)
          .map((n: any) => n.firstChild?.nodeValue);
      }
      return { ...result, [key]: attributeValue };
    }

    return result;
  }, {});
}

export function extractIdp(context: string) {
  return extract(context, idpMetadataFields);
}

export function extractSp(context: string) {
  return extract(context, spMetadataFields);
}


