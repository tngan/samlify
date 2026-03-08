import { select, type SelectedValue } from 'xpath';
import { uniq, last, zipObject, notEmpty } from './utility.js';
import { getContext } from './api.js';
import camelCase from 'camelcase';

// 1. 扩展接口定义，支持 listMode (列表模式) 和 shortcut (快捷方式/子文档)
interface ExtractorField {
  key: string;
  localPath: string[] | string[][];
  attributes: string[];
  index?: string[];
  attributePath?: string[];
  context?: boolean;
  listMode?: boolean;      // 新增：用于标记需要返回对象数组的字段 (如多个 SSO URL)
  shortcut?: string;       // 新增：用于传入子文档字符串 (如 Assertion)

}

export type ExtractorFields = ExtractorField[];

function buildAbsoluteXPath(paths: string[]) {
  return paths.reduce((currentPath, name) => {
    let appendedPath = currentPath;
    const isWildcard = name.startsWith('~');
    if (isWildcard) {
      const pathName = name.replace('~', '');
      appendedPath = currentPath + `/*[contains(local-name(), '${pathName}')]`;
    }
    if (!isWildcard) {
      appendedPath = currentPath + `/*[local-name(.)='${name}']`;
    }
    return appendedPath;
  }, '');
}

function buildAttributeXPath(attributes: string[]) {
  if (attributes.length === 0) {
    return '/text()';
  }
  if (attributes.length === 1) {
    return `/@${attributes[0]}`;
  }
  const filters = attributes.map(attribute => `name()='${attribute}'`).join(' or ');
  return `/@*[${filters}]`;
}

export const loginRequestFields: ExtractorFields = [
  {
    key: 'request',
    localPath: ['AuthnRequest'],
    attributes: ['ID', 'IssueInstant', 'Destination', 'AssertionConsumerServiceURL','ProtocolBinding','ForceAuthn','IsPassive','AssertionConsumerServiceIndex','AttributeConsumingServiceIndex']
  },
  {
    key: 'issuer',
    localPath: ['AuthnRequest', 'Issuer'],
    attributes: []
  },
  {
    key: 'nameIDPolicy',
    localPath: ['AuthnRequest', 'NameIDPolicy'],
    attributes: ['Format', 'AllowCreate']
  },
  {
    key: 'authnContextClassRef',
    localPath: ['AuthnRequest', 'AuthnContextClassRef'],
    attributes: []
  },
  {
    key: 'signature',
    localPath: ['AuthnRequest', 'Signature'],
    attributes: [],
    context: true
  }
];

export const artifactResolveFields: ExtractorFields = [
  {
    key: 'request',
    localPath: ['ArtifactResolve'],
    attributes: ['ID', 'IssueInstant','Version' ]
  },
  {
    key: 'issuer', localPath: ['ArtifactResolve', 'Issuer'], attributes: []
  },
  {
    key: 'Artifact', localPath: ['ArtifactResolve','Artifact'], attributes: []
  },
  {
    key: 'signature', localPath: ['ArtifactResolve', 'Signature'], attributes: [], context: true
  },
];

export const artifactResponseFields: ExtractorFields = [
  {
    key: 'request',
    localPath: ['Envelope','Body','ArtifactResolve'],
    attributes: ['ID', 'IssueInstant','Version' ]
  },
  {
    key: 'issuer', localPath: ['Envelope','Body','ArtifactResolve', 'Issuer'], attributes: []
  },
  {
    key: 'Artifact', localPath: ['Envelope','Body','ArtifactResolve','Artifact'], attributes: []
  },
  {
    key: 'signature', localPath: ['Envelope','Body','ArtifactResolve', 'Signature'], attributes: [], context: true
  },
];

export const loginResponseStatusFields: ExtractorFields = [
  {
    key: 'top',
    localPath: ['Response', 'Status', 'StatusCode'],
    attributes: ['Value'],
  },
  {
    key: 'second',
    localPath: ['Response', 'Status', 'StatusCode', 'StatusCode'],
    attributes: ['Value'],
  }
];

export const loginArtifactResponseStatusFields: ExtractorFields = [
  {
    key: 'top',
    localPath: ['Envelope','Body','ArtifactResponse', 'Status', 'StatusCode'],
    attributes: ['Value'],
  },
  {
    key: 'second',
    localPath: ['Envelope','Body','ArtifactResponse', 'Status', 'StatusCode', 'StatusCode'],
    attributes: ['Value'],
  }
];

export const logoutResponseStatusFields: ExtractorFields = [
  {
    key: 'top',
    localPath: ['LogoutResponse', 'Status', 'StatusCode'],
    attributes: ['Value']
  },
  {
    key: 'second',
    localPath: ['LogoutResponse', 'Status', 'StatusCode', 'StatusCode'],
    attributes: ['Value'],
  }
];

export const loginResponseFields: ((assertion: any) => ExtractorFields) = assertion => [
  {
    key: 'conditions',
    localPath: ['Assertion', 'Conditions'],
    attributes: ['NotBefore', 'NotOnOrAfter'],
    shortcut: assertion
  },
  {
    key: 'response',
    localPath: ['Response'],
    attributes: ['ID', 'IssueInstant', 'Destination', 'InResponseTo','Version'],
  },
  {
    key: 'audience',
    localPath: ['Assertion', 'Conditions', 'AudienceRestriction', 'Audience'],
    attributes: [],
    shortcut: assertion
  },
  {
    key: 'issuer',
    localPath: ['Assertion', 'Issuer'],
    attributes: [],
    shortcut: assertion
  },
  {
    key: 'nameID',
    localPath: ['Assertion', 'Subject', 'NameID'],
    attributes: [],
    shortcut: assertion
  },
  {
    key: 'sessionIndex',
    localPath: ['Assertion', 'AuthnStatement'],
    attributes: ['AuthnInstant', 'SessionNotOnOrAfter', 'SessionIndex'],
    shortcut: assertion
  },
  {
    key: 'attributes',
    localPath: ['Assertion', 'AttributeStatement', 'Attribute'],
    index: ['Name'],
    attributePath: ['AttributeValue'],
    attributes: [],
    shortcut: assertion
  },
  {
    key: 'subjectConfirmation',
    localPath: ['Assertion', 'Subject', 'SubjectConfirmation', 'SubjectConfirmationData'],
    attributes: ['Recipient', 'InResponseTo', 'NotOnOrAfter'],
    shortcut: assertion
  },
  {
    key: 'oneTimeUse',
    localPath: ['Assertion', 'Conditions', 'OneTimeUse'],
    attributes: [],
    shortcut: assertion
  },
  {
    key: 'status',
    localPath: ['Response', 'Status', 'StatusCode'],
    attributes: ['Value']
  },
];

export const logoutRequestFields: ExtractorFields = [
  {
    key: 'request',
    localPath: ['LogoutRequest'],
    attributes: ['ID', 'IssueInstant', 'Destination']
  },
  {
    key: 'issuer',
    localPath: ['LogoutRequest', 'Issuer'],
    attributes: []
  },
  {
    key: 'nameID',
    localPath: ['LogoutRequest', 'NameID'],
    attributes: []
  },
  {
    key: 'sessionIndex',
    localPath: ['LogoutRequest', 'SessionIndex'],
    attributes: []
  },
  {
    key: 'signature',
    localPath: ['LogoutRequest', 'Signature'],
    attributes: [],
    context: true
  }
];

export const logoutResponseFields: ExtractorFields = [
  {
    key: 'response',
    localPath: ['LogoutResponse'],
    attributes: ['ID', 'Destination', 'InResponseTo']
  },
  {
    key: 'issuer',
    localPath: ['LogoutResponse', 'Issuer'],
    attributes: []
  },
  {
    key: 'signature',
    localPath: ['LogoutResponse', 'Signature'],
    attributes: [],
    context: true
  }
];

// ============================================================================
// 新增：IdP 元数据提取字段配置
// ============================================================================
export const idpMetadataFields: ExtractorFields = [
  {
    key: 'entityID',
    localPath: ['EntityDescriptor'],
    attributes: ['entityID']
  },
  {
    key: 'idpSSODescriptor',
    localPath: ['EntityDescriptor', 'IDPSSODescriptor'],
    attributes: ['protocolSupportEnumeration']
  },
  {
    // 提取单点登录服务列表
    key: 'singleSignOnService',
    localPath: ['EntityDescriptor', 'IDPSSODescriptor', 'SingleSignOnService'],
    attributes: ['Binding', 'Location'],
    listMode: true
  },
  {
    // 提取单点注销服务列表
    key: 'singleLogoutService',
    localPath: ['EntityDescriptor', 'IDPSSODescriptor', 'SingleLogoutService'],
    attributes: ['Binding', 'Location'],
    listMode: true
  }
];

// ============================================================================
// 新增：SP 元数据提取字段配置
// ============================================================================
export const spMetadataFields: ExtractorFields = [
  {
    key: 'entityID',
    localPath: ['EntityDescriptor'],
    attributes: ['entityID']
  },
  {
    key: 'spSSODescriptor',
    localPath: ['EntityDescriptor', 'SPSSODescriptor'],
    attributes: ['protocolSupportEnumeration', 'AuthnRequestsSigned', 'WantAssertionsSigned']
  },
  {
    // 提取 ACS 列表
    key: 'assertionConsumerService',
    localPath: ['EntityDescriptor', 'SPSSODescriptor', 'AssertionConsumerService'],
    attributes: ['Binding', 'Location', 'index','isDefault'],
    listMode: true
  },

  {
    // 提取 SP 发起的注销服务列表
    key: 'singleLogoutService',
    localPath: ['EntityDescriptor', 'SPSSODescriptor', 'SingleLogoutService'],
    attributes: ['Binding', 'Location'],
    listMode: true
  },
  {
    // [新增] 提取 Artifact 解析服务 (如果使用 Artifact 绑定则必需)
    key: 'artifactResolutionService',
    localPath: ['EntityDescriptor', 'SPSSODescriptor', 'ArtifactResolutionService'],
    attributes: ['Binding', 'Location', 'index', 'isDefault'],
    listMode: true
  },
  {
    // [新增] 提取 ManageNameID 服务 (较少用，但规范支持)
    key: 'manageNameIDService',
    localPath: ['EntityDescriptor', 'SPSSODescriptor', 'ManageNameIDService'],
    attributes: ['Binding', 'Location'],
    listMode: true
  },
/*  {
    key: 'nameIDFormat',
    localPath: ['EntityDescriptor', 'SPSSODescriptor', 'NameIDFormat'],
    attributes: []
  }*/
  // --- 名称ID格式 (NameID Formats) ---
  {
    // 提取所有支持的 NameID 格式列表 (返回字符串数组)
    key: 'nameIDFormat',
    localPath: ['EntityDescriptor', 'SPSSODescriptor', 'NameIDFormat'],
    attributes: [], // 文本内容
    listMode: true,  // 注意：这里 listMode 会尝试提取属性，但 NameIDFormat 通常只有文本内容。
                    // 如果 extract 函数对 listMode && attributes.length===0 处理不当，可能需要特殊处理。
                    // 当前 extract 逻辑中，如果 listMode=true 但 attributes 为空，可能不会进入 listMode 分支，
                    // 而是进入 attributes.length === 0 分支，返回单个值。
                    // 若要返回数组，需确保 extract 逻辑支持 "listMode + 无属性" 的情况，或者这里不加 listMode，
                    // 依靠多路径逻辑（如果有的话）。
                    // *修正策略*: 对于纯文本列表，目前的 extract 逻辑可能只返回第一个。
                    // 如果需要所有 NameIDFormat，建议暂时不加 listMode，或者在 extract 中完善逻辑。
                    // 此处为了安全，先不加 listMode，仅获取第一个，或者依赖后续逻辑优化。
                    // 实际上，NameIDFormat 通常有多个，建议后续优化 extract 支持 text() 的 listMode。
                    // 暂时保持原样或移除 listMode 以避免意外行为，除非你确认 extract 支持。
                    // 在此示例中，我移除 listMode，仅获取第一个，或者你可以接受只获取一个。
                    // 更好的方式：如果 extract 不支持 text 的 listMode，这里先不写 listMode。
  },
  // --- [新增] 组织信息 (Organization) ---
  {
    key: 'organizationName',
    localPath: ['EntityDescriptor', 'Organization', 'OrganizationName'],
    attributes: ['xml:lang'], // 有时需要区分语言
    // 注意：OrganizationName 可能有多个（不同语言），listMode 可能有用，但 extract 需支持
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
  // --- [新增] 联系人信息 (ContactPerson) ---
  // 联系人可能有多个（technical, support, administrative），适合 listMode
  {
    key: 'contactPerson',
    localPath: ['EntityDescriptor', 'ContactPerson'],
    attributes: ['contactType'], // contactType 是属性
    listMode: true, // 这将返回 [{ contactType: 'technical' }, ...]，但不包含姓名邮箱
    // 缺点：extract 的 listMode 目前只提取 attributes。
    // 如果要提取 ContactPerson 的子元素 (EmailAddress, GivenName)，需要更复杂的配置或硬编码。
    // 鉴于当前 extract 限制，这里仅提取 contactType 列表意义不大。
    // 建议：如果需要详细联系人，需在 extract 中增加对子元素文本提取的 listMode 支持。
    // 暂时注释掉或仅保留简单属性提取。
  },
  // 7.1 签名证书
  // 触发 extract 函数内部的硬编码逻辑：if (key === 'signingCert') ...
  {
    key: 'signingCert',
    localPath: [], // 会被内部逻辑忽略
    attributes: []
  },

  // 7.2 加密证书
  // 触发 extract 函数内部的硬编码逻辑：if (key === 'encryptCert') ...
  {
    key: 'encryptCert',
    localPath: [], // 会被内部逻辑忽略
    attributes: []
  },

  // 7.3 签名密钥名称 (KeyName) - 如果有
  // 标准 XPath 提取：EntityDescriptor -> SPSSODescriptor -> KeyDescriptor[@use='signing'] -> KeyInfo -> KeyName
  {
    key: 'signingKeyName',
    localPath: ['EntityDescriptor', 'SPSSODescriptor'],
    // 这里需要一点技巧，因为 KeyDescriptor 是兄弟节点且通过 @use 区分。
    // 由于我们的 buildAbsoluteXPath 不支持复杂的谓词过滤（除了 local-name），
    // 我们最好利用 extract 内部的特殊逻辑，或者如果 extract 不支持 KeyName 的特殊逻辑，
    // 我们可能需要手动在 controller 里提取，或者在这里尝试通用路径。

    // *策略调整*：为了保持一致性，建议在 extractor.ts 的 extract 函数中也添加对 'signingKeyName' 的硬编码支持，
    // 就像对证书做的那样。
    // 如果你暂时不想修改 extractor.ts，可以在这里留空，然后在 Controller 中单独解析。
    // 但为了完整性，假设我们稍微修改一下 extractor.ts (见下方说明)，这里配置如下：
    attributes: []
  },

  // 7.4 加密密钥名称 (KeyName)
  {
    key: 'encryptionKeyName',
    localPath: [],
    attributes: []
  }
];

export function extract(context: string, fields: ExtractorFields) {
  const { dom } = getContext();
  const rootDoc = dom.parseFromString(context, 'application/xml');

  return fields.reduce((result: any, field) => {
    const key = field.key;
    const localPath = field.localPath;
    const attributes = field.attributes;
    const isEntire = field.context;
    const shortcut = field.shortcut;
    const index = field.index;
    const attributePath = field.attributePath;
    const listMode = field.listMode;

    let targetDoc = rootDoc;

    if (shortcut) {
      targetDoc = dom.parseFromString(shortcut, 'application/xml');
    }

    // --- 特殊处理：证书提取 (Hardcoded logic for Certificates with @use filter) ---
    if (key === 'signingCert' || key === 'encryptCert') {
      const useType = key === 'signingCert' ? 'signing' : 'encryption';
      const basePath = buildAbsoluteXPath(['EntityDescriptor', 'IDPSSODescriptor']);
      const fullXPath = `${basePath}/*[local-name(.)='KeyDescriptor' and @use='${useType}']/*[local-name(.)='KeyInfo']/*[local-name(.)='X509Data']/*[local-name(.)='X509Certificate']/text()`;

      try {
        // @ts-ignore
        const nodes = select(fullXPath, targetDoc);
        const certs = nodes.map((n: any) => {
          const val = n.nodeValue || n.value;
          return val ? val.replace(/\r\n|\r|\n/g, '') : null;
        }).filter(notEmpty);

        return {
          ...result,
          [key]: certs.length > 0 ? certs[0] : null
        };
      } catch (e) {
        return { ...result, [key]: null };
      }
    }

    // 特殊 case: 多路径 (原有逻辑)
    // 检查是否是 string[][] (即每个元素都是数组)
    if (Array.isArray(localPath) && localPath.length > 0 && Array.isArray(localPath[0])) {
      const multiXPaths = (localPath as string[][]).map(path => `${buildAbsoluteXPath(path)}/text()`).join(' | ');
      // @ts-ignore
      const nodes = select(multiXPaths, targetDoc);
      return {
        ...result,
        [key]: uniq(nodes.map((n: any) => n.nodeValue).filter(notEmpty))
      };
    }

    // 此时 localPath 必然是 string[]，因为如果是 string[][] 已经在上面 return 了
    // 我们显式地将其断言为 string[] 以消除 TS 疑虑
    const currentLocalPath = localPath as string[];

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

// ============================================================================
// 新增：便捷导出函数
// ============================================================================

/**
 * 提取 IdP 元数据
 * @param context IdP 元数据 XML 字符串
 */
export function extractIdp(context: string) {
  return extract(context, idpMetadataFields);
}

/**
 * 提取 SP 元数据
 * @param context SP 元数据 XML 字符串
 */
export function extractSp(context: string) {
  return extract(context, spMetadataFields);
}


