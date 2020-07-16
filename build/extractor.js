"use strict";
var __assign = (this && this.__assign) || function () {
    __assign = Object.assign || function(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
                t[p] = s[p];
        }
        return t;
    };
    return __assign.apply(this, arguments);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.extract = exports.logoutResponseFields = exports.logoutRequestFields = exports.loginResponseFields = exports.logoutResponseStatusFields = exports.loginResponseStatusFields = exports.loginRequestFields = void 0;
var xmldom_1 = require("xmldom");
var xpath_1 = require("xpath");
var utility_1 = require("./utility");
var camelcase_1 = require("camelcase");
var dom = xmldom_1.DOMParser;
function buildAbsoluteXPath(paths) {
    return paths.reduce(function (currentPath, name) {
        var appendedPath = currentPath;
        var isWildcard = name.startsWith("~");
        if (isWildcard) {
            var pathName = name.replace("~", "");
            appendedPath = currentPath + ("/*[contains(local-name(), '" + pathName + "')]");
        }
        if (!isWildcard) {
            appendedPath = currentPath + ("/*[local-name(.)='" + name + "']");
        }
        return appendedPath;
    }, "");
}
function buildAttributeXPath(attributes) {
    if (attributes.length === 0) {
        return "/text()";
    }
    if (attributes.length === 1) {
        return "/@" + attributes[0];
    }
    var filters = attributes
        .map(function (attribute) { return "name()='" + attribute + "'"; })
        .join(" or ");
    return "/@*[" + filters + "]";
}
exports.loginRequestFields = [
    {
        key: "request",
        localPath: ["AuthnRequest"],
        attributes: [
            "ID",
            "IssueInstant",
            "Destination",
            "AssertionConsumerServiceURL",
        ],
    },
    {
        key: "issuer",
        localPath: ["AuthnRequest", "Issuer"],
        attributes: [],
    },
    {
        key: "nameIDPolicy",
        localPath: ["AuthnRequest", "NameIDPolicy"],
        attributes: ["Format", "AllowCreate"],
    },
    {
        key: "authnContextClassRef",
        localPath: ["AuthnRequest", "AuthnContextClassRef"],
        attributes: [],
    },
    {
        key: "signature",
        localPath: ["AuthnRequest", "Signature"],
        attributes: [],
        context: true,
    },
];
// support two-tiers status code
exports.loginResponseStatusFields = [
    {
        key: "top",
        localPath: ["Response", "Status", "StatusCode"],
        attributes: ["Value"],
    },
    {
        key: "second",
        localPath: ["Response", "Status", "StatusCode", "StatusCode"],
        attributes: ["Value"],
    },
];
// support two-tiers status code
exports.logoutResponseStatusFields = [
    {
        key: "top",
        localPath: ["LogoutResponse", "Status", "StatusCode"],
        attributes: ["Value"],
    },
    {
        key: "second",
        localPath: ["LogoutResponse", "Status", "StatusCode", "StatusCode"],
        attributes: ["Value"],
    },
];
exports.loginResponseFields = function (assertion) { return [
    {
        key: "conditions",
        localPath: ["Assertion", "Conditions"],
        attributes: ["NotBefore", "NotOnOrAfter"],
        shortcut: assertion,
    },
    {
        key: "response",
        localPath: ["Response"],
        attributes: ["ID", "IssueInstant", "Destination", "InResponseTo"],
    },
    {
        key: "audience",
        localPath: ["Assertion", "Conditions", "AudienceRestriction", "Audience"],
        attributes: [],
        shortcut: assertion,
    },
    // {
    //   key: 'issuer',
    //   localPath: ['Response', 'Issuer'],
    //   attributes: []
    // },
    {
        key: "issuer",
        localPath: ["Assertion", "Issuer"],
        attributes: [],
        shortcut: assertion,
    },
    {
        key: "nameID",
        localPath: ["Assertion", "Subject", "NameID"],
        attributes: [],
        shortcut: assertion,
    },
    {
        key: "sessionIndex",
        localPath: ["Assertion", "AuthnStatement"],
        attributes: ["AuthnInstant", "SessionNotOnOrAfter", "SessionIndex"],
        shortcut: assertion,
    },
    {
        key: "attributes",
        localPath: ["Assertion", "AttributeStatement", "Attribute"],
        index: ["Name"],
        attributePath: ["AttributeValue"],
        attributes: [],
        shortcut: assertion,
    },
]; };
exports.logoutRequestFields = [
    {
        key: "request",
        localPath: ["LogoutRequest"],
        attributes: ["ID", "IssueInstant", "Destination"],
    },
    {
        key: "issuer",
        localPath: ["LogoutRequest", "Issuer"],
        attributes: [],
    },
    {
        key: "nameID",
        localPath: ["LogoutRequest", "NameID"],
        attributes: [],
    },
    {
        key: "signature",
        localPath: ["LogoutRequest", "Signature"],
        attributes: [],
        context: true,
    },
];
exports.logoutResponseFields = [
    {
        key: "response",
        localPath: ["LogoutResponse"],
        attributes: ["ID", "Destination", "InResponseTo"],
    },
    {
        key: "issuer",
        localPath: ["LogoutResponse", "Issuer"],
        attributes: [],
    },
    {
        key: "signature",
        localPath: ["LogoutResponse", "Signature"],
        attributes: [],
        context: true,
    },
];
function extract(context, fields) {
    var rootDoc = new dom().parseFromString(context);
    return fields.reduce(function (result, field) {
        var _a, _b, _c, _d, _e, _f;
        // get essential fields
        var key = field.key;
        var localPath = field.localPath;
        var attributes = field.attributes;
        var isEntire = field.context;
        var shortcut = field.shortcut;
        // get optional fields
        var index = field.index;
        var attributePath = field.attributePath;
        // set allowing overriding if there is a shortcut injected
        var targetDoc = rootDoc;
        // if shortcut is used, then replace the doc
        // it's a design for overriding the doc used during runtime
        if (shortcut) {
            targetDoc = new dom().parseFromString(shortcut);
        }
        // special case: multiple path
        /*
          {
            key: 'issuer',
            localPath: [
              ['Response', 'Issuer'],
              ['Response', 'Assertion', 'Issuer']
            ],
            attributes: []
          }
         */
        if (localPath.every(function (path) { return Array.isArray(path); })) {
            var multiXPaths = localPath
                .map(function (path) {
                // not support attribute yet, so ignore it
                return buildAbsoluteXPath(path) + "/text()";
            })
                .join(" | ");
            return __assign(__assign({}, result), (_a = {}, _a[key] = utility_1.uniq(xpath_1.select(multiXPaths, targetDoc)
                .map(function (n) { return n.nodeValue; })
                .filter(utility_1.notEmpty)), _a));
        }
        // eo special case: multiple path
        var baseXPath = buildAbsoluteXPath(localPath);
        var attributeXPath = buildAttributeXPath(attributes);
        // special case: get attributes where some are in child, some are in parent
        /*
          {
            key: 'attributes',
            localPath: ['Response', 'Assertion', 'AttributeStatement', 'Attribute'],
            index: ['Name'],
            attributePath: ['AttributeValue'],
            attributes: []
          }
        */
        if (index && attributePath) {
            // find the index in localpath
            var indexPath = buildAttributeXPath(index);
            var fullLocalXPath = "" + baseXPath + indexPath;
            var parentNodes = xpath_1.select(baseXPath, targetDoc);
            // [uid, mail, edupersonaffiliation], ready for aggregate
            var parentAttributes = xpath_1.select(fullLocalXPath, targetDoc).map(function (n) { return n.value; });
            // [attribute, attributevalue]
            var childXPath = buildAbsoluteXPath([utility_1.last(localPath)].concat(attributePath));
            var childAttributeXPath = buildAttributeXPath(attributes);
            var fullChildXPath_1 = "" + childXPath + childAttributeXPath;
            // [ 'test', 'test@example.com', [ 'users', 'examplerole1' ] ]
            var childAttributes = parentNodes.map(function (node) {
                var nodeDoc = new dom().parseFromString(node.toString());
                if (attributes.length === 0) {
                    var childValues = xpath_1.select(fullChildXPath_1, nodeDoc).map(function (n) { return n.nodeValue; });
                    if (childValues.length === 1) {
                        return childValues[0];
                    }
                    return childValues;
                }
                if (attributes.length > 0) {
                    var childValues = xpath_1.select(fullChildXPath_1, nodeDoc).map(function (n) { return n.value; });
                    if (childValues.length === 1) {
                        return childValues[0];
                    }
                    return childValues;
                }
                return null;
            });
            // aggregation
            var obj = utility_1.zipObject(parentAttributes, childAttributes, false);
            return __assign(__assign({}, result), (_b = {}, _b[key] = obj, _b));
        }
        // case: fetch entire content, only allow one existence
        /*
          {
            key: 'signature',
            localPath: ['AuthnRequest', 'Signature'],
            attributes: [],
            context: true
          }
        */
        if (isEntire) {
            var node = xpath_1.select(baseXPath, targetDoc);
            var value = null;
            if (node.length === 1) {
                value = node[0].toString();
            }
            if (node.length > 1) {
                value = node.map(function (n) { return n.toString(); });
            }
            return __assign(__assign({}, result), (_c = {}, _c[key] = value, _c));
        }
        // case: multiple attribute
        /*
          {
            key: 'nameIDPolicy',
            localPath: ['AuthnRequest', 'NameIDPolicy'],
            attributes: ['Format', 'AllowCreate']
          }
        */
        if (attributes.length > 1) {
            var baseNode = xpath_1.select(baseXPath, targetDoc).map(function (n) {
                return n.toString();
            });
            var childXPath_1 = "" + buildAbsoluteXPath([
                utility_1.last(localPath),
            ]) + attributeXPath;
            var attributeValues = baseNode.map(function (node) {
                var nodeDoc = new dom().parseFromString(node);
                return xpath_1.select(childXPath_1, nodeDoc).reduce(function (r, n) {
                    r[camelcase_1.default(n.name)] = n.value;
                    return r;
                }, {});
            });
            return __assign(__assign({}, result), (_d = {}, _d[key] = attributeValues.length === 1 ? attributeValues[0] : attributeValues, _d));
        }
        // case: single attribute
        /*
          {
            key: 'statusCode',
            localPath: ['Response', 'Status', 'StatusCode'],
            attributes: ['Value'],
          }
        */
        if (attributes.length === 1) {
            var fullPath = "" + baseXPath + attributeXPath;
            var attributeValues = xpath_1.select(fullPath, targetDoc).map(function (n) { return n.value; });
            return __assign(__assign({}, result), (_e = {}, _e[key] = attributeValues[0], _e));
        }
        // case: zero attribute
        /*
          {
            key: 'issuer',
            localPath: ['AuthnRequest', 'Issuer'],
            attributes: []
          }
        */
        if (attributes.length === 0) {
            var attributeValue = null;
            var node = xpath_1.select(baseXPath, targetDoc);
            if (node.length === 1) {
                var fullPath = "string(" + baseXPath + attributeXPath + ")";
                attributeValue = xpath_1.select(fullPath, targetDoc);
            }
            if (node.length > 1) {
                attributeValue = node.map(function (n) { return n.firstChild.nodeValue; });
            }
            return __assign(__assign({}, result), (_f = {}, _f[key] = attributeValue, _f));
        }
        return result;
    }, {});
}
exports.extract = extract;
//# sourceMappingURL=extractor.js.map