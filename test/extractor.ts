// This test file includes all the units related to the extractor
import test from 'ava';
import esaml2 = require('../index');
import { readFileSync } from 'fs';

const {
  SamlLib: libsaml,
  SPMetadata: spMetadata
} = esaml2;

const SPMetadata = spMetadata(readFileSync('./test/misc/spmeta.xml'));
const _decodedResponse: string = String(readFileSync('./test/misc/response_signed.xml'));

(() => {
  /** high-level extractor */
  test('get innerText returns a value', t => {
    t.is(libsaml.extractor(_decodedResponse, ['NameID'])['nameid'], '_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7');
  });
  test('get innerText returns undefined', t => {
    t.is(libsaml.extractor(_decodedResponse, ['notexist'])['notexist'] === undefined, true);
  });
  test('get innerText returns an array of values', t => {
    t.is(JSON.stringify((libsaml.extractor(_decodedResponse, ['AttributeValue']))), JSON.stringify({
      attributevalue: ['test', 'test@example.com', 'users', 'examplerole1'],
    }));
  });
  test('get innerText returns a value with custom key', t => {
    t.is(libsaml.extractor(_decodedResponse, [{ localName: 'NameID', customKey: 'nid' }])['nid'], '_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7');
  });

  test('get attributes returns an object', t => {
    t.is(JSON.stringify(libsaml.extractor(_decodedResponse, [{
      localName: 'Conditions',
      attributes: ['NotBefore', 'NotOnOrAfter'],
    }])), JSON.stringify({
      conditions: {
        notbefore: '2014-07-17T01:01:18Z',
        notonorafter: '2024-01-18T06:21:48Z',
      },
    }));
  });
  test('get attributes returns an array of objects', t => {
    t.is(JSON.stringify(libsaml.extractor(_decodedResponse, [{
      localName: 'Attribute',
      attributes: ['Name', 'NameFormat'],
    }])['attribute']), JSON.stringify([{
      name: 'uid',
      nameformat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
    }, {
      name: 'mail',
      nameformat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
    }, {
      name: 'eduPersonAffiliation',
      nameformat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
    }]));
  });
  test('get attributes returns an undefined for non-exist attribute', t => {
    t.is(libsaml.extractor(_decodedResponse, [{
      localName: 'Conditions',
      attributes: ['notexist'],
    }])['conditions'].notexist === undefined, true);
  });
  test('get attributes returns an undefined with non-exist localName', t => {
    t.is(libsaml.extractor(_decodedResponse, [{
      localName: 'Condition',
      attributes: ['notexist'],
    }])['condition'] === undefined, true);
  });
  test('get attributes returns a value with custom key', t => {
    t.is(libsaml.extractor(_decodedResponse, [{
      localName: 'Conditions',
      attributes: ['notexist'],
      customKey: 'cd',
    }])['cd'].notexist === undefined, true);
  });

  test('get entire text returns a xml string', t => {
    t.is(JSON.stringify(libsaml.extractor(_decodedResponse, [{
      localName: 'Signature',
      extractEntireBody: true,
    }]).signature), JSON.stringify('<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><Reference URI="#_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75"><Transforms><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><DigestValue>sZOR3aMpVBn1CoSmP674OQfCcyg=</DigestValue></Reference></SignedInfo><SignatureValue>h7Dk6GTh4MrNNx8b8Or12SeGsAGBM/ILd7Jgz/RuqR6ixMHrmkRAotou8LvKOzH9I9BfLthqgwcNJGm4hMPHcxoiyVlkqWqnpIMxlWc/vb1E/lXjwo86mZ/hBUJdRhgIfrgIDKCMBf98ftWtUF8I1Hd5qBvY7pTMk3ErQYOtqBfvCCFGwejAfOUKwtY4itQ7AILi4Er2IgALH0zJO7alPugTOwmICd998rafB2wAHWREJkaOfCgCasRkB8tqcWjpLx2oMqiYSTVq2d6PBgAFSmoN9ltO2neTz9pqd0BA1BKIi7PjQYN+F7dB/ffG7V8VjNoPMROrHzq6sY3Ondtv7w==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIDlzCCAn+gAwIBAgIJAO1ymQc33+bWMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNVBAYTAkhLMRMwEQYDVQQIDApTb21lLVN0YXRlMRowGAYDVQQKDBFJZGVudGl0eSBQcm92aWRlcjEUMBIGA1UECwwLRGV2ZWxvcG1lbnQxDDAKBgNVBAMMA0lEUDAeFw0xNTA3MDUxODAyMjdaFw0xODA3MDQxODAyMjdaMGIxCzAJBgNVBAYTAkhLMRMwEQYDVQQIDApTb21lLVN0YXRlMRowGAYDVQQKDBFJZGVudGl0eSBQcm92aWRlcjEUMBIGA1UECwwLRGV2ZWxvcG1lbnQxDDAKBgNVBAMMA0lEUDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAODZsWhCe+yG0PalQPTUoD7yko5MTWMCRxJ8hSm2k7mG3Eg/Y2v0EBdCmTw7iDCevRqUmbmFnq7MROyV4eriJzh0KabAdZf7/k6koghst3ZUtWOwzshyxkBtWDwGmBpQGTGsKxJ8M1js3aSqNRXBT4OBWM9w2Glt1+8ty30RhYv3pSF+/HHLH7Ac+vLSIAlokaFW34RWTcJ/8rADuRWlXih4GfnIu0W/ncm5nTSaJiRAvr3dGDRO/khiXoJdbbOj7dHPULxVGbH9IbPK76TCwLbF7ikIMsPovVbTrpyL6vsbVUKeEl/5GKppTwp9DLAOeoSYpCYkkDkYKu9TRQjF02MCAwEAAaNQME4wHQYDVR0OBBYEFP2ut2AQdy6D1dwdwK740IHmbh38MB8GA1UdIwQYMBaAFP2ut2AQdy6D1dwdwK740IHmbh38MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBANMZUoPNmHzgja2PYkbvBYMHmpvUkVoiuvQ9cJPlqGTB2CRfG68BNNs/Clz8P7cIrAdkhCUwi1rSBhDuslGFNrSaIpv6B10FpBuKwef3G7YrPWFNEN6khY7aHNWSTHqKgs1DrGef2B9hvkrnHWbQVSVXrBFKe1wTCqcgGcOpYoSK7L8C6iX6uIA/uZYnVQ4NgBrizJ0azkjdegz3hwO/gt4malEURy8D85/AAVt6PAzhpb9VJUGxSXr/EfntVUEz3L2gUFWWk1CnZFyz0rIOEt/zPmeAY8BLyd/Tjxm4Y+gwNazKq5y9AJS+m858b/nM4QdCnUE4yyoWAJDUHiAmvFA=</X509Certificate></X509Data></KeyInfo></Signature>'));
  });
  test('get entire text returns undefined', t => {
    t.is(libsaml.extractor(_decodedResponse, [{ localName: 'Not Exist', extractEntireBody: true }]).signature === undefined, true);
  });
  test('get entire text returns a value with custom key', t => {
    t.is(JSON.stringify(libsaml.extractor(_decodedResponse, [{
      localName: 'Signature',
      extractEntireBody: true,
      customKey: 'cd',
    }])['cd']), JSON.stringify('<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><Reference URI="#_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75"><Transforms><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><DigestValue>sZOR3aMpVBn1CoSmP674OQfCcyg=</DigestValue></Reference></SignedInfo><SignatureValue>h7Dk6GTh4MrNNx8b8Or12SeGsAGBM/ILd7Jgz/RuqR6ixMHrmkRAotou8LvKOzH9I9BfLthqgwcNJGm4hMPHcxoiyVlkqWqnpIMxlWc/vb1E/lXjwo86mZ/hBUJdRhgIfrgIDKCMBf98ftWtUF8I1Hd5qBvY7pTMk3ErQYOtqBfvCCFGwejAfOUKwtY4itQ7AILi4Er2IgALH0zJO7alPugTOwmICd998rafB2wAHWREJkaOfCgCasRkB8tqcWjpLx2oMqiYSTVq2d6PBgAFSmoN9ltO2neTz9pqd0BA1BKIi7PjQYN+F7dB/ffG7V8VjNoPMROrHzq6sY3Ondtv7w==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIDlzCCAn+gAwIBAgIJAO1ymQc33+bWMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNVBAYTAkhLMRMwEQYDVQQIDApTb21lLVN0YXRlMRowGAYDVQQKDBFJZGVudGl0eSBQcm92aWRlcjEUMBIGA1UECwwLRGV2ZWxvcG1lbnQxDDAKBgNVBAMMA0lEUDAeFw0xNTA3MDUxODAyMjdaFw0xODA3MDQxODAyMjdaMGIxCzAJBgNVBAYTAkhLMRMwEQYDVQQIDApTb21lLVN0YXRlMRowGAYDVQQKDBFJZGVudGl0eSBQcm92aWRlcjEUMBIGA1UECwwLRGV2ZWxvcG1lbnQxDDAKBgNVBAMMA0lEUDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAODZsWhCe+yG0PalQPTUoD7yko5MTWMCRxJ8hSm2k7mG3Eg/Y2v0EBdCmTw7iDCevRqUmbmFnq7MROyV4eriJzh0KabAdZf7/k6koghst3ZUtWOwzshyxkBtWDwGmBpQGTGsKxJ8M1js3aSqNRXBT4OBWM9w2Glt1+8ty30RhYv3pSF+/HHLH7Ac+vLSIAlokaFW34RWTcJ/8rADuRWlXih4GfnIu0W/ncm5nTSaJiRAvr3dGDRO/khiXoJdbbOj7dHPULxVGbH9IbPK76TCwLbF7ikIMsPovVbTrpyL6vsbVUKeEl/5GKppTwp9DLAOeoSYpCYkkDkYKu9TRQjF02MCAwEAAaNQME4wHQYDVR0OBBYEFP2ut2AQdy6D1dwdwK740IHmbh38MB8GA1UdIwQYMBaAFP2ut2AQdy6D1dwdwK740IHmbh38MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBANMZUoPNmHzgja2PYkbvBYMHmpvUkVoiuvQ9cJPlqGTB2CRfG68BNNs/Clz8P7cIrAdkhCUwi1rSBhDuslGFNrSaIpv6B10FpBuKwef3G7YrPWFNEN6khY7aHNWSTHqKgs1DrGef2B9hvkrnHWbQVSVXrBFKe1wTCqcgGcOpYoSK7L8C6iX6uIA/uZYnVQ4NgBrizJ0azkjdegz3hwO/gt4malEURy8D85/AAVt6PAzhpb9VJUGxSXr/EfntVUEz3L2gUFWWk1CnZFyz0rIOEt/zPmeAY8BLyd/Tjxm4Y+gwNazKq5y9AJS+m858b/nM4QdCnUE4yyoWAJDUHiAmvFA=</X509Certificate></X509Data></KeyInfo></Signature>'));
  });

  test('get attirbute-innerText (kv) pair, single value returns string', t => {
    t.is(JSON.stringify(libsaml.extractor(SPMetadata.xmlString, [{
      localName: {
        tag: 'KeyDescriptor',
        key: 'use',
      },
      valueTag: 'X509Certificate',
    }])), '{"keydescriptor":{"signing":"MIIDozCCAougAwIBAgIJAKNsmL8QbfpwMA0GCSqGSIb3DQEBCwUAMGgxCzAJBgNVBAYTAkhLMRIwEAYDVQQIDAlIb25nIEtvbmcxCzAJBgNVBAcMAkhLMRMwEQYDVQQKDApub2RlLXNhbWwyMSMwIQYJKoZIhvcNAQkBFhRub2RlLnNhbWwyQGdtYWlsLmNvbTAeFw0xNTA3MDUxNzU2NDdaFw0xODA3MDQxNzU2NDdaMGgxCzAJBgNVBAYTAkhLMRIwEAYDVQQIDAlIb25nIEtvbmcxCzAJBgNVBAcMAkhLMRMwEQYDVQQKDApub2RlLXNhbWwyMSMwIQYJKoZIhvcNAQkBFhRub2RlLnNhbWwyQGdtYWlsLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMQJAB8JrsLQbUuJa8akzLqO1EZqClS0tQp+w+5wgufp07WwGn/shma8dcQNj1dbjszI5HBeVFjOKIxlfjmNB9ovhQPstBjP/UPQYp1Ip2IoHCYX9HDgMz3xyXKbHthUzZaECz+p+7WtgwhczRkBLDOm2k15qhPYGPw0vH2zbVRGWUBS9dy2Mp3tqlVbP0xZ9CDNkhCJkV9SMNfoCVW/VYPqK2QBo7ki4obm5x5ixFQSSHsKbVARVzyQH5iNjFe1TdAp3rDwrE5Lc1NQlQaxR5Gnb2NZApDORRZIVlNv2WUdi9QvM0yCzjQ90jP0OAogHhRYaxg0/vgNEye46h+PiY0CAwEAAaNQME4wHQYDVR0OBBYEFEVkjcLAITndky090Ay74QqCmQKIMB8GA1UdIwQYMBaAFEVkjcLAITndky090Ay74QqCmQKIMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAG4lYX3KQXenez4LpDnZhcFBEZi9YstUKPF5EKd+WplpVbcTQc1A3/Z+uHRmyV8h+pQzeF6Liob37G87YpacPplJI66cf2Rj7j8hSBNbdr+66E2qpcEhAF1iJmzBNyhb/ydlEuVpn8/EsoP+HvBeiDl5gon3562MzZIgV/pLdTfxHyW6hzAQhjGq2UhcvR+gXNVJvHP2eS4jlHnJkB9bfo0kvf87Q+D6XKX3q5c3mO8tqW6UpqHSC+uLEpzZiNLeuFa4TUIhgBgjDjlRrNDKu8ndancSn3yBHYnqJ2t9cR+coFnnjYABQpNrvk4mtmXY8SXoBzYG9Y+lqeAun6+0YyE=","encryption":"MIID7TCCAtWgAwIBAgIJANSq1uUtXl4DMA0GCSqGSIb3DQEBCwUAMFcxCzAJBgNVBAYTAkhLMRIwEAYDVQQIEwlIb25nIEtvbmcxFjAUBgNVBAoTDWV4cHJlc3Mtc2FtbDIxDDAKBgNVBAsTA2RldjEOMAwGA1UEAxMFZXNhbWwwHhcNMTUxMDAzMDM0ODA2WhcNMTgxMDAyMDM0ODA2WjBXMQswCQYDVQQGEwJISzESMBAGA1UECBMJSG9uZyBLb25nMRYwFAYDVQQKEw1leHByZXNzLXNhbWwyMQwwCgYDVQQLEwNkZXYxDjAMBgNVBAMTBWVzYW1sMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyx/yIgvJwfOCwMTNjL4Fslr21ky4O/uzxp0Y8wpHk9jk8Afcj3plQCr5X8dPKG2Rz4EIh//nQQL9tq2InaUdRwJkS9SeuuAcJG7DN/KDUtfrh4+cO2lZ4h7cQIdjpbBgpGEMhGy1wwpwHJsadoBuX0PKyT4O4oHkj1gwWO14qYnK4biviNBqmjGjmN+py+lUcACsQt22abA4s8Xjm/tlvnkgNRE3H44ICvSr8m5MVhyYGoAUe7Qprn2BcsMXd9mrlZ5hEdalNUDRbKb+W7mrKEkKFCbE3wi/Ns2bc4fbNXvwcZoF3/TPzl936u2eivTQESjCLsymIqdYHwRiVLifWQIDAQABo4G7MIG4MB0GA1UdDgQWBBSdBiMAVhKrjzd72sncR13imevq/DCBiAYDVR0jBIGAMH6AFJ0GIwBWEquPN3vaydxHXeKZ6+r8oVukWTBXMQswCQYDVQQGEwJISzESMBAGA1UECBMJSG9uZyBLb25nMRYwFAYDVQQKEw1leHByZXNzLXNhbWwyMQwwCgYDVQQLEwNkZXYxDjAMBgNVBAMTBWVzYW1sggkA1KrW5S1eXgMwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEARi25PJOR+x0ytYCmfXwG5LSXKNHx5BD6G+nBgXm1/DMMJ9ZY34FYMF3gDUu+NmQoVegqARTxetQcCICpAPdKnK0yQb6MXdj3VfQnEA+4hVGFmqnHTK90g0BudEmp1fWKBjJYpLd0oncVwJQJDK5OfS7fMUftN6/Kg6/fDuJMCNIECfKRE8tiXz2Ht924MjedKlH0+qoV1F2Fy5as+QRbj/QfrPTrZrfqhP04mavTPL2bdW6+ykeQWN3zMQtJA8kt2LI0y0CIGhFjLbqAceq+gDkp4drj7/Yw8qaqmxl6GP8w3GbfLu6mXCjCLCGgsATktvWq9dRfBuapaIpNDrv0NA=="}}');
  });
  test('get attirbute-innerText (kv) pair, multi values returns array composed of multi strings', t => {
    t.is(JSON.stringify(libsaml.extractor(_decodedResponse, [{
      localName: {
        tag: 'Attribute',
        key: 'Name',
      },
      valueTag: 'AttributeValue',
    }])), '{"attribute":{"uid":"test","mail":"test@example.com","eduPersonAffiliation":["users","examplerole1"]}}');
  });
  test('get attirbute-innerText (kv) pair, non-exist key returns undefined', t => {
    t.is(JSON.stringify(libsaml.extractor(SPMetadata.xmlString, [{
      localName: {
        tag: 'KeyDescriptor',
        key: 'used',
      },
      valueTag: 'X509Certificate',
    }]))['keydescriptor'] === undefined, true);

  });
  test('get attirbute-innerText (kv) pair, non-exist value returns undefined', t => {
    t.is(JSON.stringify(libsaml.extractor(SPMetadata.xmlString, [{
      localName: {
        tag: 'KeyDescriptor',
        key: 'use',
      },
      valueTag: 'X123Certificate',
    }]))['keydescriptor'] === undefined, true);
  });
  test('get attirbute-innerText (kv) pair, non-exist tag should return undefined', t => {
    t.is(JSON.stringify(libsaml.extractor(SPMetadata.xmlString, [{
      localName: {
        tag: 'KeyDescription',
        key: 'encrypt',
      },
      valueTag: 'X509Certificate',
    }]))['keydescriptor'] === undefined, true);
  });
  test('get attirbute-innerText (kv) pair, returns value with custom key', t => {
    t.is(JSON.stringify(libsaml.extractor(_decodedResponse, [{
      localName: {
        tag: 'Attribute',
        key: 'Name',
      },
      valueTag: 'AttributeValue',
      customKey: 'kd',
    }])['kd']), '{"uid":"test","mail":"test@example.com","eduPersonAffiliation":["users","examplerole1"]}');
  });

  test('get attirbutev1-attributev2 (kv) pair, single value returns array consisting one object', t => {
    t.is(JSON.stringify(libsaml.extractor(SPMetadata.xmlString, [{
      localName: { tag: 'AssertionConsumerService', key: 'isDefault' },
      attributeTag: 'index',
    }])['assertionconsumerservice']), '[{"true":"0"}]');
  });
  test('get attirbutev1-attributev2 (kv) pair, multi values returns array composed of multi objects', t => {
    t.is(JSON.stringify(libsaml.extractor(SPMetadata.xmlString, [{
      localName: {
        tag: 'SingleLogoutService',
        key: 'Binding',
      },
      attributeTag: 'Location',
    }])['singlelogoutservice']), '[{"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect":"https://sp.example.org/sp/slo"},{"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST":"https://sp.example.org/sp/slo"}]');
  });
  test('get attirbutev1-attributev2 (kv) pair, non-exist tag returns undefined', t => {
    t.is(JSON.stringify(libsaml.extractor(SPMetadata.xmlString, [{
      localName: {
        tag: 'SingleLogoutServices',
        key: 'Binding',
      },
      attributeTag: 'Location',
    }])['singlelogoutservice']) === undefined, true);
  });
  test('get attirbutev1-attributev2 (kv) pair, non-exist key returns undefined', t => {
    t.is(JSON.stringify(libsaml.extractor(SPMetadata.xmlString, [{
      localName: {
        tag: 'SingleLogoutService',
        key: 'Winding',
      },
      attributeTag: 'Location',
    }]))['singlelogoutservice'] === undefined, true);
  });
  test('get attirbutev1-attributev2 (kv) pair, non-exist attribute tag returns undefined', t => {
    t.is(JSON.stringify(libsaml.extractor(SPMetadata.xmlString, [{
      localName: {
        tag: 'SingleLogoutService',
        key: 'Binding',
      },
      attributeTag: 'NoSuchLocation',
    }]))['singlelogoutservice'] === undefined, true);
  });
  test('get attirbutev1-attributev2 (kv) pair, returns value with custom key', t => {
    t.is(JSON.stringify(libsaml.extractor(SPMetadata.xmlString, [{
      localName: {
        tag: 'SingleLogoutService',
        key: 'Binding',
      },
      attributeTag: 'Location',
      customKey: 'slo',
    }])['slo']), '[{"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect":"https://sp.example.org/sp/slo"},{"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST":"https://sp.example.org/sp/slo"}]');
  });
})();
