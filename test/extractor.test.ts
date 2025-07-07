// This test file includes all the units related to the extractor
import test from 'ava';
import { readFileSync } from 'fs';
import { extract } from '../src/extractor';

const _decodedResponse: string = String(readFileSync('./test/misc/response_signed.xml'));
const _spmeta: string = String(readFileSync('./test/misc/spmeta.xml'));

(() => {

  test('fetch multiple attributes', t => {
    const result = extract(_decodedResponse, [
      {
        key: 'response',
        localPath: ['Response'],
        attributes: ['ID', 'Destination']
      }
    ]);
    t.is(result.response.id, '_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6');
    t.is(result.response.destination, 'http://sp.example.com/demo1/index.php?acs');
  });

  test('fetch single attributes', t => {
    const result =  extract(_decodedResponse, [
      {
        key: 'statusCode',
        localPath: ['Response', 'Status', 'StatusCode'],
        attributes: ['Value'],
      }
    ]);
    t.is(result.statusCode, 'urn:oasis:names:tc:SAML:2.0:status:Success');
  });

  test('fetch the inner context of leaf node', t => {
    const result =  extract(_decodedResponse, [
      {
        key: 'audience',
        localPath: ['Response', 'Assertion', 'Conditions', 'AudienceRestriction', 'Audience'],
        attributes: []
      }
    ]);
    t.is(result.audience, 'https://sp.example.com/metadata');
  });

  test('fetch the entire context of a non-existing node ', t => {
    const result =  extract(_decodedResponse, [
      {
        key: 'assertionSignature',
        localPath: ['Response', 'Assertion', 'Signature'],
        attributes: [],
        context: true
      }
    ]);
    t.is(result.assertionSignature, null);
  });

  test('fetch the entire context of an existed node', t => {
    const result =  extract(_decodedResponse, [
      {
        key: 'messageSignature',
        localPath: ['Response', 'Signature'],
        attributes: [],
        context: true
      }
    ]);
    t.not(result.messageSignature, null);
  });

  test('fetch the unique inner context of multiple nodes', t => {
    const result =  extract(_decodedResponse, [
      {
        key: 'issuer',
        localPath: [
          ['Response', 'Issuer'],
          ['Response', 'Assertion', 'Issuer']
        ],
        attributes: []
      }
    ]);
    t.is(result.issuer.length, 1);
    t.is(result.issuer.every(i => i === 'https://idp.example.com/metadata'), true);
  });

  test('fetch the attribute with wildcard local path', t => {
    const result =  extract(_spmeta, [
      {
        key: 'certificate',
        localPath: ['EntityDescriptor', '~SSODescriptor', 'KeyDescriptor'],
        index: ['use'],
        attributePath: ['KeyInfo', 'X509Data', 'X509Certificate'],
        attributes: []
      }
    ]);
    t.not(result.certificate.signing, null);
    t.not(result.certificate.encryption, null);
  });

  test('fetch the attribute with non-wildcard local path', t => {
    const result =  extract(_decodedResponse, [
      {
        key: 'attributes',
        localPath: ['Response', 'Assertion', 'AttributeStatement', 'Attribute'],
        index: ['Name'],
        attributePath: ['AttributeValue'],
        attributes: []
      }
    ]);
    t.is(result.attributes.uid, 'test');
    t.is(result.attributes.mail, 'test@example.com');
    t.is(result.attributes.eduPersonAffiliation.length, 2);
  });

  test('fetch with one attribute as key, another as value', t => {
    const result =  extract(_spmeta, [
      {
        key: 'singleSignOnService',
        localPath: ['EntityDescriptor', '~SSODescriptor', 'AssertionConsumerService'],
        index: ['Binding'],
        attributePath: [],
        attributes: ['Location']
      }
    ]);
    const postEndpoint = result.singleSignOnService['urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'];
    const artifactEndpoint = result.singleSignOnService['urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact'];

    t.is(postEndpoint, 'https://sp.example.org/sp/sso');
    t.is(artifactEndpoint, 'https://sp.example.org/sp/sso');
  });

})();
