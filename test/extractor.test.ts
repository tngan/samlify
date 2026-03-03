import {test, expect} from 'vitest';
import {readFileSync} from 'fs';
import {extract} from '../src/extractor.js';

const _decodedResponse: string = String(readFileSync('./test/misc/response_signed.xml'));
const _spmeta: string = String(readFileSync('./test/misc/spmeta.xml'));

test('fetch multiple attributes', () => {
    const result = extract(_decodedResponse, [
        {
            key: 'response',
            localPath: ['Response'],
            attributes: ['ID', 'Destination']
        }
    ]);
    expect(result.response.id).toBe('_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6');
    expect(result.response.destination).toBe('http://sp.example.com/demo1/index.php?acs');
});

test('fetch single attributes', () => {
    const result = extract(_decodedResponse, [
        {
            key: 'statusCode',
            localPath: ['Response', 'Status', 'StatusCode'],
            attributes: ['Value'],
        }
    ]);
    expect(result.statusCode).toBe('urn:oasis:names:tc:SAML:2.0:status:Success');
});

test('fetch the inner context of leaf node', () => {
    const result = extract(_decodedResponse, [
        {
            key: 'audience',
            localPath: ['Response', 'Assertion', 'Conditions', 'AudienceRestriction', 'Audience'],
            attributes: []
        }
    ]);
    expect(result.audience).toBe('https://sp.example.com/metadata');
});

test('fetch the entire context of a non-existing node', () => {
    const result = extract(_decodedResponse, [
        {
            key: 'assertionSignature',
            localPath: ['Response', 'Assertion', 'Signature'],
            attributes: [],
            context: true
        }
    ]);
    expect(result.assertionSignature).toBeNull();
});

test('fetch the entire context of an existed node', () => {
    const result = extract(_decodedResponse, [
        {
            key: 'messageSignature',
            localPath: ['Response', 'Signature'],
            attributes: [],
            context: true
        }
    ]);
    expect(result.messageSignature).not.toBeNull();
});

test('fetch the unique inner context of multiple nodes', () => {
    const result = extract(_decodedResponse, [
        {
            key: 'issuer',
            localPath: [
                ['Response', 'Issuer'],
                ['Response', 'Assertion', 'Issuer']
            ],
            attributes: []
        }
    ]);
    expect(result.issuer.length).toBe(1);
    expect(result.issuer.every(i => i === 'https://idp.example.com/metadata')).toBe(true);
});

test('fetch the attribute with wildcard local path', () => {
    const result = extract(_spmeta, [
        {
            key: 'certificate',
            localPath: ['EntityDescriptor', '~SSODescriptor', 'KeyDescriptor'],
            index: ['use'],
            attributePath: ['KeyInfo', 'X509Data', 'X509Certificate'],
            attributes: []
        }
    ]);
    expect(result.certificate.signing).not.toBeNull();
    expect(result.certificate.encryption).not.toBeNull();
});

test('fetch the attribute with non-wildcard local path', () => {
    const result = extract(_decodedResponse, [
        {
            key: 'attributes',
            localPath: ['Response', 'Assertion', 'AttributeStatement', 'Attribute'],
            index: ['Name'],
            attributePath: ['AttributeValue'],
            attributes: []
        }
    ]);
    expect(result.attributes.uid).toBe('test');
    expect(result.attributes.mail).toBe('test@example.com');
    expect(result.attributes.eduPersonAffiliation.length).toBe(2);
});

test('fetch with one attribute as key, another as value', () => {
    const result = extract(_spmeta, [
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

    expect(postEndpoint).toBe('https://sp.example.org/sp/sso');
    expect(artifactEndpoint).toBe('https://sp.example.org/sp/sso');
});
