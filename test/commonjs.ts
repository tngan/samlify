import { test, expect, beforeAll } from 'vitest';
import { execSync } from 'child_process';
import { existsSync } from 'fs';
import { resolve } from 'path';

const buildDir = resolve(__dirname, '..', 'build');
const entryPoint = resolve(buildDir, 'index.js');

beforeAll(() => {
  execSync('npx tsc', { cwd: resolve(__dirname, '..'), stdio: 'pipe' });
});

test('build output exists as CommonJS', () => {
  expect(existsSync(entryPoint)).toBe(true);
});

test('require() succeeds without throwing', () => {
  const result = execSync(
    `node -e "require('./build/index'); console.log('OK')"`,
    { cwd: resolve(__dirname, '..'), encoding: 'utf-8' }
  );
  expect(result.trim()).toBe('OK');
});

test('all expected exports are available via require()', () => {
  const script = `
    const m = require('./build/index');
    const keys = Object.keys(m).sort();
    console.log(JSON.stringify(keys));
  `;
  const result = execSync(`node -e "${script.replace(/\n/g, ' ')}"`, {
    cwd: resolve(__dirname, '..'),
    encoding: 'utf-8',
  });
  const exports = JSON.parse(result.trim());

  const expected = [
    'Constants',
    'Extractor',
    'IdPMetadata',
    'IdentityProvider',
    'IdentityProviderInstance',
    'SPMetadata',
    'SamlLib',
    'ServiceProvider',
    'ServiceProviderInstance',
    'Utility',
    'setDOMParserOptions',
    'setSchemaValidator',
  ];
  for (const name of expected) {
    expect(exports).toContain(name);
  }
});

test('SamlLib is functional via require()', () => {
  const script = `
    const m = require('./build/index');
    const result = m.SamlLib.createXPath('NameID');
    console.log(result);
  `;
  const result = execSync(`node -e "${script.replace(/\n/g, ' ')}"`, {
    cwd: resolve(__dirname, '..'),
    encoding: 'utf-8',
  });
  expect(result.trim()).toBe("//*[local-name(.)='NameID']");
});

test('Utility is functional via require()', () => {
  const script = `
    const m = require('./build/index');
    const encoded = m.Utility.base64Encode('hello samlify');
    console.log(encoded);
  `;
  const result = execSync(`node -e "${script.replace(/\n/g, ' ')}"`, {
    cwd: resolve(__dirname, '..'),
    encoding: 'utf-8',
  });
  expect(result.trim()).toBe(Buffer.from('hello samlify').toString('base64'));
});

test('Extractor module is loadable via require()', () => {
  const script = `
    const m = require('./build/index');
    const hasExtract = typeof m.Extractor.extract === 'function';
    console.log(hasExtract);
  `;
  const result = execSync(`node -e "${script.replace(/\n/g, ' ')}"`, {
    cwd: resolve(__dirname, '..'),
    encoding: 'utf-8',
  });
  expect(result.trim()).toBe('true');
});

test('IdentityProvider and ServiceProvider constructors are callable via require()', () => {
  const script = `
    const m = require('./build/index');
    console.log(JSON.stringify({
      idp: typeof m.IdentityProvider,
      sp: typeof m.ServiceProvider,
    }));
  `;
  const result = execSync(`node -e "${script.replace(/\n/g, ' ')}"`, {
    cwd: resolve(__dirname, '..'),
    encoding: 'utf-8',
  });
  const types = JSON.parse(result.trim());
  expect(types.idp).toBe('function');
  expect(types.sp).toBe('function');
});

test('no ESM-only dependencies break require()', () => {
  const script = `
    try {
      require('./build/index');
      require('./build/src/extractor');
      require('./build/src/libsaml');
      console.log('OK');
    } catch (e) {
      console.log('FAIL: ' + e.message);
    }
  `;
  const result = execSync(`node -e "${script.replace(/\n/g, ' ')}"`, {
    cwd: resolve(__dirname, '..'),
    encoding: 'utf-8',
  });
  expect(result.trim()).toBe('OK');
});
