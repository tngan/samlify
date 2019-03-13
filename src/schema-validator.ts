import * as fs from 'fs';
import * as path from 'path';

enum SchemaValidators {
  JAVAC = '@authenio/xsd-schema-validator',
  LIBXML = 'libxml-xsd',
  XMLLINT = 'node-xmllint'
}

interface SchemaValidator {
  validate: (xml: string) => Promise<string>;
}

type GetValidatorModuleSpec = () => Promise<SchemaValidator>;

const moduleResolver = (name: string) => {
  try {
    require.resolve(name);
    return name;
  } catch (e) {
    return null;
  }
};

const getValidatorModule: GetValidatorModuleSpec = async () => {

  const selectedValidator: string = moduleResolver(SchemaValidators.JAVAC)
    || moduleResolver(SchemaValidators.LIBXML)
    || moduleResolver(SchemaValidators.XMLLINT);

  const xsd = 'saml-schema-protocol-2.0.xsd';

  if (selectedValidator === SchemaValidators.JAVAC) {

    // TODO: refactor
    const setSchemaDir = (v: any) => {
      let schemaDir;
      try {
        schemaDir = path.resolve(__dirname, '../schemas');
        fs.accessSync(schemaDir, fs.constants.F_OK);
      } catch (err) {
        // for built-from git folder layout
        try {
          schemaDir = path.resolve(__dirname, '../../schemas');
          fs.accessSync(schemaDir, fs.constants.F_OK);
        } catch (err) {
          //console.warn('Unable to specify schema directory', err);
          // QUESTION should this be swallowed?
          console.error(err);
          throw new Error('ERR_FAILED_FETCH_SCHEMA_FILE');
        }
      }
      v.cwd = schemaDir;
      v.debug = process.env.NODE_ENV === 'test';
      return v;
    };

    const validator = await import (SchemaValidators.JAVAC);
    const mod = setSchemaDir(new validator());

    return {
      validate: (xml: string) => {
        return new Promise((resolve, reject) => {
          mod.validateXML(xml, xsd, (err, result) => {
            if (err) {
              console.error('[ERROR] validateXML', err);
              return reject('ERR_EXCEPTION_VALIDATE_XML');
            }
            if (result.valid) {
              return resolve('SUCCESS_VALIDATE_XML');
            }
            return reject('ERR_INVALID_XML');
          });
        });
      }
    };
  }

  if (selectedValidator === SchemaValidators.LIBXML) {
    const mod = await import (SchemaValidators.LIBXML);
    return {
      validate: (xml: string) => {
        return new Promise((resolve, reject) => {
          // https://github.com/albanm/node-libxml-xsd/issues/11
          process.chdir(path.resolve(__dirname, '../schemas'));
          mod.parseFile(path.resolve(xsd), (err, schema) => {
            if (err) {
              console.error('[ERROR] validateXML', err);
              return reject('ERR_INVALID_XML');
            }
            schema.validate(xml, (techErrors, validationErrors) => {
              if (techErrors !== null || validationErrors !== null) {
                console.error(`this is not a valid saml response with errors: ${validationErrors}`);
                return reject('ERR_EXCEPTION_VALIDATE_XML');
              }
              return resolve('SUCCESS_VALIDATE_XML');
            });
          });
        });
      }
    };
  }

  if (selectedValidator === SchemaValidators.XMLLINT) {

    const mod = await import (SchemaValidators.XMLLINT);

    const schemaPath = (schema: string) => path.resolve(__dirname, `../schemas/${schema}`);

    let schemaProto = fs.readFileSync(schemaPath(xsd), 'utf-8');
    let schemaAssert = fs.readFileSync(schemaPath('saml-schema-assertion-2.0.xsd'), 'utf-8');
    const schemaXmldsig = fs.readFileSync(schemaPath('xmldsig-core-schema.xsd'), 'utf-8');
    let schemaXenc = fs.readFileSync(schemaPath('xenc-schema.xsd'), 'utf-8');

    // file fix for virtual filesystem of emscripten
    schemaProto = schemaProto.replace('saml-schema-assertion-2.0.xsd', 'file_0.xsd');
    schemaProto = schemaProto.replace('xmldsig-core-schema.xsd', 'file_1.xsd');
    schemaAssert = schemaAssert.replace('xmldsig-core-schema.xsd', 'file_1.xsd');
    schemaAssert = schemaAssert.replace('xenc-schema.xsd', 'file_2.xsd');
    schemaXenc = schemaXenc.replace('xmldsig-core-schema.xsd', 'file_1.xsd');

    return {
      validate: (xml: string) => {

        return new Promise((resolve, reject) => {

          const validationResult = mod.validateXML({
            xml: xml,
            schema: [schemaAssert, schemaXmldsig, schemaXenc, schemaProto]
          });

          if (!validationResult.errors) {
            return resolve('SUCCESS_VALIDATE_XML');
          }

          console.error(`this is not a valid saml response with errors: ${validationResult.errors}`);
          return reject('ERR_EXCEPTION_VALIDATE_XML');

        });
      }
    };
  }

  // allow to skip the validate function if it's in development or test mode if no schema validator is provided
  if (process.env.NODE_ENV === 'dev' || process.env.NODE_ENV === 'test') {
    return {
      validate: (_xml: string) => {
        return new Promise((resolve, _reject) => resolve('SKIP_XML_VALIDATION'));
      }
    };
  }

  throw new Error('ERR_UNDEFINED_SCHEMA_VALIDATOR_MODULE');

};

export {
  getValidatorModule
};