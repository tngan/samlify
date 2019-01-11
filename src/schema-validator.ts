import * as fs from 'fs';
import * as path from 'path';

enum SchemaValidators {
  JAVAC = '@passify/xsd-schema-validator',
  LIBXML = 'libxmljs-mt'
}

interface SchemaValidator {
  validate: (xml: string, xsd: string) => Promise<string>;
}

type GetValidatorModuleSpec = () => Promise<SchemaValidator>;

const getValidatorModule: GetValidatorModuleSpec = async () => {

  if (require.resolve(SchemaValidators.JAVAC)) {

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
      validate: (xml: string, xsd: string) => {
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

  if (require.resolve(SchemaValidators.LIBXML)) {
    const validator = await import (SchemaValidators.LIBXML);
    const mod = new validator();
    return {
      validate: (xml: string, xsd: string) => {
        return new Promise((resolve, reject) => {
          const xsdContext = fs.readFileSync(`../schemas/${xsd}`).toString();
          const xmlDoc = mod.parseXml(xml);
          const xsdDoc = mod.parseXml(xsdContext);
          const result = xmlDoc.validate(xsdDoc);
          if (result) {
            return resolve('SUCCESS_VALIDATE_XML');
          } 
          console.error('[ERROR] validateXML', xmlDoc.validationErrors);
          return reject('ERR_EXCEPTION_VALIDATE_XML');
        });
      }
    };
  }

  throw new Error('ERR_UNDEFINED_SCHEMA_VALIDATOR_MODULE');

};

export {
  getValidatorModule
};