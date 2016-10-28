/**
* express-saml2
* Copyright(c) 2015-2016 tngan
* MIT
*/
import IdentityProvider from './src/entity-idp';
import ServiceProvider from './src/entity-sp';
import IdPMetadata from './src/metadata-idp';
import SPMetadata from './src/metadata-sp';
import Utility from './src/utility';
import SamlLib from './src/libsaml';
import * as Constants from './src/urn';

export default {
	// version <= 1.25
	IdentityProvider,
	ServiceProvider,
	IdPMetadata,
	SPMetadata,
	Utility,
	SamlLib,
	Constants,
	// new name convention
	// pending version >= 3.0
};
