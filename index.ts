import IdentityProvider from './src/entity-idp';
import ServiceProvider from './src/entity-sp';
import IdPMetadata from './src/metadata-idp';
import SPMetadata from './src/metadata-sp';
import Utility from './src/utility';
import SamlLib from './src/libsaml';
import * as Constants from './src/urn';

export = {
	// version <= 1.25
	IdentityProvider,
	ServiceProvider,
	IdPMetadata,
	SPMetadata,
	Utility,
	SamlLib,
	Constants,
	// roadmap
	// new name convention in version >= 3.0
};
