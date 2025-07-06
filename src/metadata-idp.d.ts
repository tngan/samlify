/**
* @file metadata-idp.ts
* @author tngan
* @desc  Metadata of identity provider
*/
import Metadata, { type MetadataInterface } from './metadata.js';
import type { MetadataIdpConstructor } from './types.js';
export interface IdpMetadataInterface extends MetadataInterface {
}
export default function (meta: MetadataIdpConstructor): IdpMetadata;
export declare class IdpMetadata extends Metadata {
    constructor(meta: MetadataIdpConstructor);
    /**
    * @desc Get the preference whether it wants a signed request
    * @return {boolean} WantAuthnRequestsSigned
    */
    isWantAuthnRequestsSigned(): boolean;
    /**
    * @desc Get the entity endpoint for single sign on service
    * @param  {string} binding      protocol binding (e.g. redirect, post)
    * @return {string/object} location
    */
    getSingleSignOnService(binding: string): string | object;
    /**
     * @desc Get the entity endpoint for single ArtifactResolutionService
     * @param  {string} binding      protocol binding (e.g. redirect, post)
     * @return {string/object} location
     */
    getArtifactResolutionService(binding: string): string | object;
}
//# sourceMappingURL=metadata-idp.d.ts.map