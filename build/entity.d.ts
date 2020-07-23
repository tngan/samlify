/// <reference types="node" />
import { IdpMetadata as IdpMetadataConstructor } from "./metadata-idp";
import { SpMetadata as SpMetadataConstructor } from "./metadata-sp";
import { EntitySetting, MetadataIdpConstructor, MetadataSpConstructor } from "./types";
export interface ESamlHttpRequest {
    query?: any;
    body?: any;
    octetString?: string;
}
export interface BindingContext {
    context: string;
    id: string;
}
export interface PostBindingContext extends BindingContext {
    relayState?: string;
    entityEndpoint: string;
    type: string;
}
export interface ParseResult {
    samlContent: string;
    extract: any;
    sigAlg: string;
}
export declare type EntityConstructor = (MetadataIdpConstructor | MetadataSpConstructor) & {
    metadata?: string | Buffer;
};
export default class Entity {
    entitySetting: EntitySetting;
    entityType: string;
    entityMeta: IdpMetadataConstructor | SpMetadataConstructor;
    /**
     * @param entitySetting
     * @param entityType
     */
    constructor(entitySetting: EntityConstructor, entityType: "idp" | "sp");
    /**
     * @desc  Returns the setting of entity
     * @return {object}
     */
    getEntitySetting(): EntitySetting;
    /**
     * @desc  Returns the xml string of entity metadata
     * @return {string}
     */
    getMetadata(): string;
    /**
     * @desc  Exports the entity metadata into specified folder
     * @param  {string} exportFile indicates the file name
     */
    exportMetadata(exportFile: string): void;
    /** * @desc  Verify fields with the one specified in metadata
     * @param  {string/[string]} field is a string or an array of string indicating the field value in SAML message
     * @param  {string} metaField is a string indicating the same field specified in metadata
     * @return {boolean} True/False
     */
    verifyFields(field: string | string[], metaField: string): boolean;
    /** @desc   Generates the logout request for developers to design their own method
     * @param targetEntity
     * @param  {string}   binding       protocol binding
     * @param  {object}   user          current logged user (e.g. user)
     * @param  {string} relayState      the URL to which to redirect the user when logout is complete
     * @param  {function} customTagReplacement     used when developers have their own login response template
     */
    createLogoutRequest(targetEntity: any, binding: any, user: any, relayState?: string, customTagReplacement?: any): BindingContext | PostBindingContext;
    /**
     * @desc  Generates the logout response for developers to design their own method
     * @param target
     * @param  {object} requestInfo                 corresponding request, used to obtain the id
     * @param  {string} relayState                  the URL to which to redirect the user when logout is complete.
     * @param  {string} binding                     protocol binding
     * @param  {function} customTagReplacement                 used when developers have their own login response template
     */
    createLogoutResponse(target: any, requestInfo: any, binding: any, relayState?: string, customTagReplacement?: any): BindingContext | PostBindingContext;
    /**
     * @desc   Validation of the parsed the URL parameters
     * @param from
     * @param  {string}   binding                   protocol binding
     * @param request
     * @return {Promise}
     */
    parseLogoutRequest(from: any, binding: any, request: ESamlHttpRequest): Promise<import("./flow").FlowResult>;
    /**
     * @desc   Validation of the parsed the URL parameters
     * @param from
     * @param  {string}   binding                   protocol binding
     * @param request
     * @return {Promise}
     */
    parseLogoutResponse(from: any, binding: any, request: ESamlHttpRequest): Promise<import("./flow").FlowResult>;
}
