/**
 * @file Entity.js
 * @author Tony Ngan
 * @desc  An abstraction for identity provider and service provider.
 */
var bindDict = require('./urn').wording.binding,
Utility = require('./Utility'),
namespace = require('./urn').namespace,
nsBinding = namespace.binding,
uuid = require('node-uuid'),
RedirectBinding = require('./RedirectBinding'),
PostBinding = require('./PostBinding'),
wording = require('./urn').wording,
algorithms = wording.algorithms,
SamlLib = require('./SamlLib');

module.exports = function(entitySetting,entityMetaClass,entityMeta){
    /**
    * @desc  Constructor
    * @param {object} entitySetting
    * @param {object} entityMetaClass determine whether the entity is IdentityProvider or ServiceProvider
    * @param {string} entityMeta is the entity metafile path
    */
    function Entity(entitySetting,entityMetaClass,entityMeta){
        this.entitySetting = Utility.applyDefault({
            wantLogoutResponseSigned: false,
            wantLogoutRequestSigned: false,
            allowCreate: false,
            requestSignatureAlgorithm: algorithms.RSA_SHA1,
            generateID: function generateID() {
                return uuid.v4();
            }
        }, entitySetting || {});
        if(entityMeta !== undefined){
            this.entityMeta = require('./'+entityMetaClass)(entityMeta);
        } else {
            this.entityMeta = require('./'+entityMetaClass)(entitySetting);
        }
    }
    /**
     * @desc  getEntityID
     * @return {string} ID of entitiy
     */
    Entity.prototype.getEntityID = function getEntityID(){
        return this.entityMeta.getEntityID();
    };
    /**
    * @desc  Returns the setting of entity
    * @return {object}
    */
    Entity.prototype.getEntitySetting = function getEntitySetting(){
        return this.entitySetting;
    };
    /**
    * @desc  Returns the xml string of entity metadata
    * @return {string}
    */
    Entity.prototype.getMetadata = function getMetadata(){
        return this.entityMeta.getMetadata();
    };
    /**
    * @desc  Exports the entity metadata into specified folder
    * @param  {string} exportFile indicates the file name
    */
    Entity.prototype.exportMetadata = function exportMetadata(exportFile){
        return this.entityMeta.exportMetadata(exportFile);
    };
    /**
    * @desc  Verify fields with the one specified in metadata
    * @param  {string/[string]} field is a string or an array of string indicating the field value in SAML message
    * @param  {string} metaField is a string indicating the same field specified in metadata
    * @return {boolean} True/False
    */
    Entity.prototype.verifyFields = function verifyFields(field,metaField){
        if(typeof field === 'string'){
            return field === metaField;
        } else if (field && field.length > 0){
            var res = true;
            field.forEach(function(_i){
                if(_i != metaField){
                    res = false;
                    return;
                }
            });
            return res;
        }
        return false;
    };
    /**
    * @desc  Verify time stamp
    * @param  {date} notBefore
    * @param  {date} notOnOrAfter
    * @return {boolean}
    */
    Entity.prototype.verifyTime = function verifyTime(notBefore,notOnOrAfter){
        var _now = new Date();
        if(notBefore === undefined && notOnOrAfter === undefined){
            return true; // throw exception todo
        }
        if(notBefore !== undefined && notOnOrAfter === undefined){
            return +new Date(notBefore) <= +_now;
        }
        if(notBefore === undefined && notOnOrAfter !== undefined){
            return _now < new Date(notOnOrAfter);
        }
        return +new Date(notBefore) <= +_now && _now < new Date(notOnOrAfter);
    };
    /**
    * @desc  Validate and parse the request/response with different bindings
    * @param  {object} opts is the options for abstraction
    * @param  {string} binding is the protocol bindings (e.g. redirect, post)
    * @param  {request} req is the http request
    * @param  {Metadata} targetEntityMetadata either IDP metadata or SP metadata
    * @param  {function} parseCallback is the callback function with extracted parameter
    * @return {function} parseCallback
    */
    Entity.prototype.abstractBindingParser = function abstractBindingParser(opts,binding,req,targetEntityMetadata,parseCallback){
        var options = opts || {},
        _parseResult = {},
        _parserFormat = options.parserFormat,
        _parserType = options.parserType,
        _actionType = options.actionType,
        _checkSignature = options.checkSignature === true,
        _entityMeta = this.entityMeta;

        var _supportBindings = [nsBinding.redirect,nsBinding.post];
        if(_actionType == 'login'){
            if(_entityMeta.getAssertionConsumerService){
                var _assertionConsumerService = _entityMeta.getAssertionConsumerService();
                if(_assertionConsumerService !== undefined){
                    _supportBindings =  _entityMeta.getSupportBindings(typeof _assertionConsumerService == 'string' ? [_assertionConsumerService] : _assertionConsumerService);
                }
            }else if(_entityMeta.getSingleSignOnService){
                var _singleSignOnService = _entityMeta.getSingleSignOnService();
                if(_singleSignOnService !== undefined){
                    _supportBindings =  _entityMeta.getSupportBindings(typeof _singleSignOnService == 'string' ? [_singleSignOnService] : _singleSignOnService);
                }
            }
        }else if(_actionType == 'logout'){
            var _singleLogoutServices = _entityMeta.getSingleLogoutService();
            if(_singleLogoutServices !== undefined){
                _supportBindings =  _entityMeta.getSupportBindings(typeof _singleLogoutServices == 'string' ? [_singleLogoutServices] : _singleLogoutServices);
            }
        }

        if(binding == bindDict.redirect && _supportBindings.indexOf(nsBinding[binding]) !== -1){
            var reqQuery = req.query,
            samlContent = reqQuery[_parserType];

            if(samlContent === undefined){
                throw new Error('Bad request');
            }

            var _origRequest = Utility.inflateString(decodeURIComponent(samlContent));

            if(_checkSignature) {
                var sigAlg = reqQuery.SigAlg,
                signature = reqQuery.Signature;
                if(signature && sigAlg){
                    if(SamlLib.verifyMessageSignature(targetEntityMetadata,req._parsedOriginalUrl.query.split('&Signature=')[0],new Buffer(decodeURIComponent(signature),'base64'))) {
                        _parseResult = {
                            samlContent:_origRequest,
                            sigAlg:decodeURIComponent(sigAlg),
                            extract: SamlLib.extractor(_origRequest,_parserFormat)
                        };
                    } else {
                        // Fail to verify message signature
                        throw new Error('Fail to verify message signature');
                    }
                }else{
                    // Missing signature or signature algorithm
                    throw new Error('Missing signature or signature algorithm');
                }

            } else {
                _parseResult = {
                    samlContent:_origRequest,
                    extract: SamlLib.extractor(_origRequest,_parserFormat)
                };
            }

        }else if(binding == bindDict.post && _supportBindings.indexOf(nsBinding[binding]) !== -1){
            // make sure express.bodyParser() has been used
            var _encodedRequest = req.body[_parserType],
            _decodedRequest = Utility.base64Decode(_encodedRequest),
            _issuer = targetEntityMetadata.getEntityID();
            _parseResult = {
                samlContent:_decodedRequest,
                extract: SamlLib.extractor(_decodedRequest,_parserFormat)
            };
            if(_checkSignature) {
                // verify the signature
                if(!SamlLib.verifySignature(_decodedRequest,_parseResult.extract.signature,{cert:targetEntityMetadata})){
                    throw new Error('Incorrect signature');
                }
            }
            if(!this.verifyFields(_parseResult.extract.issuer,_issuer)){
                throw new Error('Incorrect issuer');
            }
        }else{
            // Will support arifact in the next release
            throw new Error('This binding is not support');
        }
        return parseCallback(_parseResult);
    };
    /**
    * @desc   Generates the logout request and callback to developers to design their own method
    * @param  {ServiceProvider} sp                 object of service provider
    * @param  {string}   binding                   protocol binding
    * @param  {object}   user                      current logged user (e.g. req.user)
    * @param  {string} relayState                  the URL to which to redirect the user when logout is complete
    * @param  {function} callback                  developers do their own request to do with passing information
    * @param  {function} rcallback     used when developers have their own login response template
    */
    Entity.prototype.sendLogoutRequest = function sendLogoutRequest(targetEntity,binding,user,relayState,callback,rcallback){
        var _binding = namespace.binding[binding] || namespace.binding.redirect;
        if(_binding == namespace.binding.redirect){
            return callback(RedirectBinding.logoutRequestRedirectURL(user,{
                init: this,
                target: targetEntity
            },rcallback,relayState));
        }else if(_binding == namespace.binding.post){
            return callback({
                actionValue: PostBinding.base64LogoutRequest(user,SamlLib.createXPath('Issuer'),{
                    init: this,
                    target: targetEntity
                },rcallback),
                relayState: relayState,
                entityEndpoint: targetEntity.entityMeta.getSingleLogoutService(binding),
                actionType: 'LogoutRequest'
            });
        }else{
            // Will support arifact in the next release
            throw new Error('The binding is not support');
        }
    };
    /**
     * @desc  Generates the logout response and callback to developers to design their own method
     * @param  {IdentityProvider} idp               object of identity provider
     * @param  {object} requestInfo                 corresponding request, used to obtain the id
     * @param  {string} relayState                  the URL to which to redirect the user when logout is complete.
     * @param  {string} binding                     protocol binding
     * @param  {function} callback                  developers use their own form submit to do with passing information
     * @param  {function} rcallback                 used when developers have their own login response template
     */
    Entity.prototype.sendLogoutResponse = function sendLogoutResponse(targetEntity,requestInfo,binding,relayState,callback,rcallback){
        var _binding = namespace.binding[binding] || namespace.binding.redirect;
        if(_binding == namespace.binding.redirect){
            return callback(RedirectBinding.logoutResponseRedirectURL(requestInfo,{
                init: this,
                target: targetEntity
            },relayState,rcallback));
        }else if(_binding == namespace.binding.post){
            return callback({
                actionValue: PostBinding.base64LogoutResponse(requestInfo,SamlLib.createXPath('Issuer'),{
                    init: this,
                    target: targetEntity
                },rcallback),
                relayState: relayState,
                entityEndpoint: targetEntity.entityMeta.getSingleLogoutService(binding),
                actionType: 'LogoutResponse'
            });
        }else{
            throw new Error('This binding is not support');
        }
    };
    /**
     * @desc   Validation and callback parsed the URL parameters
     * @param  {IdentityProvider}   idp             object of identity provider
     * @param  {string}   binding                   protocol binding
     * @param  {request}   req                      request
     * @param  {function} parseCallback             developers use their own validation to do with passing information
     */
    Entity.prototype.parseLogoutRequest = function parseLogoutRequest(targetEntity,binding,req,parseCallback){
        return this.abstractBindingParser({
            parserFormat: ['NameID','Issuer',{
                localName: 'Signature',
                extractEntireBody: true
            },{
                localName: 'LogoutRequest',
                attributes: ['ID','Destination']
            }],
            checkSignature: this.entitySetting.wantLogoutRequestSigned,
            parserType: 'LogoutRequest',
            actionType: 'logout'
        },binding,req,targetEntity.entityMeta,parseCallback);
    };
    /**
    * @desc   Validation and callback parsed the URL parameters
    * @param  {string}   binding                   protocol binding
    * @param  {request}   req                      request
    * @param  {ServiceProvider}   sp               object of service provider
    * @param  {function} parseCallback             developers use their own validation to do with passing information
    */
    Entity.prototype.parseLogoutResponse = function parseLogoutResponse(targetEntity,binding,req,parseCallback){
        return this.abstractBindingParser({
            parserFormat: [{
                localName: 'StatusCode',
                attributes: ['Value']
            },'Issuer',{
                localName: 'Signature',
                extractEntireBody: true
            },{
                localName: 'LogoutResponse',
                attributes: ['ID','Destination','InResponseTo']
            }],
            checkSignature: this.entitySetting.wantLogoutResponseSigned,
            supportBindings: ['post'],
            parserType: 'LogoutResponse',
            actionType: 'logout'
        },binding,req,targetEntity.entityMeta,parseCallback);
    };
    /**
    * return a new instance
    */
    return new Entity(entitySetting,entityMetaClass,entityMeta);
};
