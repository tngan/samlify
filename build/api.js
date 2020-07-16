"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.setSchemaValidator = exports.getContext = void 0;
var context = {
    validate: undefined,
};
function getContext() {
    return context;
}
exports.getContext = getContext;
function setSchemaValidator(params) {
    if (typeof params.validate !== "function") {
        throw new Error("validate must be a callback function having one arguemnt as xml input");
    }
    // assign the validate function to the context
    context.validate = params.validate;
}
exports.setSchemaValidator = setSchemaValidator;
//# sourceMappingURL=api.js.map