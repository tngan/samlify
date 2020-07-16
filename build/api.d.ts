interface Context extends ValidatorContext {
}
interface ValidatorContext {
    validate?: (xml: string) => Promise<any>;
}
export declare function getContext(): Context;
export declare function setSchemaValidator(params: ValidatorContext): void;
export {};
