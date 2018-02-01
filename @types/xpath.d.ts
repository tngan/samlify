declare module "xpath" {
	export interface XPath {
		toString: () => string;
		XML_NAMESPACE_URI: string;
		XMLNS_NAMESPACE_URI: string;
	}
	export function select (e, doc, single?): string | number | boolean | any;
	const _default: { select };
	export default _default;
}
