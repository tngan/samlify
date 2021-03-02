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
	type: 'SAMLRequest' | 'SAMLResponse';
}
