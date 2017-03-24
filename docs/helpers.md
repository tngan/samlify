# Helper functions

?> This module does basic validation for request and response, for example signature verfication and decrpytion, the rest is left to the developers. Some useful functions are also exported, this section if for the specification of those functions.


## verifyTime (notBefore: string, notOnOrAfter: string)

Verify whether the response has valid time.

**notBefore: A time instant before which the subject cannot be confirmed. The time value is encoded in UTC**

**notOnOrAfter: A time instant at which the subject can no longer be confirmed. The time value is encoded in UTC**

### Example

```javascript
sp.parseLoginResponse(idp, 'post', req)
.then(parseResult => {
	const { notBefore, notOnOrAfter } = parseResult.extract.conditions;
	const validTimeframe = sp.verifyTime(notBefore, notOnOrAfter);

	if (!validTimeframe) {
		console.error(`Response is expired. ${notBefore} - ${notOnOrAfter}`);
		return res.sendStatus(401);
	} 

	return res.send(parseResult.extract.nameid);
})
.catch(console.err);
```

?> [Reference P.19](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf)
