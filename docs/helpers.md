# Helper functions

?> This module does basic validation for request and response, for example signature verfication and decrpytion, the rest is left to the developers. Some useful functions are also exported, this section if for the specification of those functions.

#### verifyTime (notBefore, notOnOrAfter): Boolean

Verify whether the response has valid time.

**notBefore: String**<br/>
A time instant before which the subject cannot be confirmed. The time value is encoded in UTC.

**notOnOrAfter: String**<br/>
A time instant at which the subject can no longer be confirmed. The time value is encoded in UTC.

**drift: [Number, Number]**<br/>
A time range allowing for drifting the range that specified in the SAML document. The first one is for the `notBefore` time and the second one is for `notOnOrAfter`. Default value of both drift value is `0`. The unit is in `ms`.

For example, if you set `[-5000, 3000]`. The value can be either positive or negative in order to take care of the flexibility.

```console
# tolerated timeline
notBefore - 5s >>>>>>> notBefore >>>>>>> notAfter ---- notAfter + 3s 

# new valid time
notBefore - 5s >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> notAfter + 3s 
```

Another example, if you don't set, the default drift tolerance is `[0, 0]`. The valid range is trivial.

```console
# valid time
notBefore >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> notAfter
```

#### Example

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
