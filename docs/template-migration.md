# Migrating to the strict template renderer

samlify builds every SAML message by filling `{Tag}` placeholders in an XML
template. Since 2.15 there are two engines:

| | `legacy` (default until v3) | `strict` |
|---|---|---|
| Function | `SamlLib.replaceTagsByValue` *(deprecated)* | `SamlLib.renderTemplate` |
| Entity setting | `templateRenderer: 'legacy'` | `templateRenderer: 'strict'` |
| How placeholders are found | String matching | A single-pass XML lexer that knows whether each placeholder is in an attribute value or in text |
| Placeholders in element / attribute names, end tags, comments, CDATA, processing instructions | Substituted | Rejected (`ERR_TEMPLATE_PLACEHOLDER_POSITION`) |
| Malformed tags (unquoted or unterminated attribute values) | Rendered as-is | Rejected (`ERR_TEMPLATE_MALFORMED`) |
| Value escaping | XML-escaped | XML-escaped |
| Values scanned again for placeholders | No (since 2.15) | No |
| Output for a valid template | — | Identical to `legacy` |

Both engines escape every value, and since 2.15 the legacy engine is
hardened as well:
- Values are inserted in a single pass.
- Tag names are matched literally, never as regular expressions.
- `{` and `}` in values are written as `&#123;` / `&#125;`. XML parsers and
  canonicalization read these as the same characters.
- Attribute metadata (`name`, `nameFormat`, `valueXsiType`, `valueXmlnsXs`,
  `valueXmlnsXsi`) is escaped.

The strict engine adds structural guarantees: a value can only ever become
the content of the attribute value or text node its placeholder sits in, and
a template that puts a placeholder anywhere else fails loudly instead of
producing unexpected XML.

`replaceTagsByValue` is deprecated and will be removed in v3, when `strict`
becomes the default.

## 1. Switch the built-in rendering

Set `templateRenderer` on each entity that builds messages:

```javascript
const sp = ServiceProvider({
  // ...
  templateRenderer: 'strict', // AuthnRequest, LogoutRequest, LogoutResponse
});

const idp = IdentityProvider({
  // ...
  templateRenderer: 'strict', // Response (incl. AttributeStatement), LogoutRequest, LogoutResponse
});
```

The setting applies to the default templates, to your custom templates
(`loginRequestTemplate`, `loginResponseTemplate`, `logoutRequestTemplate`,
`logoutResponseTemplate`), and to the attribute templates
(`loginResponseTemplate.additionalTemplates`).

## 2. Switch your `customTagReplacement` callbacks

If you render templates yourself, replace `replaceTagsByValue` with
`renderTemplate`. Its arguments and return value are the same:

```javascript
const { SamlLib } = require('samlify');

// Before
idp.createLoginResponse(sp, requestInfo, 'post', user, template => ({
  id,
  context: SamlLib.replaceTagsByValue(template, values),
}));

// After
idp.createLoginResponse(sp, requestInfo, 'post', user, template => ({
  id,
  context: SamlLib.renderTemplate(template, values),
}));
```

`null` and `undefined` behave as before:
- If the placeholder is an attribute's whole value (`Destination="{Destination}"`), the attribute is omitted.
- If the placeholder is an element's only content (`<samlp:SessionIndex>{SessionIndex}</samlp:SessionIndex>`), the element is omitted.
- Anywhere else it renders as an empty string.

A placeholder that has no entry in `values` is left in place.

## 3. Check your templates

Only placeholder **positions** matter. Put placeholders inside attribute
values or in text:

```xml
<!-- OK -->
<saml:Attribute Name="{Name}" NameFormat="{NameFormat}">
  <saml:AttributeValue xsi:type="{ValueXsiType}">{Value}</saml:AttributeValue>
</saml:Attribute>

<!-- Rejected by strict: placeholder in an element / attribute name -->
<saml:{ElementName}/>
<saml:Attribute {AttributeName}="x"/>
```

Templates may be fragments, as attribute templates are, and may use
namespace prefixes declared elsewhere. Placeholders in `xmlns` declarations
(`xmlns:xs="{ValueXmlnsXs}"`) are supported.

To check a template without sending anything, render it once in a test:

```javascript
SamlLib.renderTemplate(myTemplate, {}); // throws if a placeholder is misplaced
```

## 4. Attribute `valueTag`

The placeholder for an attribute value is `attr` plus the camel-cased
`valueTag` (`user.email` → `{attrUserEmail}`). Keep `valueTag` to letters,
digits, `.`, `-`, `_` and spaces. Both engines encode any other character so
that it stays inside one placeholder and can't inject markup. Templates that
use such tags still render, but the strict engine is the one that guarantees
it.

## Error reference

| Error | Meaning |
|---|---|
| `ERR_TEMPLATE_PLACEHOLDER_POSITION` | A placeholder sits outside an attribute value or text (strict only). |
| `ERR_TEMPLATE_MALFORMED` | An attribute value is unquoted or unterminated, or a start tag is unterminated (strict only). |

## Timeline

- **2.15**: `strict` is available and opt-in. `replaceTagsByValue` is hardened and marked deprecated.
- **v3**: `strict` becomes the default and `replaceTagsByValue` is removed.
