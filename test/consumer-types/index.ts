/**
 * Compile-time regression guard for issue #636.
 *
 * Node-only consumers compile without `lib.dom` on purpose. @xmldom/xmldom
 * 0.8's typings start with `/// <reference lib="dom" />`, and samlify's
 * public declarations import xmldom, so every program importing samlify
 * silently gained the browser DOM globals (`skipLibCheck` does not stop a
 * `reference lib` directive from loading the library).
 *
 * `yarn test:types` emits samlify's declarations into `types/` and compiles
 * this file with `lib: ["es2020"]`, `types: ["node"]` and `skipLibCheck: false`.
 * The `@ts-expect-error` below fails the build if `lib.dom` sneaks back in,
 * because `document` would then resolve.
 */
import * as samlify from '../../types/index';

samlify.setDOMParserOptions({ locator: false });

// @ts-expect-error -- `document` must not exist without lib.dom
export const leakedDomGlobal = document;
