/**
 * @file api.ts
 * @author tngan
 * @desc Global module configuration: XML schema validator and DOM parser.
 */
import { DOMParser as Dom, DOMParserOptions } from '@xmldom/xmldom';

/** Module-wide runtime configuration. */
interface Context extends ValidatorContext, DOMParserContext {}

/** Caller-supplied SAML XML schema validator. */
interface ValidatorContext {
  validate?: (xml: string) => Promise<unknown>;
}

/** DOM parser used to decode SAML messages. */
interface DOMParserContext {
  dom: Dom;
}

type ErrorHandler = NonNullable<DOMParserOptions['onError']>;
type ErrorLevel = Parameters<ErrorHandler>[0];

/**
 * Pre-0.9 xmldom `errorHandler` object form. xmldom 0.9 throws a
 * `TypeError` when it receives this shape, so samlify converts it to an
 * `onError` callback to keep existing `setDOMParserOptions` callers working.
 */
type LegacyErrorHandler = Partial<Record<ErrorLevel, (msg: string) => void>>;

/** Options accepted by `setDOMParserOptions`. */
type ParserOptions = Omit<DOMParserOptions, 'errorHandler'> & {
  errorHandler?: ErrorHandler | LegacyErrorHandler;
};

/**
 * Treat XML parsing errors as fatal to prevent XXE attacks.
 * Entity references (e.g. &xxe;) and malformed XML in SAML messages
 * are not expected and may indicate an attack attempt.
 */
const xxeSafeOnError: ErrorHandler = (level, msg) => {
  if (level === 'error') {
    throw new Error(`XML parsing error: ${msg}`);
  }
  if (level === 'fatalError') {
    throw new Error(`XML fatal error: ${msg}`);
  }
  console.warn(`[xmldom warning] ${msg}`);
};

/**
 * Resolve the error callback for a caller's options: an explicit `onError`
 * wins, then the deprecated `errorHandler` (function or legacy object),
 * otherwise the XXE-safe default.
 */
function resolveOnError({ onError, errorHandler }: ParserOptions): ErrorHandler {
  if (onError) {
    return onError;
  }
  if (typeof errorHandler === 'function') {
    return errorHandler;
  }
  if (errorHandler) {
    return (level, msg) => {
      const handler = errorHandler[level];
      if (handler) {
        handler(msg);
      } else if (level !== 'warning') {
        // Levels the legacy object omits keep failing closed.
        xxeSafeOnError(level, msg, undefined);
      }
    };
  }
  return xxeSafeOnError;
}

const context: Context = {
  validate: undefined,
  dom: new Dom({ onError: xxeSafeOnError }),
};

/**
 * Return the module-wide runtime context (DOM parser and validator).
 *
 * @returns shared context object
 */
export function getContext(): Context {
  return context;
}

/**
 * Register the caller-supplied SAML schema validator. Throws when the
 * supplied value does not expose a `validate` callback.
 *
 * @param params object with a `validate(xml)` callback
 */
export function setSchemaValidator(params: ValidatorContext): void {
  if (typeof params.validate !== 'function') {
    throw new Error('validate must be a callback function having one argument as xml input');
  }
  context.validate = params.validate;
}

/**
 * Replace the module-wide DOM parser with one configured by the caller.
 *
 * The XXE-safe error callback is applied as a baseline so callers can
 * override unrelated settings without accidentally disabling XXE
 * protection (`saml-core §6.4`, `saml-sec-consider §6.3.1`). A caller can
 * still opt out by passing its own `onError` (or the deprecated
 * `errorHandler`), but it must do so explicitly.
 *
 * @param options xmldom parser options
 */
export function setDOMParserOptions(options: ParserOptions = {}): void {
  const { errorHandler, ...rest } = options;
  context.dom = new Dom({
    ...rest,
    onError: resolveOnError(options),
  });
}
