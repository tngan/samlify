/**
 * @file options.ts
 * @desc Backwards-compatible discriminators for the options-bag /
 * legacy-positional shapes accepted by the create* methods on
 * Entity / IdentityProvider / ServiceProvider.
 *
 * Per `saml-bindings §3.4.3, §3.5.3`, RelayState is request-scoped.
 * These helpers let callers pass it as part of an options bag while
 * preserving the legacy callback-only / string-only positional shapes.
 */
import type {
  CreateLoginRequestOptions,
  CreateLoginResponseOptions,
  CreateLogoutRequestOptions,
  CreateLogoutResponseOptions,
  CustomTagReplacement,
} from './types';

/**
 * Resolve the 3rd-position parameter of `ServiceProvider#createLoginRequest`.
 * Accepts a callback (legacy), an options bag, or undefined.
 */
export function normalizeCreateLoginRequestOptions(
  input: CreateLoginRequestOptions | CustomTagReplacement | undefined,
): CreateLoginRequestOptions {
  if (input == null) return {};
  if (typeof input === 'function') return { customTagReplacement: input };
  return input;
}

/**
 * Resolve the 5th-position parameter of `IdentityProvider#createLoginResponse`.
 * Accepts a callback (legacy), an options bag, or undefined.
 *
 * Legacy positional `encryptThenSign` (6th) and `relayState` (7th) are
 * folded into the bag when the 5th argument is the legacy callback form.
 */
export function normalizeCreateLoginResponseOptions(
  optionsOrCallback: CreateLoginResponseOptions | CustomTagReplacement | undefined,
  legacyEncryptThenSign?: boolean,
  legacyRelayState?: string,
): CreateLoginResponseOptions {
  if (optionsOrCallback == null) {
    return { encryptThenSign: legacyEncryptThenSign, relayState: legacyRelayState };
  }
  if (typeof optionsOrCallback === 'function') {
    return {
      customTagReplacement: optionsOrCallback,
      encryptThenSign: legacyEncryptThenSign,
      relayState: legacyRelayState,
    };
  }
  return optionsOrCallback;
}

/**
 * Resolve the 4th-position parameter of `Entity#createLogoutRequest`.
 * Accepts a string (legacy `relayState`), an options bag, or undefined.
 *
 * Legacy positional `customTagReplacement` (5th) is folded into the bag
 * when the 4th argument is the legacy string form.
 */
export function normalizeCreateLogoutRequestOptions(
  optionsOrRelayState: CreateLogoutRequestOptions | string | undefined,
  legacyCustomTagReplacement?: CustomTagReplacement,
): CreateLogoutRequestOptions {
  if (optionsOrRelayState == null) {
    return { customTagReplacement: legacyCustomTagReplacement };
  }
  if (typeof optionsOrRelayState === 'string') {
    return {
      relayState: optionsOrRelayState,
      customTagReplacement: legacyCustomTagReplacement,
    };
  }
  return optionsOrRelayState;
}

/**
 * Resolve the 4th-position parameter of `Entity#createLogoutResponse`.
 * Same dispatch rules as {@link normalizeCreateLogoutRequestOptions}.
 */
export function normalizeCreateLogoutResponseOptions(
  optionsOrRelayState: CreateLogoutResponseOptions | string | undefined,
  legacyCustomTagReplacement?: CustomTagReplacement,
): CreateLogoutResponseOptions {
  if (optionsOrRelayState == null) {
    return { customTagReplacement: legacyCustomTagReplacement };
  }
  if (typeof optionsOrRelayState === 'string') {
    return {
      relayState: optionsOrRelayState,
      customTagReplacement: legacyCustomTagReplacement,
    };
  }
  return optionsOrRelayState;
}
