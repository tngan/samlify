/**
 * @file validator.ts
 * @author tngan
 * @desc Time-window validators for SAML `NotBefore` / `NotOnOrAfter` conditions.
 */

/** Signed clock-drift tolerance in milliseconds for the two boundaries. */
type DriftTolerance = [number, number];

/**
 * Check whether the current clock falls within the provided SAML time
 * window, applying a symmetric drift tolerance to both ends.
 *
 * Behaviour:
 *   - Both bounds missing: logs a warning and returns `true`.
 *   - Only `utcNotBefore` given: returns true when now is at or after it.
 *   - Only `utcNotOnOrAfter` given: returns true when now is strictly before it.
 *   - Both given: returns true only when both individual checks pass.
 *
 * @param utcNotBefore ISO-8601 lower bound (inclusive) or undefined
 * @param utcNotOnOrAfter ISO-8601 upper bound (exclusive) or undefined
 * @param drift tolerance applied to each bound, defaults to `[0, 0]`
 * @returns whether the current time is within the configured window
 */
function verifyTime(
  utcNotBefore: string | undefined,
  utcNotOnOrAfter: string | undefined,
  drift: DriftTolerance = [0, 0],
): boolean {
  const now = new Date();

  if (!utcNotBefore && !utcNotOnOrAfter) {
    console.warn("You intend to have time validation however the document doesn't include the valid range.");
    return true;
  }

  const [notBeforeDrift, notOnOrAfterDrift] = drift;

  if (utcNotBefore && !utcNotOnOrAfter) {
    const notBeforeLocal = new Date(utcNotBefore);
    return +notBeforeLocal + notBeforeDrift <= +now;
  }
  if (!utcNotBefore && utcNotOnOrAfter) {
    const notOnOrAfterLocal = new Date(utcNotOnOrAfter);
    return +now < +notOnOrAfterLocal + notOnOrAfterDrift;
  }

  const notBeforeLocal = new Date(utcNotBefore!);
  const notOnOrAfterLocal = new Date(utcNotOnOrAfter!);

  return (
    +notBeforeLocal + notBeforeDrift <= +now &&
    +now < +notOnOrAfterLocal + notOnOrAfterDrift
  );
}

export { verifyTime };
