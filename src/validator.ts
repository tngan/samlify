function verifyTime(utcNotBefore?: string, utcNotOnOrAfter?: string): boolean {

  const now = new Date();
  if (!utcNotBefore && !utcNotOnOrAfter) {
    return true; // throw exception todo
  }

  let notBeforeLocal = null;
  let notOnOrAfterLocal = null;

  if (utcNotBefore && !utcNotOnOrAfter) {
    notBeforeLocal = new Date(utcNotBefore);
    return +notBeforeLocal <= +now;
  }
  if (!utcNotBefore && utcNotOnOrAfter) {
    notOnOrAfterLocal = new Date(utcNotOnOrAfter);
    return now < notOnOrAfterLocal;
  }

  notBeforeLocal = new Date(utcNotBefore);
  notOnOrAfterLocal = new Date(utcNotOnOrAfter);
  return +notBeforeLocal <= +now && now < notOnOrAfterLocal;
}

export {
  verifyTime,
};
