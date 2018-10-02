function verifyTime(utcNotBefore?: string, utcNotOnOrAfter?: string): boolean {

  const now = new Date();
  if (!utcNotBefore && !utcNotOnOrAfter) {
    return true; // throw exception todo
  }
  if (utcNotBefore && !utcNotOnOrAfter) {
    const notBeforeLocal = new Date(utcNotBefore);
    return +notBeforeLocal <= +now;
  }
  if (!utcNotBefore && utcNotOnOrAfter) {
    const notOnOrAfterLocal = new Date(utcNotOnOrAfter);
    return now < notOnOrAfterLocal;
  }

  const notBeforeLocal = new Date(utcNotBefore);
  const notOnOrAfterLocal = new Date(utcNotOnOrAfter);
  return +notBeforeLocal <= +now && now < notOnOrAfterLocal;
}

export {
  verifyTime
};