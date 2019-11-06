function verifyTime(utcNotBefore?: string, utcNotOnOrAfter?: string): boolean {

  const now = new Date();
  if (!utcNotBefore && !utcNotOnOrAfter) {
    return true; // throw exception todo
  }

  let notBeforeLocal: Date | null = null;
  let notOnOrAfterLocal: Date | null = null;

  if (utcNotBefore && !utcNotOnOrAfter) {
    notBeforeLocal = new Date(utcNotBefore);
    return +notBeforeLocal <= +now;
  }
  if (!utcNotBefore && utcNotOnOrAfter) {
    notOnOrAfterLocal = new Date(utcNotOnOrAfter);
    return now < notOnOrAfterLocal;
  }

  notBeforeLocal = new Date(utcNotBefore!);
  notOnOrAfterLocal = new Date(utcNotOnOrAfter!);

  //Here setting time diff b/w notBeforeLocal and now can be greater than -5 seconds. This comes in the scenario when there is a mismatch of time between sp and idp server timings which result in ERR_SUBJECT_VALIDATION error
  return +now - +notBeforeLocal > -5000  && now < notOnOrAfterLocal;
}

export {
  verifyTime,
};
