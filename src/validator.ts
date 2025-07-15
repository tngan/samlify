// unit is ms
type DriftTolerance = [number, number];

function verifyTime(
    utcNotBefore: string | undefined,
    utcNotOnOrAfter: string | undefined,
    drift: DriftTolerance = [0, 0]
): boolean {
  const now = Date.now();

  // 处理两个时间都缺失的情况
  if (!utcNotBefore && !utcNotOnOrAfter) {
    console.warn('Time validation requested but no time constraints provided');
    return true;
  }

  const [startDrift, endDrift] = drift;

  // 解析时间并转换为时间戳
  const notBefore = utcNotBefore ? new Date(utcNotBefore).getTime() : -Infinity;
  const notOnOrAfter = utcNotOnOrAfter ? new Date(utcNotOnOrAfter).getTime() : Infinity;

  // 应用漂移容忍度
  const adjustedNotBefore = notBefore - startDrift;
  const adjustedNotOnOrAfter = notOnOrAfter + endDrift;

  // 验证时间范围
  return now >= adjustedNotBefore && now < adjustedNotOnOrAfter;
}

export { verifyTime };