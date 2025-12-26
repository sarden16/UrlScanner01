export function parseVTResult(vtData) {
  // Defensive defaults
  const safe = vtData && typeof vtData === 'object' ? vtData : {};

  const verdict =
    typeof safe.verdict === 'string' ? safe.verdict : 'UNKNOWN';

  const riskScore =
    Number.isFinite(Number(safe.risk_score))
      ? Number(safe.risk_score)
      : 0;

  const maliciousCount =
    Number.isFinite(Number(safe.malicious_count))
      ? Number(safe.malicious_count)
      : 0;

  const totalEngines =
    Number.isFinite(Number(safe.total_engines))
      ? Number(safe.total_engines)
      : 0;

  const confidence =
    typeof safe.confidence === 'string'
      ? safe.confidence
      : riskScore > 70
      ? 'High'
      : riskScore > 30
      ? 'Medium'
      : 'Low';

  const detections = Array.isArray(safe.detections)
    ? safe.detections
    : [];

  return {
    verdict,
    risk_score: riskScore,
    confidence,
    malicious_count: maliciousCount,
    total_engines: totalEngines,
    detections,
    count: 1
  };
}

/**
 * OPTIONAL helper:
 * Quickly check if VT considers the URL malicious
 */
export function isVTMalicious(vtData) {
  if (!vtData) return false;
  return (
    vtData.verdict === 'MALICIOUS' ||
    Number(vtData.malicious_count) > 0
  );
}
