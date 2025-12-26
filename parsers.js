function normalizeResult(r) {
  if (!r || typeof r !== 'object') return r;

  // Normalize favicon fields (accept many shapes)
  const faviconUrl = r.favicon_url || r.favicon || r.faviconUrl || r.favicon_image_url || r.favicons?.[0]?.url || null;
  const faviconBase64 = r.favicon_base64 || r.faviconBase64 || r.favicon_data || r.faviconData || null;
  const screenshotBase64 = r.screenshot?.screenshot_base64 || r.screenshot_base64 || r.screenshotBase64 || null;
  const screenshotUrl = r.screenshot?.image_url || r.screenshot_url || r.screenshotUrl || null;

  const favicon_src = faviconUrl
    ? faviconUrl
    : (faviconBase64 ? `data:image/png;base64,${faviconBase64}` : null);

  const screenshot_src = screenshotUrl
    ? screenshotUrl
    : (screenshotBase64 ? `data:image/png;base64,${screenshotBase64}` : null);

  return {
    ...r,
    favicon_url: faviconUrl || null,
    favicon_base64: faviconBase64 || null,
    favicon_src,
    screenshot_src,
  };
}

export function normalizeScanResponse(raw) {
  // If already an array of categories, attempt to normalize nested results
  if (Array.isArray(raw)) return raw.map(cat => ({ ...cat, results: Array.isArray(cat.results) ? cat.results.map(normalizeResult) : cat.results }));

  if (!raw || typeof raw !== 'object') return [];

  // Some n8n flows may return an object with a `categories` field
  if (Array.isArray(raw.categories)) return raw.categories.map(cat => ({ ...cat, results: Array.isArray(cat.results) ? cat.results.map(normalizeResult) : cat.results }));

  // Some flows return { results: [...] } where each result is a category
  if (Array.isArray(raw.results) && raw.results.length > 0 && raw.results[0].verdict) {
    return raw.results.map(cat => ({ ...cat, results: Array.isArray(cat.results) ? cat.results.map(normalizeResult) : cat.results }));
  }

  // If the payload looks like a single category object (verdict, risk_score, results)
  if (raw.verdict || raw.risk_score || Array.isArray(raw.results)) {
    return [
      {
        verdict: raw.verdict || 'UNKNOWN',
        risk_score: raw.risk_score || 0,
        confidence: raw.confidence || 'N/A',
        malicious_count: raw.malicious_count || 0,
        total_engines: raw.total_engines || 0,
        detections: Array.isArray(raw.detections) ? raw.detections : [],
        results: Array.isArray(raw.results) ? raw.results.map(normalizeResult) : (Array.isArray(raw.items) ? raw.items.map(normalizeResult) : []),
        count: raw.count || (Array.isArray(raw.results) ? raw.results.length : 1),
        // preserve raw for any specialized handlers
        _raw: raw
      }
    ];
  }

  // As a fallback: if there are fields that look like a single scan result, wrap them
  if (raw.input_url || raw.domain || raw.ip) {
    return [
      {
        verdict: 'UNKNOWN',
        risk_score: 0,
        confidence: 'N/A',
        malicious_count: 0,
        total_engines: 0,
        detections: [],
        results: [normalizeResult(raw)],
        count: 1,
        _raw: raw
      }
    ];
  }

  // Nothing we recognize — return empty
  return [];
}
