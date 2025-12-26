/**
 * Applies heuristics to determine the final verdict (CLEAN, SUSPICIOUS, or MALICIOUS)
 * based on scan results from various engines and sources
 */
export function decideVerdict(normalized) {
  if (!Array.isArray(normalized)) {
    return normalized;
  }

  return normalized.map(category => {
    let verdict = 'CLEAN';
    let riskScore = 0;
    let maliciousCount = 0;
    let totalEngines = 0;

    // Count detections from results
    if (Array.isArray(category.results) && category.results.length > 0) {
      category.results.forEach(result => {
        // Check for malicious indicators in result
        if (result.risk_score && result.risk_score > 50) {
          maliciousCount++;
        }
      });
    }

    // Check detections array
    if (Array.isArray(category.detections) && category.detections.length > 0) {
      const detectionCount = category.detections.length;
      maliciousCount += detectionCount;
      totalEngines = Math.max(totalEngines, 70); // Assume ~70 engines for VT
    }

    // Use existing counts if available
    if (category.malicious_count !== undefined) {
      maliciousCount = category.malicious_count;
    }
    if (category.total_engines !== undefined) {
      totalEngines = category.total_engines;
    }

    // Calculate risk score based on detections
    if (totalEngines > 0) {
      riskScore = Math.round((maliciousCount / totalEngines) * 100);
    } else if (category.risk_score) {
      riskScore = category.risk_score;
    }

    // Determine verdict based on heuristics
    if (riskScore >= 70 || maliciousCount >= 10) {
      verdict = 'MALICIOUS';
    } else if (riskScore >= 40 || maliciousCount >= 3) {
      verdict = 'SUSPICIOUS';
    } else {
      verdict = 'CLEAN';
    }

    // Override with existing verdict if it's more severe
    if (category.verdict) {
      const verdictRank = { 'MALICIOUS': 3, 'SUSPICIOUS': 2, 'CLEAN': 1 };
      const currentRank = verdictRank[category.verdict] || 0;
      const calculatedRank = verdictRank[verdict] || 0;
      if (currentRank > calculatedRank) {
        verdict = category.verdict;
      }
    }

    return {
      ...category,
      verdict,
      risk_score: category.risk_score !== undefined ? category.risk_score : riskScore,
      malicious_count: maliciousCount,
      total_engines: totalEngines || 1
    };
  });
}