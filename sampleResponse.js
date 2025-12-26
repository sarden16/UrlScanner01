export const SAMPLE_RESPONSE = [
  {
    verdict: 'SUSPICIOUS',
    risk_score: 66,
    confidence: 'Medium',
    malicious_count: 2,
    total_engines: 60,
    detections: [
      { engine: 'AV-Test', result: 'suspicious', threat_type: 'phishing' },
      { engine: 'MalDetect', result: 'malicious', threat_type: 'malware' }
    ],
    results: [
      {
        input_url: 'https://example-bad.com',
        domain: 'example-bad.com',
        ip: '198.51.100.42',
        whois: { registrar: 'BadRegistrar', org: 'BadCo', country: 'US', creation_date: ['2024-01-01'] },
        dns: { A: ['198.51.100.42'], MX: [], NS: ['ns1.bad.com'] },
        ssl: { subject: [['CN', 'example-bad.com']], issuer: [["C","Fake CA"]], notBefore: '2024-01-01', notAfter: '2025-01-01' },
        favicon_url: null,
        screenshot: { image_url: null }
      }
    ],
    count: 1
  }
];
