import React, { useEffect, useRef, useState } from 'react';
import { parseVTResult, isVTMalicious } from './VT.js';
import { fetchScan } from './n8nClient.js';
import { normalizeScanResponse } from './parsers.js';
import { loadHistory, addToHistory, clearHistory, removeHistoryItem } from './storage.js';
import { parseWhoisData } from './whoisUtils.js';
import { decideVerdict } from './verdict.js';

function isValidUrl(value) {
  try {
    const u = new URL(value.trim());
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch {
    return false;
  }
}

// Ensure the URL has a protocol; default to http if missing
function ensureProtocol(value) {
  if (!value || typeof value !== 'string') return value;
  const v = value.trim();
  if (/^https?:\/\//i.test(v)) return v;
  return `http://${v}`;
}

function CollapsibleSection({ title, icon, children }) {
  const [isOpen, setIsOpen] = useState(false);

  return (
    <div className="collapsible-section">
      <button 
        type="button"
        className="collapsible-header" 
        onClick={() => setIsOpen(!isOpen)}
        aria-expanded={isOpen}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span style={{ fontSize: '1.2rem' }}>{icon}</span>
          <span style={{ fontWeight: 600, color: '#374151', fontSize: '1rem' }}>{title}</span>
        </div>
        <span className="chevron" style={{ 
          transform: isOpen ? 'rotate(180deg)' : 'rotate(0deg)' 
        }}>
          ▼
        </span>
      </button>
      <div className={`collapsible-content ${isOpen ? 'open' : ''}`} aria-hidden={!isOpen}>
        <div className="collapsible-inner">
          {children}
        </div>
      </div>
    </div>
  );
}

function UrlScanner() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [shownScreenshots, setShownScreenshots] = useState({});
  const [expandedCategories, setExpandedCategories] = useState({});
  const [modalImage, setModalImage] = useState(null);


  const resultRef = useRef(null);

  function toggleScreenshot(key) {
    setShownScreenshots((s) => ({ ...s, [key]: !s[key] }));
  }

  function toggleCategory(key) {
    setExpandedCategories((s) => ({ ...s, [key]: !s[key] }));
  }

  // Load history on mount
  useEffect(() => {
    setHistory(loadHistory());
  }, []);

  const handleScan = async (e) => {
    e.preventDefault();
    setError('');
    setResult(null);

    if (!isValidUrl(url)) {
      setError('Please enter a valid http/https URL.');
      return;
    }

    setLoading(true);

    try {
      // normalize URL (add protocol if missing) and reflect back in the input
      const normalizedUrl = ensureProtocol(url);
      if (normalizedUrl !== url) setUrl(normalizedUrl);

      if (!isValidUrl(normalizedUrl)) {
        setError('Please enter a valid http/https URL.');
        return;
      }

      const data = await fetchScan(normalizedUrl);
      let normalized = normalizeScanResponse(data);

      // Apply heuristics to determine the final verdict
      normalized = decideVerdict(normalized);

      setResult(normalized);
      
      // Initialize screenshot visibility
      setShownScreenshots(() => {
        const map = {};
        if (Array.isArray(normalized) && normalized.length > 0 && 
            Array.isArray(normalized[0].results) && normalized[0].results.length > 0) {
          map[`0-0`] = true;
        }
        return map;
      });

      // Expand first category by default
      setExpandedCategories(() => ({ 0: true }));

      // Add to history using storage module
      const updatedHistory = addToHistory(normalizedUrl || url, normalized);
      setHistory(updatedHistory);

      requestAnimationFrame(() => resultRef.current?.focus());
    } catch (err) {
      setError(err.message || 'Scan failed');

    } finally {

      setLoading(false);

    }

  };




  const handleClearHistory = () => {
    if (window.confirm('Are you sure you want to clear all scan history?')) {
      clearHistory();
      setHistory([]);
    }
  };

  const handleRemoveHistoryItem = (index) => {
    const updatedHistory = removeHistoryItem(index);
    setHistory(updatedHistory);
  };

  const getVerdictStyle = (verdict) => {
    switch(verdict?.toUpperCase()) {
      case 'CLEAN':
        return { background: '#d1fae5', color: '#065f46', border: '2px solid #10b981' };
      case 'SUSPICIOUS':
        return { background: '#fef3c7', color: '#92400e', border: '2px solid #f59e0b' };
      case 'MALICIOUS':
        return { background: '#fee2e2', color: '#991b1b', border: '2px solid #ef4444' };
      default:
        return { background: '#f3f4f6', color: '#374151', border: '2px solid #9ca3af' };
    }
  };

  return (
    <div className="scanner-container" style={{ maxWidth: '1400px', width: '95%', margin: '0 auto' }}>
      <h1>🔒 URL Security Scanner</h1>

      <form className="url-form" onSubmit={handleScan}>
        <input
          className="url-input"
          placeholder="https://example.com"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          disabled={loading}
        />
        <button className="scan-button" disabled={loading}>
          {loading ? 'Scanning…' : 'Scan URL'}
        </button>

        {/* Reset button to clear form and UI state */}
        <button
          type="button"
          className="scan-button"
          onClick={() => {
            setUrl('');
            setResult(null);
            setError('');
            setShownScreenshots({});
            setExpandedCategories({});
            requestAnimationFrame(() => resultRef.current?.focus());
          }}
          style={{ marginLeft: 8 }}
          disabled={loading}
        >
          Reset
        </button>
      </form>

      {error && <div className="error">❌ {error}</div>}

      <div ref={resultRef} tabIndex={-1}>
        {result && (
          <div className="result-card">
            <h2>📊 Scan Results</h2>

            {Array.isArray(result) ? (
              result.map((cat, ci) => {
                const verdictStyle = getVerdictStyle(cat.verdict);
                const isExpanded = expandedCategories[ci];
                const vtRaw = cat.vt || cat.virustotal || cat.vt_data || cat.raw_vt || cat.virus_total || cat.vtResult || cat.vtData;
                const vtParsed = vtRaw ? parseVTResult(vtRaw) : null;
                
                const firstResult = cat.results?.[0];
                const mainScreenshotBase64 = firstResult?.screenshot?.screenshot_base64;
                const mainScreenshotUrl = firstResult?.screenshot?.image_url || 
                  (mainScreenshotBase64 ? `data:image/png;base64,${mainScreenshotBase64}` : null);

                return (
                  <div key={ci} style={{ marginBottom: 20 }}>
                    <div className="result-layout">
                      {/* LEFT COLUMN: Verdict & Details */}
                      <div className="result-main">
                        <div className="verdict-box" style={verdictStyle}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                            <div style={{ fontSize: '1.3rem', fontWeight: 'bold' }}>
                              {cat.verdict === 'CLEAN' && '✅ '}
                              {cat.verdict === 'SUSPICIOUS' && '⚠️ '}
                              {cat.verdict === 'MALICIOUS' && '🚨 '}
                              {cat.verdict || 'UNKNOWN'}
                            </div>
                            <button 
                              className="scan-button" 
                              onClick={() => toggleCategory(ci)}
                              style={{ padding: '8px 16px', fontSize: '0.875rem' }}
                            >
                              {isExpanded ? '▲ Collapse' : '▼ Expand'}
                            </button>
                          </div>

                          <div className="result-grid">
                            <div>
                              <strong>🎯 Risk Score</strong>
                              <div style={{ fontSize: '1.2rem', fontWeight: 'bold' }}>{cat.risk_score || 0}/100</div>
                            </div>
                            <div>
                              <strong>📈 Confidence</strong>
                              <div style={{ fontSize: '1.2rem', fontWeight: 'bold' }}>{cat.confidence || 'N/A'}</div>
                            </div>
                            <div>
                              <strong>🔍 Detections</strong>
                              <div style={{ fontSize: '1.2rem', fontWeight: 'bold' }}>
                                {cat.malicious_count || 0} / {cat.total_engines || 0}
                              </div>
                            </div>
                            <div>
                              <strong>📋 Results</strong>
                              <div style={{ fontSize: '1.2rem', fontWeight: 'bold' }}>
                                {cat.count || cat.results?.length || 0}
                              </div>
                            </div>
                            {vtParsed && (
                              <div>
                                <strong>🛡️ VirusTotal</strong>
                                <div style={{ fontSize: 13, color: '#334155' }}>
                                  <div>Verdict: {vtParsed.verdict} {isVTMalicious(vtRaw) ? '⚠️' : '✅'}</div>
                                  <div>Score: {vtParsed.risk_score} • {vtParsed.malicious_count}/{vtParsed.total_engines}</div>
                                </div>
                              </div>
                            )}
                          </div>

                          {/* Detections List */}
                          {Array.isArray(cat.detections) && cat.detections.length > 0 && (
                            <div style={{ marginTop: 16, padding: 16, background: '#fff1f2', borderRadius: 12 }}>
                              <h3 style={{ color: '#991b1b', marginBottom: 10 }}>⚠️ Threats Detected</h3>
                              <ul style={{ listStyle: 'none', padding: 0 }}>
                                {cat.detections.map((d, i) => (
                                  <li key={i} style={{ padding: '8px 0', borderBottom: '1px solid #fecaca' }}>
                                    <strong>{d.engine}</strong> → {d.result} 
                                    <span style={{ color: '#dc2626', marginLeft: 8 }}>({d.threat_type})</span>
                                  </li>
                                ))}
                              </ul>
                            </div>
                          )}
                        </div>

                        {/* Expanded Details */}
                        {isExpanded && Array.isArray(cat.results) && cat.results.length > 0 && (
                          <>
                            <div className="section-divider" />
                            
                            {cat.results.map((r, ri) => {
                              const key = `${ci}-${ri}`;
                              const faviconBase64 = r.favicon_base64;
                              const faviconSrc = r.favicon_url || 
                                (faviconBase64 ? `data:image/png;base64,${faviconBase64}` : null);

                              return (
                                <div key={key} className="detail-card" style={{ 
                                  marginBottom: 16, 
                                  padding: 20, 
                                  background: '#ffffff',
                                  borderRadius: 12,
                                  border: '1px solid #e5e7eb',
                                  boxShadow: '0 1px 3px rgba(0,0,0,0.1)'
                                }}>
                                  {/* URL Header */}
                                  <div style={{ marginBottom: 16 }}>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                                      {faviconSrc && (
                                        <img src={faviconSrc} alt="favicon" style={{ 
                                          height: 24, 
                                          width: 24, 
                                          borderRadius: 4,
                                          objectFit: 'contain'
                                        }} />
                                      )}
                                      <h3 style={{ margin: 0, fontSize: '1.1rem' }}>
                                        <a 
                                          href={r.input_url} 
                                          target="_blank" 
                                          rel="noreferrer"
                                          style={{ color: '#667eea', textDecoration: 'none' }}
                                        >
                                          🔗 {r.input_url}
                                        </a>
                                      </h3>
                                    </div>
                                  </div>

                                  {/* Domain Information */}
                                  <CollapsibleSection title="Domain Information" icon="🌐">
                                    <div className="result-grid" style={{ marginTop: 0, marginBottom: 16 }}>
                                      <div>
                                        <strong>Domain</strong>
                                        <div style={{ fontFamily: 'monospace', fontSize: '0.9rem' }}>{r.domain || 'N/A'}</div>
                                      </div>
                                      <div>
                                        <strong>IP Address</strong>
                                        <div style={{ fontFamily: 'monospace', fontSize: '0.9rem' }}>{r.ip || 'N/A'}</div>
                                      </div>
                                      <div>
                                        <strong>Favicon</strong>
                                        <div style={{ fontSize: '0.9rem', color: '#334155' }}>
                                          {r.favicon_src ? (
                                            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                                              <img src={r.favicon_src} alt="favicon" style={{ height: 36, width: 36, borderRadius: 6, objectFit: 'contain', border: '1px solid #e5e7eb' }} />
                                              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start' }}>
                                                <small style={{ color: '#64748b' }}>{r.favicon_url ? 'Remote' : 'Embedded'}</small>
                                                <a href={r.favicon_src} target="_blank" rel="noreferrer" style={{ fontSize: 12, color: '#667eea' }}>
                                                  Open
                                                </a>
                                                {r.favicon_src && r.favicon_src.startsWith('data:') && (
                                                  <a href={r.favicon_src} download={`favicon-${r.domain || 'site'}.png`} style={{ fontSize: 12, color: '#10b981', marginTop: 4 }}>
                                                    Download
                                                  </a>
                                                )}
                                              </div>
                                            </div>
                                          ) : (
                                            '—'
                                          )}
                                        </div>
                                      </div>
                                    </div>
                                  </CollapsibleSection>

                                  {/* WHOIS Info */}
                                  {r.whois && (() => {
                                    const w = parseWhoisData(r.whois);
                                    if (!w) return null;
                                    return (
                                      <CollapsibleSection title="WHOIS Information" icon="📋">
                                        <div style={{ 
                                          fontSize: '0.875rem',
                                          background: '#f8fafc',
                                          padding: 12,
                                          borderRadius: 8,
                                          display: 'flex',
                                          flexWrap: 'wrap',
                                          gap: 20,
                                          marginBottom: 16
                                        }}>
                                          <div style={{ flex: 1, minWidth: '200px' }}>
                                            {w.domain && <div style={{ marginBottom: 6 }}><strong>Domain:</strong> {w.domain}</div>}
                                            {w.registrar && <div style={{ marginBottom: 6 }}><strong>Registrar:</strong> {w.registrar}</div>}
                                            {w.registrant?.organization && <div style={{ marginBottom: 6 }}><strong>Organization:</strong> {w.registrant.organization}</div>}
                                            {w.registrant?.country && <div><strong>Country:</strong> {w.registrant.country}</div>}
                                          </div>
                                          <div style={{ flex: 1, minWidth: '200px' }}>
                                            {w.dates.created && <div style={{ marginBottom: 6 }}><strong>Created:</strong> {w.dates.created}</div>}
                                            {w.dates.updated && <div style={{ marginBottom: 6 }}><strong>Updated:</strong> {w.dates.updated}</div>}
                                            {w.dates.expires && <div><strong>Expires:</strong> {w.dates.expires}</div>}
                                          </div>
                                        </div>
                                      </CollapsibleSection>
                                    );
                                  })()}

                                  {/* DNS Info */}
                                  {r.dns && (
                                    <CollapsibleSection title="DNS Records" icon="🖥️">
                                      <div style={{ 
                                        fontSize: '0.875rem',
                                        background: '#f0fdf4',
                                        padding: 12,
                                        borderRadius: 8,
                                        marginBottom: 16
                                      }}>
                                        {r.dns.A && r.dns.A.length > 0 && (
                                          <div style={{ marginBottom: 6 }}>
                                            <strong>A Records:</strong> 
                                            <div style={{ fontFamily: 'monospace', color: '#059669' }}>
                                              {r.dns.A.join(', ')}
                                            </div>
                                          </div>
                                        )}
                                        {r.dns.MX && r.dns.MX.length > 0 && (
                                          <div style={{ marginBottom: 6 }}>
                                            <strong>MX Records:</strong>
                                            <div style={{ fontFamily: 'monospace', color: '#059669' }}>
                                              {r.dns.MX.join(', ')}
                                            </div>
                                          </div>
                                        )}
                                        {r.dns.NS && r.dns.NS.length > 0 && (
                                          <div>
                                            <strong>NS Records:</strong>
                                            <div style={{ fontFamily: 'monospace', color: '#059669' }}>
                                              {r.dns.NS.join(', ')}
                                            </div>
                                          </div>
                                        )}
                                      </div>
                                    </CollapsibleSection>
                                  )}

                                  {/* SSL Info */}
                                  {r.ssl && (
                                    <CollapsibleSection title="SSL Certificate" icon="🔐">
                                      <div style={{ 
                                        fontSize: '0.875rem',
                                        background: '#faf5ff',
                                        padding: 12,
                                        borderRadius: 8,
                                        marginBottom: 16
                                      }}>
                                        {r.ssl.subject?.[0]?.[0]?.[1] && (
                                          <div><strong>Common Name:</strong> {r.ssl.subject[0][0][1]}</div>
                                        )}
                                        {r.ssl.issuer?.[1]?.[0]?.[1] && (
                                          <div><strong>Issuer:</strong> {r.ssl.issuer[1][0][1]}</div>
                                        )}
                                        {r.ssl.notBefore && (
                                          <div><strong>Valid From:</strong> {r.ssl.notBefore}</div>
                                        )}
                                        {r.ssl.notAfter && (
                                          <div><strong>Valid Until:</strong> {r.ssl.notAfter}</div>
                                        )}
                                      </div>
                                    </CollapsibleSection>
                                  )}
                                </div>
                              );
                            })}
                          </>
                        )}
                      </div>

                      {/* RIGHT COLUMN: Sticky Screenshot */}
                      <div className="result-sidebar">
                        {mainScreenshotUrl && (
                          <div className="screenshot-card">
                            <h4 style={{ marginTop: 0, marginBottom: 12, color: '#334155' }}>📸 Website Preview</h4>
                            <img 
                              src={mainScreenshotUrl} 
                              alt="Screenshot" 
                              style={{ 
                                width: '100%', 
                                borderRadius: 8, 
                                border: '1px solid rgba(0,0,0,0.1)',
                                cursor: 'zoom-in',
                                display: 'block',
                                background: '#f8fafc',
                                minHeight: 160,
                                objectFit: 'cover'
                              }}
                              onClick={() => setModalImage(mainScreenshotUrl)}
                            />
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })
            ) : (
              <div className="no-history">No results returned from scan.</div>
            )}
          </div>
        )}
      </div>

      {/* History Section */}
      <div className="history-section">
        <div className="section-divider" />
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
          <h3>📜 Scan History</h3>
          {history.length > 0 && (
            <button
              className="scan-button"
              onClick={handleClearHistory}
              style={{ padding: '6px 12px', fontSize: '0.875rem', background: '#ef4444' }}
            >
              Clear All
            </button>
          )}
        </div>

        {history.length === 0 ? (
          <div className="no-history">No recent scans.</div>
        ) : (
          <div style={{ maxHeight: '300px', overflowY: 'auto' }}>
            {history.map((h, i) => (
              <div key={i} className="history-row" style={{ 
                display: 'flex', 
                gap: 8, 
                marginBottom: 10,
                alignItems: 'center'
              }}>
                <button
                  className="scan-button"
                  onClick={() => {
                    setUrl(h.url);
                    setResult(h.result);
                    setShownScreenshots(() => {
                      const map = {};
                      if (Array.isArray(h.result) && h.result.length > 0 && 
                          Array.isArray(h.result[0].results) && h.result[0].results.length > 0) {
                        map[`0-0`] = true;
                      }
                      return map;
                    });
                    setExpandedCategories(() => ({ 0: true }));
                  }}
                  style={{ flex: 1, textAlign: 'left' }}
                >
                  {h.url}
                </button>
                <small style={{ color: '#64748b', whiteSpace: 'nowrap' }} title={new Date(h.when).toString()}>
                  {new Date(h.when).toLocaleString()}
                </small>
                <button
                  className="scan-button"
                  onClick={() => handleRemoveHistoryItem(i)}
                  style={{ 
                    padding: 0,
                    width: 20,
                    height: 20,
                    minWidth: 20,
                    maxWidth: 20,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontSize: '12px',
                    lineHeight: 1,
                    background: '#ef4444',
                    color: '#fff',
                    borderRadius: '50%',
                    border: 'none',
                    cursor: 'pointer',
                    flexShrink: 0  
                  }}
                  title="Remove this item"
                >
                  ✕
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Image Modal */}
      {modalImage && (
        <div 
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: 'rgba(0,0,0,0.85)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 9999,
            padding: 20,
            cursor: 'zoom-out'
          }}
          onClick={() => setModalImage(null)}
        >
          <img 
            src={modalImage} 
            alt="Full size screenshot" 
            style={{ maxWidth: '100%', maxHeight: '90vh', borderRadius: 8, boxShadow: '0 4px 20px rgba(0,0,0,0.5)', cursor: 'default' }} 
            onClick={(e) => e.stopPropagation()}
          />
        </div>
      )}
    </div>
  );
}

export default UrlScanner;