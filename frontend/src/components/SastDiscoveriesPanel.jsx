import React, { useState, useEffect } from 'react';

export default function SastDiscoveriesPanel() {
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [isCollapsed, setIsCollapsed] = useState(false);

  // Fetch SAST findings data
  useEffect(() => {
    async function fetchSastFindings() {
      try {
        setLoading(true);
        const response = await fetch('/api/sast/findings');
        const data = await response.json();
        if (data && Array.isArray(data.items)) {
          setFindings(data.items);
        } else {
          setFindings([]);
        }
      } catch (error) {
        console.error('Error fetching SAST findings:', error);
        setFindings([]);
      } finally {
        setLoading(false);
      }
    }
    
    // Initial fetch
    fetchSastFindings();
    
    // Set up polling interval
    const interval = setInterval(fetchSastFindings, 10000);
    
    // Clean up on component unmount
    return () => clearInterval(interval);
  }, []);

  // Format timestamp
  const formatTime = (timestamp) => {
    if (!timestamp) return '';
    try {
      return new Date(timestamp).toLocaleTimeString();
    } catch {
      return '';
    }
  };
  
  // Severity class helper
  const sevClass = (sev) => {
    const s = String(sev || '').toUpperCase();
    if (s === 'CRITICAL') return 'sev sev-critical';
    if (s === 'HIGH') return 'sev sev-high';
    if (s === 'MEDIUM') return 'sev sev-medium';
    if (s === 'LOW') return 'sev sev-low';
    return 'sev';
  };
  
  // Truncate text for display
  const truncate = (text, maxLength = 50) => {
    if (!text || text.length <= maxLength) return text;
    return text.substring(0, maxLength) + '...';
  };
  
  // Handle clicking on a finding
  const handleFindingClick = (finding) => {
    setSelectedFinding(finding);
  };
  
  // Close the details modal
  const closeDetails = () => {
    setSelectedFinding(null);
  };

  // Display the grid layout for rows
  const rowStyle = { display: 'grid', gridTemplateColumns: '1fr 1fr auto', alignItems: 'baseline', gap: 8 };
  
  return (
    <div className="card">
      <div className="card-title" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span>SAST Discoveries {loading ? '(loading...)' : ''}</span>
        <button className="btn btn-sm" onClick={() => setIsCollapsed(!isCollapsed)}>
          {isCollapsed ? 'Expand' : 'Collapse'}
        </button>
      </div>
      {!isCollapsed && (
        <div className="card-body" style={{ maxHeight: '300px', overflowY: 'auto' }}>
          {findings.length > 0 ? (
            <ul className="list">
              <li style={{ ...rowStyle, fontWeight: 600, opacity: 0.8 }}>
                <div>Vulnerability</div>
                <div>URL</div>
                <div>Severity</div>
              </li>
              {findings.map((finding, index) => (
                <li key={index}>
                  <div style={rowStyle}>
                    <div style={{ fontWeight: 600 }}>
                      <span 
                        style={{ cursor: 'pointer', textDecoration: 'underline' }}
                        onClick={() => handleFindingClick(finding)} 
                        title="Open details"
                      >
                        {finding.cveId || finding.type || 'Unknown'}
                      </span>
                      <span style={{ marginLeft: 8, opacity: 0.8 }}>({finding.tech || 'Unknown'})</span>
                    </div>
                    <div style={{ opacity: 0.9 }} title={finding.url}>{truncate(finding.url)}</div>
                    <div className={sevClass(finding.severity)}>{finding.severity || '—'}</div>
                  </div>
                  <div 
                    style={{ marginTop: 4, opacity: 0.9, cursor: 'pointer' }}
                    onClick={() => handleFindingClick(finding)}
                    title="Open details"
                  >
                    {finding.title || ''}
                  </div>
                </li>
              ))}
            </ul>
          ) : (
            <div style={{ opacity: 0.7 }}>No SAST findings detected yet.</div>
          )}
        </div>
      )}

      {/* Details modal */}
      {selectedFinding && (
        <div className="details-overlay" onClick={closeDetails}>
          <div className="details-panel" onClick={e => e.stopPropagation()}>
            <div className="details-header">
              <div style={{ fontWeight: 600 }}>SAST Finding Details</div>
              <button className="btn" onClick={closeDetails}>Close</button>
            </div>
            <div className="details-body">
              <div className="kv"><span className="k">ID</span><span className="v">{selectedFinding.cveId || selectedFinding.type || 'Unknown'}</span></div>
              <div className="kv"><span className="k">Title</span><span className="v wrap">{selectedFinding.title || ''}</span></div>
              <div className="kv"><span className="k">Tech</span><span className="v">{selectedFinding.tech || 'Unknown'}</span></div>
              <div className="kv"><span className="k">URL</span><span className="v wrap">{selectedFinding.url || '—'}</span></div>
              <div className="kv"><span className="k">Severity</span><span className="v">{selectedFinding.severity || '—'}</span></div>
              <div className="kv"><span className="k">Method</span><span className="v">{selectedFinding.method || '—'}</span></div>
              <div className="kv"><span className="k">Timestamp</span><span className="v">{formatTime(selectedFinding.at) || '—'}</span></div>
              
              <div className="section">
                <div className="section-title">Code Context</div>
                <pre className="pre" style={{ whiteSpace: 'pre-wrap' }}>{selectedFinding.indicator || '—'}</pre>
              </div>
              
              <div className="section">
                <div className="section-title">Recommendation</div>
                <div>
                  {selectedFinding.cveId === '[SAST-XSS-INNERHTML]' && (
                    <p>Avoid using innerHTML with untrusted data. Use textContent or create DOM elements properly.</p>
                  )}
                  {selectedFinding.cveId === '[SAST-XSS-FORM]' && (
                    <p>Sanitize input before rendering it in form fields. Use proper encoding methods.</p>
                  )}
                  {selectedFinding.cveId === '[SAST-MISSING-CSP]' && (
                    <p>Implement a Content Security Policy to protect against XSS attacks. Add appropriate headers or meta tags.</p>
                  )}
                  {selectedFinding.cveId === '[SAST-EVAL]' && (
                    <p>Avoid using eval() which can lead to code injection. Use safer alternatives.</p>
                  )}
                  {selectedFinding.cveId === '[SAST-DOCUMENT-WRITE]' && (
                    <p>Avoid using document.write() which can lead to XSS. Manipulate the DOM safely using proper DOM methods.</p>
                  )}
                  {selectedFinding.cveId === '[SAST-DOM-XSS]' && (
                    <p>Sanitize user-controlled input (like URL parameters) before inserting into the DOM. Use DOMPurify or similar libraries.</p>
                  )}
                  {selectedFinding.cveId === '[SAST-JQUERY-XSS]' && (
                    <p>When using jQuery with user-controlled input, ensure the data is sanitized before insertion into the DOM.</p>
                  )}
                  {selectedFinding.cveId === '[SAST-SETTIMEOUT]' || selectedFinding.cveId === '[SAST-SETINTERVAL]' && (
                    <p>Avoid passing strings to setTimeout or setInterval. Use function references instead.</p>
                  )}
                  {selectedFinding.cveId === '[SAST-FUNCTION-CONSTRUCTOR]' && (
                    <p>Avoid using the Function constructor which can lead to code injection. Use regular functions instead.</p>
                  )}
                  {selectedFinding.cveId === '[SAST-LOCALSTORAGE]' || selectedFinding.cveId === '[SAST-SESSIONSTORAGE]' && (
                    <p>Sanitize data from localStorage/sessionStorage before using it in DOM operations.</p>
                  )}
                  {selectedFinding.cveId === '[SAST-HARDCODED-CREDENTIALS]' && (
                    <p>Avoid hardcoded credentials in source code. Use environment variables or secure credential management.</p>
                  )}
                  {selectedFinding.cveId === '[SAST-SQL-INJECTION]' && (
                    <p>Use parameterized queries or prepared statements to prevent SQL injection.</p>
                  )}
                  {selectedFinding.cveId === '[SAST-WEAK-CRYPTO]' && (
                    <p>Avoid using weak cryptographic algorithms. Use modern algorithms like SHA-256, SHA-3, or AES.</p>
                  )}
                  {/* Default recommendation if none of the specific ones match */}
                  {!selectedFinding.cveId.startsWith('[SAST-') && (
                    <p>Review the code for security issues and follow secure coding practices.</p>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}