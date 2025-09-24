import React, { useMemo, useState } from 'react'
import { investigateVulnerability, getLlmPrompt } from '../api.js'

export default function VulnerabilitiesPanel({ vulnerabilities = [] }) {
  const items = Array.isArray(vulnerabilities) ? vulnerabilities : []
  const maxShow = 20
  const show = items.slice(0, maxShow)

  const sevClass = (sev) => {
    const s = String(sev || '').toUpperCase()
    if (s === 'CRITICAL') return 'sev sev-critical'
    if (s === 'HIGH') return 'sev sev-high'
    if (s === 'MEDIUM') return 'sev sev-medium'
    if (s === 'LOW') return 'sev sev-low'
    return 'sev'
  }

  const rowStyle = { display: 'grid', gridTemplateColumns: '1fr 1fr auto', alignItems: 'baseline', gap: 8 }

  const makeKey = (v) => `${v.cveId || v.type || ''}::${v.host || ''}::${v.tech || ''}@${v.version || ''}`

  const [openKey, setOpenKey] = useState('')
  const [resultsByKey, setResultsByKey] = useState({}) // key -> { loading, error, data }
  const [promptsByKey, setPromptsByKey] = useState({}) // key -> { loading, error, prompt, customPrompt }

  const openVuln = (v) => setOpenKey(k => (k === makeKey(v) ? '' : makeKey(v)))
  const closePanel = () => setOpenKey('')

  const openItem = useMemo(() => show.find(v => makeKey(v) === openKey) || null, [openKey, show])
  const currentResult = resultsByKey[openKey]
  const currentPrompt = promptsByKey[openKey]

  // Fetch the prompt when an item is opened
  const fetchPrompt = async () => {
    if (!openItem) return
    const key = makeKey(openItem)
    if (promptsByKey[key]?.prompt) return // already have the prompt
    
    setPromptsByKey(prev => ({ ...prev, [key]: { loading: true, error: '', prompt: '', customPrompt: '' } }))
    try {
      const data = await getLlmPrompt({ vulnerability: openItem })
      setPromptsByKey(prev => ({ 
        ...prev, 
        [key]: { 
          loading: false, 
          error: '', 
          prompt: data.prompt,
          customPrompt: data.prompt 
        } 
      }))
    } catch (e) {
      setPromptsByKey(prev => ({ ...prev, [key]: { loading: false, error: e.message || 'Error', prompt: '', customPrompt: '' } }))
    }
  }

  // Fetch prompt when an item is opened
  React.useEffect(() => {
    if (openItem) {
      fetchPrompt()
    }
  }, [openItem])

  const handlePromptChange = (e) => {
    if (!openItem) return
    const key = makeKey(openItem)
    setPromptsByKey(prev => ({ 
      ...prev, 
      [key]: { 
        ...prev[key], 
        customPrompt: e.target.value 
      } 
    }))
  }

  const handleInvestigate = async () => {
    if (!openItem) return
    const key = makeKey(openItem)
    // If we already have data, do not re-fetch
    if (resultsByKey[key]?.data) return
    setResultsByKey(prev => ({ ...prev, [key]: { loading: true, error: '', data: null } }))
    try {
      // Use the custom prompt if available
      const customPrompt = promptsByKey[key]?.customPrompt
      const data = await investigateVulnerability({ 
        vulnerability: openItem,
        customPrompt
      })
      setResultsByKey(prev => ({ ...prev, [key]: { loading: false, error: '', data } }))
    } catch (e) {
      setResultsByKey(prev => ({ ...prev, [key]: { loading: false, error: e.message || 'Error', data: null } }))
    }
  }

  return (
    <div className="card">
      <div className="card-title">Identified Vulnerabilities</div>
      <div className="card-body">
        {show.length ? (
          <ul className="list">
            <li style={{ ...rowStyle, fontWeight: 600, opacity: 0.8 }}>
              <div>Vulnerability</div>
              <div>Host</div>
              <div>Severity</div>
            </li>
            {show.map(v => (
              <li key={`${v.cveId}-${v.tech}-${v.version}-${v.host || ''}`}>
                <div style={rowStyle}>
                  <div style={{ fontWeight: 600 }}>
                    <span style={{ cursor: 'pointer', textDecoration: 'underline' }} onClick={() => openVuln(v)} title="Open details">
                      {v.cveId}
                    </span>
                    <a style={{ marginLeft: 8 }} href={v.url} target="_blank" rel="noreferrer">ref</a>
                    <span style={{ marginLeft: 8, opacity: 0.8 }}>({v.tech} {v.version})</span>
                  </div>
                  <div style={{ opacity: 0.9 }}>{v.host || '—'}</div>
                  <div className={sevClass(v.severity)}>{v.severity || '—'}</div>
                </div>
                <div style={{ marginTop: 4, opacity: 0.9, cursor: 'pointer' }} onClick={() => openVuln(v)} title="Open details">{v.title || ''}</div>
              </li>
            ))}
            {items.length > maxShow && (
              <li style={{ opacity: 0.7 }}>+{items.length - maxShow} more …</li>
            )}
          </ul>
        ) : (
          <div style={{ opacity: 0.7 }}>No vulnerabilities detected yet.</div>
        )}
      </div>

      {openItem && (
        <div className="details-overlay" onClick={closePanel}>
          <div className="details-panel" onClick={e => e.stopPropagation()}>
            <div className="details-header">
              <div style={{ fontWeight: 600 }}>Vulnerability Investigation</div>
              <button className="btn" onClick={closePanel}>Close</button>
            </div>
            <div className="details-body">
              <div className="kv"><span className="k">CVE</span><span className="v">{openItem.cveId || openItem.type}</span></div>
              <div className="kv"><span className="k">Title</span><span className="v wrap">{openItem.title || ''}</span></div>
              <div className="kv"><span className="k">Tech</span><span className="v">{openItem.tech || ''} {openItem.version || ''}</span></div>
              <div className="kv"><span className="k">Host</span><span className="v">{openItem.host || '—'}</span></div>
              <div className="kv"><span className="k">Severity</span><span className="v">{openItem.severity || '—'}</span></div>
              <div className="kv"><span className="k">Reference</span><span className="v"><a href={openItem.url} target="_blank" rel="noreferrer">{openItem.url || '—'}</a></span></div>

              <div className="section">
                <div className="section-title">LLM Prompt</div>
                {currentPrompt?.loading && <div style={{ opacity: 0.8 }}>Loading prompt...</div>}
                {currentPrompt?.error && <div style={{ color: '#f87171' }}>Error loading prompt: {currentPrompt.error}</div>}
                {currentPrompt?.customPrompt && (
                  <textarea 
                    className="pre"
                    style={{ 
                      width: '100%', 
                      minHeight: '100px',
                      maxHeight: '400px',
                      resize: 'vertical',
                      fontFamily: 'monospace', 
                      padding: '8px',
                      marginBottom: '10px',
                      color: '#b5b5b5',
                    }}
                    value={currentPrompt.customPrompt}
                    onChange={handlePromptChange}
                  />
                )}
                <button className="btn" onClick={handleInvestigate} disabled={currentResult?.loading || !currentPrompt?.customPrompt}>Investigate</button>
                {currentResult?.loading && <span style={{ marginLeft: 10, opacity: 0.8 }}>Investigating…</span>}
                {currentResult?.error && <span style={{ marginLeft: 10, color: '#f87171' }}>Error: {currentResult.error}</span>}
              </div>

              {currentResult?.data && (
                <div className="section">
                  <div className="section-title">Analysis</div>
                  <div className="section">
                    <div className="section-title">Exploitation Techniques</div>
                    <ul className="list">
                      {(currentResult.data.parsed?.exploitationTechniques || []).map((t, i) => <li key={i}>• {t}</li>)}
                      {!(currentResult.data.parsed?.exploitationTechniques || []).length && <li>—</li>}
                    </ul>
                  </div>
                  <div className="section">
                    <div className="section-title">Attack Vectors</div>
                    <ul className="list">
                      {(currentResult.data.parsed?.attackVectors || []).map((t, i) => <li key={i}>• {t}</li>)}
                      {!(currentResult.data.parsed?.attackVectors || []).length && <li>—</li>}
                    </ul>
                  </div>
                  <div className="section">
                    <div className="section-title">Proof of Concept (PoC)</div>
                    <pre className="pre">{currentResult.data.parsed?.pocCode || '—'}</pre>
                  </div>
                  <div className="section">
                    <div className="section-title">Mitigation Advice</div>
                    <pre className="pre">{currentResult.data.parsed?.mitigationAdvice || '—'}</pre>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
