import React from 'react'

const DEFAULT_FUZZ_OPTIONS = [
  { key: 'xss', label: 'XSS payloads' },
  { key: 'sqli', label: 'SQLi payloads' },
  { key: 'path_traversal', label: 'Path Traversal' },
  { key: 'lfi', label: 'Local File Inclusion (LFI)' },
  { key: 'rfi', label: 'Remote File Inclusion (RFI)' },
  { key: 'command_injection', label: 'Command Injection' },
  { key: 'headers_common', label: 'Headers (common fuzz values)' },
]

export default function OptionsPanel({ open, onClose, llmEnabled, onToggleLlm, aggressiveFP, onToggleAggressiveFP, onFuzz, onSaveProject, onLoadProject, fuzzOptions, onFuzzOptionsChange, llmApiType = 'LMStudio' }) {
    if (!open) return null
    
    const toggleFuzzOption = (key) => {
        const next = { ...(fuzzOptions || {}) }
        next[key] = !next[key]
        onFuzzOptionsChange?.(next)
    }
    
    return (
        <div className="details-overlay" onClick={onClose}>
            <div className="details-panel" onClick={e => e.stopPropagation()}>
                <div className="details-header">
                    <div style={{ fontWeight: 600 }}>Options</div>
                    <button className="btn" onClick={onClose}>Close</button>
                </div>
                <div className="details-body">
                    <div className="section">
                        <div className="section-title">Project</div>
                        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                            <button className="btn" onClick={onFuzz}>Generate Fuzz File</button>
                            <button className="btn" onClick={onSaveProject}>Save Project</button>
                            <button className="btn" onClick={onLoadProject}>Load Project</button>
                        </div>
                    </div>

                    <div className="section">
                        <div className="section-title">Behavior</div>
                        <label style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                            <input type="checkbox" checked={!!llmEnabled} onChange={e => onToggleLlm?.(e.target.checked)} />
                            Use LLM in Vulnerability Investigation
                        </label>
                        
                        <div style={{ marginTop: 12 }}>
                            <div style={{ marginBottom: 4 }}>LLM API Type:</div>
                            <select 
                                style={{ 
                                    padding: '4px 8px', 
                                    borderRadius: '4px',
                                    backgroundColor: '#1a1a1a',
                                    color: '#f0f0f0',
                                    border: '1px solid #333'
                                }}
                                value={llmApiType}
                                onChange={e => {
                                    if (typeof onToggleLlm === 'function') {
                                        const apiType = e.target.value;
                                        onToggleLlm(true, { llmApiType: apiType });
                                    }
                                }}
                            >
                                <option value="LMStudio">LMStudio (default)</option>
                                <option value="Ollama">Ollama</option>
                                <option value="OpenAI">OpenAI</option>
                                <option value="Gemini">Gemini</option>
                            </select>
                            <div style={{ opacity: 0.75, marginTop: 4, fontSize: 12 }}>
                                Select the LLM API to use for vulnerability investigation.
                            </div>
                        </div>
                        
                        <div style={{ height: 16 }} />
                        <label style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                            <input type="checkbox" checked={!!aggressiveFP} onChange={e => onToggleAggressiveFP?.(e.target.checked)} />
                            Enable aggressive fingerprinting for new hosts
                        </label>
                        <div style={{ opacity: 0.75, marginTop: 4, fontSize: 13 }}>
                            When enabled, the backend will send a small burst of malformed HTTP requests for each newly discovered host to elicit detailed server signatures. All requests and responses are logged in Live Requests.
                        </div>
                    </div>
                    
                    <div className="section">
                        <div className="section-title">FuzzDB Options</div>
                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                          {DEFAULT_FUZZ_OPTIONS.map(opt => (
                            <label key={opt.key} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                              <input 
                                type="checkbox" 
                                checked={!!fuzzOptions?.[opt.key]} 
                                onChange={() => toggleFuzzOption(opt.key)} 
                              />
                              <span>{opt.label}</span>
                            </label>
                          ))}
                        </div>
                        <div style={{ marginTop: 8, opacity: 0.7, fontSize: 12 }}>
                          These options approximate categories from fuzzdb-project. The generated file will include payloads for each selected category for every observed URL path.
                        </div>
                    </div>
                </div>
            </div>
        </div>
    )
}
