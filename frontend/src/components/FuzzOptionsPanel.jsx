import React from 'react'

const DEFAULT_OPTIONS = [
  { key: 'xss', label: 'XSS payloads' },
  { key: 'sqli', label: 'SQLi payloads' },
  { key: 'path_traversal', label: 'Path Traversal' },
  { key: 'lfi', label: 'Local File Inclusion (LFI)' },
  { key: 'rfi', label: 'Remote File Inclusion (RFI)' },
  { key: 'command_injection', label: 'Command Injection' },
  { key: 'headers_common', label: 'Headers (common fuzz values)' },
]

export default function FuzzOptionsPanel({ value = {}, onChange }) {
  const toggle = (key) => {
    const next = { ...(value || {}) }
    next[key] = !next[key]
    onChange?.(next)
  }

  return (
    <div className="card">
      <div className="card-title">FuzzDB Options</div>
      <div className="card-body">
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
          {DEFAULT_OPTIONS.map(opt => (
            <label key={opt.key} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <input type="checkbox" checked={!!value?.[opt.key]} onChange={() => toggle(opt.key)} />
              <span>{opt.label}</span>
            </label>
          ))}
        </div>
        <div style={{ marginTop: 8, opacity: 0.7, fontSize: 12 }}>
          These options approximate categories from fuzzdb-project. The generated file will include payloads for each selected category for every observed URL path.
        </div>
      </div>
    </div>
  )
}
