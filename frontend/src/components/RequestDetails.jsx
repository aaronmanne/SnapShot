import React from 'react'
import { spiderFromUrl } from '../api.js'

export default function RequestDetails({ request, onClose }) {
  if (!request) return null
  let u
  try { u = new URL(request.url) } catch {}
  // Prefer deriving from the full URL; fallback to backend-provided path
  const pathFull = u
    ? (u.pathname + (u.search || '') + (u.hash || ''))
    : (request.path || '')

  return (
    <div className="details-overlay" onClick={onClose}>
      <div className="details-panel" onClick={e => e.stopPropagation()}>
        <div className="details-header">
          <div style={{ fontWeight: 600 }}>Request Details</div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="btn" onClick={async () => {
              try {
                await spiderFromUrl(request.url)
                alert('Spider started from this URL')
              } catch (e) {
                alert('Failed to start spider')
              }
            }}>Spider from here</button>
            <button className="btn" onClick={onClose}>Close</button>
          </div>
        </div>
        <div className="details-body">
          <div className="kv"><span className="k">Time</span><span className="v">{new Date(request.timestamp).toLocaleString()}</span></div>
          <div className="kv"><span className="k">Method</span><span className="v">{request.method}</span></div>
          <div className="kv"><span className="k">Status</span><span className="v">{request.status}</span></div>
          <div className="kv"><span className="k">Host</span><span className="v">{request.host}</span></div>
          <div className="kv"><span className="k">Full URL</span><span className="v wrap" title={request.url}>{request.url}</span></div>
          <div className="kv"><span className="k">URL Path</span><span className="v wrap" title={pathFull}>{pathFull}</span></div>
          {request.tech?.length ? (
            <div className="kv"><span className="k">Detected Tech</span><span className="v">{request.tech.join(', ')}</span></div>
          ) : null}
          <div className="section">
            <div className="section-title">Response Headers</div>
            <pre className="pre">
{(Array.isArray(request.headersRaw) && request.headersRaw.length
  ? request.headersRaw
  : Object.entries(request.headers || {}).flatMap(([k,v]) => Array.isArray(v) ? v.map(val => [k, String(val)]) : [[k, String(v)]]).flat()
).reduce((lines, cur, idx, arr) => {
  if (idx % 2 === 0) {
    const key = arr[idx];
    const val = arr[idx + 1] ?? '';
    lines.push(`${key}: ${val}`);
  }
  return lines;
}, []).join('\n')}
            </pre>
          </div>
          <div className="section">
            <div className="section-title">Request Headers</div>
            <pre className="pre">
{(Array.isArray(request.reqHeadersRaw) && request.reqHeadersRaw.length
  ? request.reqHeadersRaw
  : Object.entries(request.reqHeaders || {}).flatMap(([k,v]) => Array.isArray(v) ? v.map(val => [k, String(val)]) : [[k, String(v)]]).flat()
).reduce((lines, cur, idx, arr) => {
  if (idx % 2 === 0) {
    const key = arr[idx];
    const val = arr[idx + 1] ?? '';
    lines.push(`${key}: ${val}`);
  }
  return lines;
}, []).join('\n')}
            </pre>
          </div>
        </div>
      </div>
    </div>
  )
}
