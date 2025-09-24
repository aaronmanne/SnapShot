import React, { useMemo, useState } from 'react'

export default function DataTable({ loading, data, sortKey, sortDir, onSort, perPage = 500, onPerPageChange, onRowClick }) {
  const [page, setPage] = useState(1)

  // headers: TIME, METHOD, STATUS, URL
  const headers = [
    { key: 'timestamp', label: 'Time' },
    { key: 'method', label: 'Method' },
    { key: 'status', label: 'Status' },
    { key: 'url', label: 'URL' },
  ]

  const total = data.length
  const totalPages = Math.max(1, Math.ceil(total / perPage))

  // Keep table live: when data changes, clamp page
  if (page > totalPages) setPage(totalPages)

  const pageData = useMemo(() => {
    const start = (page - 1) * perPage
    return data.slice(start, start + perPage)
  }, [data, page, perPage])

  const perPageOptions = [500, 1000, 2000, 5000]

  return (
    <div className="card">
      <div className="card-title">Live Requests {loading ? '(loading...)' : ''}</div>
      <div className="table-controls">
        <div className="pagination">
          <button disabled={page <= 1} onClick={() => setPage(1)}>« First</button>
          <button disabled={page <= 1} onClick={() => setPage(p => Math.max(1, p - 1))}>‹ Prev</button>
          <span>Page {page} / {totalPages}</span>
          <button disabled={page >= totalPages} onClick={() => setPage(p => Math.min(totalPages, p + 1))}>Next ›</button>
          <button disabled={page >= totalPages} onClick={() => setPage(totalPages)}>Last »</button>
        </div>
        <div className="per-page">
          <label>Rows per page:&nbsp;</label>
          <select value={perPage} onChange={(e) => onPerPageChange?.(Number(e.target.value))}>
            {perPageOptions.map(o => <option key={o} value={o}>{o}</option>)}
          </select>
        </div>
      </div>
      <div className="table-wrapper">
        <table className="table">
          <thead>
            <tr>
              {headers.map(h => (
                <th key={h.key} onClick={() => onSort(h.key)} className={sortKey === h.key ? 'sorted ' + sortDir : ''}>
                  {h.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {pageData.map(r => (
              <tr key={r.id} onClick={() => onRowClick?.(r)} style={{ cursor: onRowClick ? 'pointer' : 'default' }}>
                <td>{new Date(r.timestamp).toLocaleTimeString()}</td>
                <td><span className={`pill pill-${r.method}`}>{r.method}</span></td>
                <td><span className={`status status-${Math.floor(r.status/100)}xx`}>{r.status}</span></td>
                <td className="url-cell" title={r.url}>{r.url}</td>
              </tr>
            ))}
            {!data.length && (
              <tr>
                <td colSpan={4} style={{ textAlign: 'center', opacity: 0.6 }}>No data yet. Route any request through the proxy: POST {typeof window !== 'undefined' ? window.location.origin : ''}/proxy?url=https://example.com</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
