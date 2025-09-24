import React from 'react'

function Card({ title, children }) {
  return (
    <div className="card">
      <div className="card-title">{title}</div>
      <div className="card-body">{children}</div>
    </div>
  )
}

export default function AnalyticsPanels({ analytics, selectedHost, onSelectHost, selectedTech, onSelectTech }) {
  if (!analytics) return (
    <div className="analytics-grid">
      <Card title="Totals"><div>Loading...</div></Card>
      <Card title="Unique Hostnames" />
      <Card title="Technologies" />
      <Card title="OpenAPI/Swagger" />
    </div>
  )

  const techEntries = Object.entries(analytics.technologies || {}).sort((a,b)=>b[1]-a[1])
  const methodEntries = Object.entries(analytics.methods || {})
  const statusEntries = Object.entries(analytics.statuses || {})

  //const hostsSorted = (analytics.hostnames || []).slice().sort((a,b)=>a.localeCompare(b))
  const hostsSorted = (analytics.hostnames || []).slice().sort((a, b) => {
        const extractSLD = (domain) => {
            const parts = domain.split('.');
            if (parts.length >= 2) { // Ensure there's at least a SLD and TLD
                return parts[1];  // The second element is the SLD
            } else {
                return ''; // Or handle invalid domains as needed (e.g., return null)
            }
        };

        const sla = extractSLD(a);
        const slb = extractSLD(b);

        if (sla === undefined || sla === null) return -1; // Treat undefined/null as smaller
        if (slb === undefined || slb === null) return 1;

        return sla.localeCompare(slb);
    });

  const hostListStyle = hostsSorted.length > 30 ? { maxHeight: 300, overflowY: 'auto' } : undefined

  return (
    <div className="analytics-grid">
      <Card title="Totals">
        <ul className="list">
          <li><strong>Requests:</strong> {analytics.totals.requests}</li>
          <li><strong>Methods:</strong> {methodEntries.map(([k,v])=>`${k}: ${v}`).join(', ') || '—'}</li>
          <li><strong>Status Codes:</strong> {statusEntries.map(([k,v])=>`${k}: ${v}`).join(', ') || '—'}</li>
        </ul>
      </Card>
      <Card title="Technologies">
        <ul className="list selectable">
          {techEntries.slice(0, 20).map(([t,c]) => (
            <li
              key={t}
              onClick={() => onSelectTech?.(t === selectedTech ? '' : t)}
              className={t === selectedTech ? 'selected' : ''}
            >
              {t} <span className="badge">{c}</span>
            </li>
          ))}
          {!techEntries.length && <li>—</li>}
        </ul>
      </Card>
      <Card title="OpenAPI/Swagger Docs">
        <ul className="list">
          {analytics.openApi?.length ? analytics.openApi.map(({host, urls}) => (
            <li key={host}>
              <div className="host" style={{ cursor: 'pointer', fontWeight: host===selectedHost?600:500 }} onClick={() => onSelectHost?.(host === selectedHost ? '' : host)}>{host}</div>
              <ul>
                {urls.map(u => <li key={u}><a href={u} target="_blank" rel="noreferrer">{u}</a></li>)}
              </ul>
            </li>
          )) : <li>—</li>}
        </ul>
      </Card>
        <Card title="Unique Hostnames">
            <ul className="list selectable" style={hostListStyle}>
                {hostsSorted.map(h => (
                    <li
                        key={h}
                        onClick={() => onSelectHost?.(h === selectedHost ? '' : h)}
                        className={h === selectedHost ? 'selected' : ''}
                    >
                        {h}
                    </li>
                ))}
                {!hostsSorted.length && <li>—</li>}
            </ul>
        </Card>
    </div>
  )
}
