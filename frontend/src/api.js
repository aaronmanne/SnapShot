export async function fetchRequests(params = {}) {
  const qs = new URLSearchParams(params)
  const res = await fetch(`/api/requests?${qs.toString()}`)
  if (!res.ok) throw new Error('Failed to fetch requests')
  return res.json()
}

export async function fetchAnalytics() {
  const res = await fetch('/api/analytics')
  if (!res.ok) throw new Error('Failed to fetch analytics')
  return res.json()
}

export async function generateFuzz(params = {}) {
  const res = await fetch('/api/fuzz/generate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params)
  })
  if (!res.ok) throw new Error('Failed to generate')
  const blob = await res.blob()
  return new Blob([blob], { type: 'text/plain' })
}

export async function purgeAll() {
  const res = await fetch('/api/purge', { method: 'POST' })
  if (!res.ok) throw new Error('Failed to purge')
  return res.json()
}

export async function investigateVulnerability({ vulnerability, requestId, force, customPrompt } = {}) {
  const res = await fetch('/api/llm/investigate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ vulnerability, requestId, force, customPrompt })
  })
  if (!res.ok) {
    let msg = 'Failed to investigate';
    try { const e = await res.json(); msg = e.message || e.error || msg } catch {}
    throw new Error(msg)
  }
  return res.json()
}

export async function exportProject() {
  const res = await fetch('/api/project/export')
  if (!res.ok) throw new Error('Failed to export project')
  return res.json()
}

export async function importProject(payload) {
  const res = await fetch('/api/project/import', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  })
  if (!res.ok) {
    let msg = 'Failed to import project';
    try { const e = await res.json(); msg = e.message || e.error || msg } catch {}
    throw new Error(msg)
  }
  return res.json()
}

export async function spiderFromUrl(url, userAgent) {
  const res = await fetch('/api/spider/from', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url, userAgent })
  })
  if (!res.ok) {
    let msg = 'Failed to start spider';
    try { const e = await res.json(); msg = e.message || e.error || msg } catch {}
    throw new Error(msg)
  }
  return res.json()
}

export async function stopSpider() {
  const res = await fetch('/api/spider/stop', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' }
  })
  if (!res.ok) {
    let msg = 'Failed to stop spider';
    try { const e = await res.json(); msg = e.message || e.error || msg } catch {}
    throw new Error(msg)
  }
  return res.json()
}

export async function getSpiderStatus() {
  const res = await fetch('/api/spider/status')
  if (!res.ok) {
    let msg = 'Failed to get spider status';
    try { const e = await res.json(); msg = e.message || e.error || msg } catch {}
    throw new Error(msg)
  }
  return res.json()
}


export async function getOptions() {
  const res = await fetch('/api/options');
  if (!res.ok) throw new Error('Failed to fetch options');
  return res.json();
}

export async function setOptions(opts = {}) {
  const res = await fetch('/api/options', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(opts)
  });
  if (!res.ok) {
    let msg = 'Failed to save options';
    try { const e = await res.json(); msg = e.message || e.error || msg } catch {}
    throw new Error(msg);
  }
  return res.json();
}

export async function getLlmPrompt({ vulnerability, requestId } = {}) {
  const res = await fetch('/api/llm/prompt', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ vulnerability, requestId })
  });
  if (!res.ok) {
    let msg = 'Failed to build prompt';
    try { const e = await res.json(); msg = e.message || e.error || msg } catch {}
    throw new Error(msg);
  }
  return res.json();
}
