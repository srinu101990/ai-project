const BASE = '/api'

async function request(path, options = {}) {
  const response = await fetch(`${BASE}${path}`, {
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
    ...options,
  })

  if (!response.ok) {
    const detail = await response.text()
    throw new Error(detail || `Request failed: ${response.status}`)
  }

  const type = response.headers.get('content-type') || ''
  if (type.includes('application/pdf')) {
    return response.blob()
  }
  return response.json()
}

export const api = {
  health: () => request('/health'),
  getThreats: (params = {}) => {
    const qs = new URLSearchParams(params).toString()
    return request(`/threats${qs ? `?${qs}` : ''}`)
  },
  getStats: () => request('/stats'),
  collect: (batchSize = 8, mode = 'network') =>
    request('/collect', {
      method: 'POST',
      body: JSON.stringify({ batch_size: batchSize, mode }),
    }),
  liveSources: () => request('/sources'),
  sweepSources: () =>
    request('/sources/sweep', {
      method: 'POST',
      body: JSON.stringify({}),
    }),
  projectionBurst: () =>
    request('/sources/burst', {
      method: 'POST',
      body: JSON.stringify({}),
    }),
  remoteAgents: () => request('/agents'),
  monitorStatus: () => request('/monitor'),
  startMonitor: (intervalSeconds) =>
    request('/monitor/start', {
      method: 'POST',
      body: JSON.stringify(
        intervalSeconds ? { interval_seconds: intervalSeconds } : {},
      ),
    }),
  stopMonitor: () =>
    request('/monitor/stop', {
      method: 'POST',
      body: JSON.stringify({}),
    }),
  demoFeedStatus: () => request('/demo-feed'),
  injectAllDemoThreats: () =>
    request('/demo-feed/inject-all', {
      method: 'POST',
      body: JSON.stringify({}),
    }),
  startDemoFeed: (intervalSeconds = 30) =>
    request('/demo-feed/start', {
      method: 'POST',
      body: JSON.stringify({ interval_seconds: intervalSeconds }),
    }),
  stopDemoFeed: () =>
    request('/demo-feed/stop', {
      method: 'POST',
      body: JSON.stringify({}),
    }),
  ingest: (payload) =>
    request('/ingest', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  classify: (text) =>
    request('/classify', {
      method: 'POST',
      body: JSON.stringify({ text }),
    }),
  checkMail: (payload) =>
    request('/mail/check', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  uploadMail: async (file) => {
    const body = new FormData()
    body.append('file', file)
    const response = await fetch(`${BASE}/mail/upload-eml`, {
      method: 'POST',
      body,
    })
    if (!response.ok) {
      throw new Error((await response.text()) || 'Upload failed')
    }
    return response.json()
  },
  scanMailDrop: () =>
    request('/mail/scan-drop', {
      method: 'POST',
      body: JSON.stringify({}),
    }),
  mailStatus: () => request('/mail/status'),
  connectMailImap: (payload) =>
    request('/mail/imap/connect', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  pollMailImap: () =>
    request('/mail/imap/poll', {
      method: 'POST',
      body: JSON.stringify({}),
    }),
  stopMailImap: () =>
    request('/mail/imap/stop', {
      method: 'POST',
      body: JSON.stringify({}),
    }),
  fileStatus: () => request('/files/status'),
  startFileWatch: () =>
    request('/files/start', {
      method: 'POST',
      body: JSON.stringify({}),
    }),
  scanFiles: () =>
    request('/files/scan', {
      method: 'POST',
      body: JSON.stringify({}),
    }),
  stopFileWatch: () =>
    request('/files/stop', {
      method: 'POST',
      body: JSON.stringify({}),
    }),
  testFileSample: () =>
    request('/files/test-sample', {
      method: 'POST',
      body: JSON.stringify({}),
    }),
  uploadFile: async (file) => {
    const body = new FormData()
    body.append('file', file)
    const response = await fetch(`${BASE}/files/upload`, {
      method: 'POST',
      body,
    })
    if (!response.ok) {
      throw new Error((await response.text()) || 'Upload failed')
    }
    return response.json()
  },
  setupStatus: () => request('/setup'),
  updateStatus: (id, status) =>
    request(`/threats/${id}`, {
      method: 'PATCH',
      body: JSON.stringify({ status }),
    }),
  reportSummary: () => request('/reports/summary'),
  downloadReport: async () => {
    const blob = await request('/reports/pdf')
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `threat_intel_report_${Date.now()}.pdf`
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
  },
}
