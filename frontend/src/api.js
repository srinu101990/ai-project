const BASE = '/api'

function errorMessage(raw, fallback) {
  if (!raw) return fallback
  try {
    const data = JSON.parse(raw)
    if (typeof data.detail === 'string') return data.detail
    if (Array.isArray(data.detail)) {
      return data.detail
        .map((item) => item.msg || item.message || JSON.stringify(item))
        .join('; ')
    }
  } catch {
    /* not JSON */
  }
  return raw
}

async function request(path, options = {}) {
  const { timeoutMs = 25000, timeoutMessage, headers, signal, ...rest } = options
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  if (signal) {
    if (signal.aborted) controller.abort()
    else signal.addEventListener('abort', () => controller.abort(), { once: true })
  }

  try {
    const response = await fetch(`${BASE}${path}`, {
      headers: {
        'Content-Type': 'application/json',
        ...(headers || {}),
      },
      ...rest,
      signal: controller.signal,
    })

    if (!response.ok) {
      const detail = await response.text()
      throw new Error(errorMessage(detail, `Request failed: ${response.status}`))
    }

    const type = response.headers.get('content-type') || ''
    if (type.includes('application/pdf')) {
      return response.blob()
    }
    return response.json()
  } catch (err) {
    if (err?.name === 'AbortError') {
      throw new Error(
        timeoutMessage ||
          'The server did not answer in time. Keep the black window open and try again.',
      )
    }
    throw err
  } finally {
    clearTimeout(timer)
  }
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
      throw new Error(errorMessage(await response.text(), 'Upload failed'))
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
      timeoutMs: 18000,
      timeoutMessage:
        'Gmail did not answer in time. Enable IMAP, use a 16-character App Password (not your normal password), and check that port 993 is not blocked.',
    }),
  pollMailImap: () =>
    request('/mail/imap/poll', {
      method: 'POST',
      body: JSON.stringify({}),
      timeoutMs: 18000,
    }),
  stopMailImap: () =>
    request('/mail/imap/stop', {
      method: 'POST',
      body: JSON.stringify({}),
    }),
  startOutlookWatch: () =>
    request('/mail/outlook/start', {
      method: 'POST',
      body: JSON.stringify({}),
      timeoutMs: 20000,
    }),
  pollOutlookWatch: () =>
    request('/mail/outlook/poll', {
      method: 'POST',
      body: JSON.stringify({}),
    }),
  stopOutlookWatch: () =>
    request('/mail/outlook/stop', {
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
      throw new Error(errorMessage(await response.text(), 'Upload failed'))
    }
    return response.json()
  },
  setupStatus: () => request('/setup'),
  endpointStatus: () => request('/endpoint/status'),
  startEndpointWatch: () =>
    request('/endpoint/start', {
      method: 'POST',
      body: JSON.stringify({}),
    }),
  scanEndpoint: () =>
    request('/endpoint/scan', {
      method: 'POST',
      body: JSON.stringify({}),
    }),
  stopEndpointWatch: () =>
    request('/endpoint/stop', {
      method: 'POST',
      body: JSON.stringify({}),
    }),
  updateStatus: (id, status) =>
    request(`/threats/${id}`, {
      method: 'PATCH',
      body: JSON.stringify({ status }),
    }),
  reportSummary: () => request('/reports/summary'),
  downloadReport: async () => {
    const blob = await request('/reports/pdf', { timeoutMs: 60000 })
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
