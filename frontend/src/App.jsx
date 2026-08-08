import { useCallback, useEffect, useState } from 'react'
import { Activity, Radar, RefreshCw, Shield } from 'lucide-react'
import { api } from './api'
import ThreatCharts from './components/ThreatCharts'
import ThreatTable from './components/ThreatTable'
import ClassifyPanel from './components/ClassifyPanel'
import IngestPanel from './components/IngestPanel'
import ReportPanel from './components/ReportPanel'

function App() {
  const [stats, setStats] = useState(null)
  const [threats, setThreats] = useState([])
  const [summary, setSummary] = useState(null)
  const [loading, setLoading] = useState(true)
  const [collecting, setCollecting] = useState(false)
  const [downloading, setDownloading] = useState(false)
  const [toast, setToast] = useState('')
  const [lastRefresh, setLastRefresh] = useState(null)

  const showToast = useCallback((message) => {
    setToast(message)
    window.setTimeout(() => setToast(''), 3200)
  }, [])

  const refresh = useCallback(async () => {
    try {
      const [statsData, threatData, reportData] = await Promise.all([
        api.getStats(),
        api.getThreats({ limit: 40 }),
        api.reportSummary(),
      ])
      setStats(statsData)
      setThreats(threatData)
      setSummary(reportData)
      setLastRefresh(new Date())
    } catch (err) {
      showToast(err.message || 'Failed to load dashboard data')
    } finally {
      setLoading(false)
    }
  }, [showToast])

  useEffect(() => {
    refresh()
    const timer = window.setInterval(refresh, 12000)
    return () => window.clearInterval(timer)
  }, [refresh])

  async function handleCollect() {
    setCollecting(true)
    try {
      const result = await api.collect(10)
      showToast(result.message || `Collected ${result.events_collected} events`)
      await refresh()
    } catch (err) {
      showToast(err.message || 'Collection failed')
    } finally {
      setCollecting(false)
    }
  }

  async function handleStatusChange(id, status) {
    try {
      await api.updateStatus(id, status)
      showToast(`Threat #${id} marked ${status}`)
      await refresh()
    } catch (err) {
      showToast(err.message || 'Status update failed')
    }
  }

  async function handleDownload() {
    setDownloading(true)
    try {
      await api.downloadReport()
      showToast('PDF report downloaded')
    } catch (err) {
      showToast(err.message || 'Report download failed')
    } finally {
      setDownloading(false)
    }
  }

  const critical = stats?.by_severity?.critical || 0
  const high = stats?.by_severity?.high || 0

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand">
          <div className="brand-mark">
            <Shield size={24} />
          </div>
          <div>
            <h1>Aegis Intel</h1>
            <p>AI-based Cyber Threat Intelligence Dashboard</p>
          </div>
        </div>
        <div className="live-pill" title={lastRefresh ? lastRefresh.toLocaleTimeString() : ''}>
          <span className="live-dot" />
          Live monitoring
        </div>
      </header>

      <section className="hero-strip">
        <div className="panel hero-copy">
          <h2>Collect, classify, and act on cyber threats in one operational view.</h2>
          <p>
            Network telemetry is scored by an AI model for phishing, malware, and ransomware —
            then surfaced with real-time charts and decision-ready reporting.
          </p>
          <div className="hero-actions">
            <button className="btn btn-primary" onClick={handleCollect} disabled={collecting}>
              <Radar size={16} />
              {collecting ? 'Scanning network…' : 'Collect from Network'}
            </button>
            <button className="btn btn-ghost" onClick={refresh} disabled={loading}>
              <RefreshCw size={16} />
              Refresh
            </button>
          </div>
        </div>

        <div className="panel stat-grid">
          <div className="stat-card total">
            <div className="stat-label">Total Threats</div>
            <div className="stat-value">{stats?.total_threats ?? '—'}</div>
          </div>
          <div className="stat-card open">
            <div className="stat-label">Open Cases</div>
            <div className="stat-value">{stats?.open_threats ?? '—'}</div>
          </div>
          <div className="stat-card critical">
            <div className="stat-label">Critical</div>
            <div className="stat-value">{critical}</div>
          </div>
          <div className="stat-card high">
            <div className="stat-label">High</div>
            <div className="stat-value">{high}</div>
          </div>
        </div>
      </section>

      <ThreatCharts stats={stats || { timeline: [], by_type: {}, by_severity: {} }} />

      <section className="layout-grid" style={{ marginTop: '1rem' }}>
        <div className="panel section">
          <div className="section-head">
            <h3>Live Threat Feed</h3>
            <span>
              <Activity size={14} style={{ verticalAlign: '-2px', marginRight: 4 }} />
              Avg confidence{' '}
              {stats ? `${Math.round((stats.recent_confidence_avg || 0) * 100)}%` : '—'}
            </span>
          </div>
          <ThreatTable threats={threats} onStatusChange={handleStatusChange} />
        </div>
        <ReportPanel
          summary={summary}
          onDownload={handleDownload}
          downloading={downloading}
        />
      </section>

      <section className="tools-grid">
        <ClassifyPanel onToast={showToast} />
        <IngestPanel onIngested={refresh} onToast={showToast} />
      </section>

      {toast ? <div className="toast">{toast}</div> : null}
    </div>
  )
}

export default App
