import { useCallback, useEffect, useState } from 'react'
import {
  Activity,
  Brain,
  Crosshair,
  PauseCircle,
  PlayCircle,
  Radar,
  RefreshCw,
  Shield,
  ShieldAlert,
  Wifi,
} from 'lucide-react'
import { api } from './api'
import ThreatCharts from './components/ThreatCharts'
import ThreatTable from './components/ThreatTable'
import ClassifyPanel from './components/ClassifyPanel'
import IngestPanel from './components/IngestPanel'
import ReportPanel from './components/ReportPanel'
import ThreatDefinitions from './components/ThreatDefinitions'
import LogAnalyzer from './components/LogAnalyzer'
import StatusFooter from './components/StatusFooter'

function useClock() {
  const [now, setNow] = useState(() => new Date())
  useEffect(() => {
    const timer = window.setInterval(() => setNow(new Date()), 1000)
    return () => window.clearInterval(timer)
  }, [])
  return now
}

function App() {
  const [stats, setStats] = useState(null)
  const [threats, setThreats] = useState([])
  const [summary, setSummary] = useState(null)
  const [loading, setLoading] = useState(true)
  const [collecting, setCollecting] = useState(false)
  const [downloading, setDownloading] = useState(false)
  const [toast, setToast] = useState('')
  const [lastRefresh, setLastRefresh] = useState(null)
  const [health, setHealth] = useState(null)
  const [monitor, setMonitor] = useState(null)
  const [monitorBusy, setMonitorBusy] = useState(false)
  const now = useClock()

  const showToast = useCallback((message) => {
    setToast(message)
    window.setTimeout(() => setToast(''), 4200)
  }, [])

  const refresh = useCallback(async () => {
    try {
      const [statsData, threatData, reportData, healthData, monitorData] = await Promise.all([
        api.getStats(),
        api.getThreats({ limit: 40 }),
        api.reportSummary(),
        api.health().catch(() => null),
        api.monitorStatus().catch(() => null),
      ])
      setStats(statsData)
      setThreats(threatData)
      setSummary(reportData)
      if (healthData) setHealth(healthData)
      if (monitorData) setMonitor(monitorData)
      setLastRefresh(new Date())
    } catch (err) {
      showToast(err.message || 'Failed to load dashboard data')
    } finally {
      setLoading(false)
    }
  }, [showToast])

  useEffect(() => {
    refresh()
    // Refresh often so continuous monitor results appear without a click.
    const timer = window.setInterval(refresh, 5000)
    return () => window.clearInterval(timer)
  }, [refresh])

  useEffect(() => {
    // Ensure continuous monitoring is running when the dashboard loads.
    let cancelled = false
    ;(async () => {
      try {
        const status = await api.monitorStatus()
        if (cancelled) return
        if (!status.enabled) {
          const started = await api.startMonitor()
          if (!cancelled) {
            setMonitor(started)
            showToast('Continuous network monitoring started')
          }
        } else {
          setMonitor(status)
        }
      } catch {
        // Backend may still be starting; the poll loop will retry.
      }
    })()
    return () => {
      cancelled = true
    }
  }, [showToast])

  async function handleCollect() {
    setCollecting(true)
    try {
      const result = await api.collect(12, 'network')
      const detail = [
        result.message || `Collected ${result.events_collected} events`,
        result.subnet ? `subnet ${result.subnet}` : null,
        typeof result.hosts_alive === 'number' ? `${result.hosts_alive} host(s)` : null,
      ]
        .filter(Boolean)
        .join(' · ')
      showToast(detail)
      await refresh()
    } catch (err) {
      showToast(err.message || 'Network scan failed')
    } finally {
      setCollecting(false)
    }
  }

  async function handleToggleMonitor() {
    setMonitorBusy(true)
    try {
      if (monitor?.enabled) {
        const stopped = await api.stopMonitor()
        setMonitor(stopped)
        showToast('Continuous monitoring paused')
      } else {
        const started = await api.startMonitor()
        setMonitor(started)
        showToast('Continuous monitoring resumed')
      }
      await refresh()
    } catch (err) {
      showToast(err.message || 'Could not update monitor')
    } finally {
      setMonitorBusy(false)
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
  const confidencePct = stats
    ? `${((stats.recent_confidence_avg || 0) * 100).toFixed(1)}%`
    : '—'
  const dominant = summary?.top_threat_type || '—'
  const latestThreat = threats[0] || null

  const timeLabel = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
  const dateLabel = now
    .toLocaleDateString('en-GB', { day: '2-digit', month: '2-digit', year: 'numeric' })
    .replace(/\//g, '-')

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand">
          <div className="brand-mark">
            <Shield size={26} />
          </div>
          <div>
            <h1>
              CYBER_SENTINEL<span className="brand-dot">.AI</span>
            </h1>
            <p>AI Cyber Threat Intelligence Dashboard</p>
          </div>
        </div>

        <div
          className={`secure-pill network-pill ${monitor?.enabled ? 'monitoring' : ''}`}
          title={
            monitor?.enabled
              ? `Continuous monitoring every ${monitor.interval_seconds}s`
              : health?.scan_subnet
                ? `Live LAN detection on ${health.scan_subnet}`
                : 'Live LAN host/port/connection detection'
          }
        >
          <Wifi size={15} />
          {monitor?.enabled
            ? monitor.scanning
              ? 'Monitoring · Scanning…'
              : 'Continuous Monitoring'
            : health?.network_detection === false
              ? 'Simulated Mode'
              : 'Network Detection'}
          {health?.local_ip ? ` · ${health.local_ip}` : ''}
        </div>

        <div className="sys-status">
          <div className="sys-operational">
            <span className="live-dot" />
            Operational
          </div>
          <div className="sys-clock mono">
            <span>{timeLabel}</span>
            <span className="sys-date">{dateLabel}</span>
          </div>
          <Wifi size={18} className="sys-signal" />
        </div>
      </header>

      <ThreatDefinitions />

      <section className="kpi-row" aria-label="Summary metrics">
        <article className="kpi-card panel total">
          <div className="kpi-icon">
            <Shield size={22} />
          </div>
          <div>
            <div className="stat-label">Total Threats Ingested</div>
            <div className="stat-value">{stats?.total_threats ?? '—'}</div>
          </div>
        </article>
        <article className="kpi-card panel critical">
          <div className="kpi-icon">
            <ShieldAlert size={22} />
          </div>
          <div>
            <div className="stat-label">Critical Incidents</div>
            <div className="stat-value">{critical}</div>
          </div>
        </article>
        <article className="kpi-card panel dominant">
          <div className="kpi-icon">
            <Crosshair size={22} />
          </div>
          <div>
            <div className="stat-label">Dominant Vector</div>
            <div className="stat-value text-value">{dominant}</div>
          </div>
        </article>
        <article className="kpi-card panel confidence">
          <div className="kpi-icon">
            <Brain size={22} />
          </div>
          <div>
            <div className="stat-label">AI Model Confidence</div>
            <div className="stat-value">{confidencePct}</div>
          </div>
        </article>
      </section>

      <section className="action-bar">
        <button
          className={`btn ${monitor?.enabled ? 'btn-ghost' : 'btn-primary'}`}
          onClick={handleToggleMonitor}
          disabled={monitorBusy}
        >
          {monitor?.enabled ? <PauseCircle size={16} /> : <PlayCircle size={16} />}
          {monitorBusy
            ? 'Updating…'
            : monitor?.enabled
              ? 'Pause Monitoring'
              : 'Resume Monitoring'}
        </button>
        <button className="btn btn-primary" onClick={handleCollect} disabled={collecting}>
          <Radar size={16} />
          {collecting ? 'Scanning now…' : 'Scan Now'}
        </button>
        <button className="btn btn-ghost" onClick={refresh} disabled={loading}>
          <RefreshCw size={16} className={loading ? 'spin' : undefined} />
          Refresh Intel
        </button>
        <span className="action-hint mono">
          {monitor?.enabled
            ? `Auto-scan every ${monitor.interval_seconds}s · Cycles ${monitor.cycles_completed}`
            : 'Monitoring paused'}
          {' · '}
          Open: {stats?.open_threats ?? '—'}
          {health?.scan_subnet ? ` · ${health.scan_subnet}` : ''}
        </span>
      </section>

      <section className="intel-row">
        <LogAnalyzer threat={latestThreat} />
        <ThreatCharts stats={stats || { timeline: [], by_type: {}, by_severity: {} }} />
      </section>

      <section className="layout-grid">
        <div className="panel section">
          <div className="section-head">
            <h3>Live Threat Feed</h3>
            <span>
              <Activity size={14} style={{ verticalAlign: '-2px', marginRight: 4 }} />
              Stream synced{' '}
              {lastRefresh
                ? lastRefresh.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
                : '—'}
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

      <StatusFooter
        lastRefresh={lastRefresh}
        onRefresh={refresh}
        loading={loading}
        health={health}
        monitor={monitor}
      />

      {toast ? <div className="toast">{toast}</div> : null}
    </div>
  )
}

export default App
