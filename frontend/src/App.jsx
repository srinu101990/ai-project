import { useCallback, useEffect, useRef, useState } from 'react'
import {
  Brain,
  CheckCircle2,
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
import { ClassificationChart, SeverityChart } from './components/ThreatCharts'
import ThreatTable from './components/ThreatTable'
import ClassifyPanel from './components/ClassifyPanel'
import IngestPanel from './components/IngestPanel'
import ReportPanel from './components/ReportPanel'
import LogAnalyzer from './components/LogAnalyzer'
import TopNav from './components/TopNav'
import SystemMetaRow from './components/SystemMetaRow'
import CityThreatChart from './components/CityThreatChart'
import RecentAlerts from './components/RecentAlerts'
import DemoLabPage from './components/DemoLabPage'
import RemediationPanel from './components/RemediationPanel'
import ThreatPopup from './components/ThreatPopup'

function useClock() {
  const [now, setNow] = useState(() => new Date())
  useEffect(() => {
    const timer = window.setInterval(() => setNow(new Date()), 1000)
    return () => window.clearInterval(timer)
  }, [])
  return now
}

function App() {
  const [tab, setTab] = useState('dashboard')
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
  const [demoFeed, setDemoFeed] = useState(null)
  const [demoBusy, setDemoBusy] = useState(false)
  const [injectBusy, setInjectBusy] = useState(false)
  const [lastInjected, setLastInjected] = useState([])
  const [classifiedType, setClassifiedType] = useState(null)
  const [unreadCount, setUnreadCount] = useState(0)
  const [notifications, setNotifications] = useState([])
  const [bellOpen, setBellOpen] = useState(false)
  const [threatPopups, setThreatPopups] = useState([])
  const knownThreatIds = useRef(null)
  const popupTimers = useRef(new Map())
  const now = useClock()

  const showToast = useCallback((message) => {
    setToast(message)
    window.setTimeout(() => setToast(''), 4200)
  }, [])

  const dismissThreatPopup = useCallback((popupId) => {
    setThreatPopups((prev) => prev.filter((item) => item.popupId !== popupId))
    const timer = popupTimers.current.get(popupId)
    if (timer) {
      window.clearTimeout(timer)
      popupTimers.current.delete(popupId)
    }
  }, [])

  const pushThreatPopups = useCallback(
    (incoming) => {
      const stamped = incoming.map((threat, index) => ({
        ...threat,
        popupId: `${threat.id}-${Date.now()}-${index}`,
      }))
      setThreatPopups((prev) => [...stamped, ...prev].slice(0, 4))
      stamped.forEach((item) => {
        const timer = window.setTimeout(() => dismissThreatPopup(item.popupId), 6500)
        popupTimers.current.set(item.popupId, timer)
      })
    },
    [dismissThreatPopup],
  )

  const registerNewDetections = useCallback(
    (threatData) => {
      const ids = new Set((threatData || []).map((threat) => threat.id))
      if (knownThreatIds.current === null) {
        knownThreatIds.current = ids
        return
      }
      const fresh = (threatData || []).filter((threat) => !knownThreatIds.current.has(threat.id))
      knownThreatIds.current = ids
      if (!fresh.length) return

      const newestFirst = [...fresh].reverse()
      setUnreadCount((count) => count + newestFirst.length)
      setNotifications((prev) => [...newestFirst, ...prev].slice(0, 20))
      pushThreatPopups(newestFirst.slice(0, 3))
    },
    [pushThreatPopups],
  )

  const handleBellToggle = useCallback((nextOpen) => {
    setBellOpen(nextOpen)
  }, [])

  const handleClearNotifications = useCallback(() => {
    setUnreadCount(0)
    setNotifications([])
    setBellOpen(false)
  }, [])

  const handleSelectNotification = useCallback(() => {
    setUnreadCount(0)
    setBellOpen(false)
    setTab('threats')
  }, [])

  useEffect(
    () => () => {
      popupTimers.current.forEach((timer) => window.clearTimeout(timer))
      popupTimers.current.clear()
    },
    [],
  )

  const refresh = useCallback(async () => {
    try {
      const [statsData, threatData, reportData, healthData, monitorData, demoData] =
        await Promise.all([
          api.getStats(),
          api.getThreats({ limit: 40 }),
          api.reportSummary(),
          api.health().catch(() => null),
          api.monitorStatus().catch(() => null),
          api.demoFeedStatus().catch(() => null),
        ])
      setStats(statsData)
      setThreats(threatData)
      setSummary(reportData)
      if (healthData) setHealth(healthData)
      if (monitorData) setMonitor(monitorData)
      if (demoData) setDemoFeed(demoData)
      registerNewDetections(threatData)
      setLastRefresh(new Date())
    } catch (err) {
      showToast(err.message || 'Failed to load dashboard data')
    } finally {
      setLoading(false)
    }
  }, [registerNewDetections, showToast])

  useEffect(() => {
    refresh()
    const timer = window.setInterval(refresh, 5000)
    return () => window.clearInterval(timer)
  }, [refresh])

  useEffect(() => {
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
        // Backend may still be starting.
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

  async function handleToggleDemoFeed() {
    setDemoBusy(true)
    try {
      if (demoFeed?.enabled) {
        const stopped = await api.stopDemoFeed()
        setDemoFeed(stopped)
        showToast('Threat Demo stopped')
      } else {
        const started = await api.startDemoFeed(30)
        setDemoFeed(started)
        showToast('Threat Demo started — one virus type every 30 seconds')
        setTab('dashboard')
      }
      await refresh()
    } catch (err) {
      showToast(err.message || 'Could not update demo feed')
    } finally {
      setDemoBusy(false)
    }
  }

  async function handleInjectAllThreats() {
    setInjectBusy(true)
    try {
      const result = await api.injectAllDemoThreats()
      setDemoFeed(result)
      setLastInjected(result.events || [])
      showToast(result.last_message || 'All threat types injected and classified')
      await refresh()
      setTab('dashboard')
    } catch (err) {
      showToast(err.message || 'Demo inject failed')
    } finally {
      setInjectBusy(false)
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
  const containedResolved = (threats || []).filter((t) =>
    ['contained', 'resolved'].includes(t.status),
  ).length
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
          className={`secure-pill ${monitor?.enabled ? 'monitoring' : ''}`}
          title={
            monitor?.enabled
              ? `Continuous monitoring every ${monitor.interval_seconds}s`
              : 'Secure local AI + SQLite mode'
          }
        >
          <Shield size={15} />
          Secure Local Mode
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

      <TopNav
        active={tab}
        onChange={setTab}
        unreadCount={unreadCount}
        notifications={notifications}
        bellOpen={bellOpen}
        onBellToggle={handleBellToggle}
        onClearNotifications={handleClearNotifications}
        onSelectNotification={handleSelectNotification}
      />
      <SystemMetaRow
        health={health}
        monitor={monitor}
        lastRefresh={lastRefresh}
        demoFeed={demoFeed}
        onToggleDemo={handleToggleDemoFeed}
        demoBusy={demoBusy}
      />

      {tab === 'dashboard' ? (
        <>
          <section className="dashboard-top">
            <LogAnalyzer threat={latestThreat} />
            <ClassificationChart stats={stats || { by_type: {} }} />
            <SeverityChart stats={stats || { by_severity: {} }} />
          </section>

          <section className="kpi-row five" aria-label="Summary metrics">
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
            <article className="kpi-card panel resolved">
              <div className="kpi-icon">
                <CheckCircle2 size={22} />
              </div>
              <div>
                <div className="stat-label">Contained / Resolved</div>
                <div className="stat-value">{containedResolved}</div>
              </div>
            </article>
          </section>

          <section className="dashboard-bottom">
            <CityThreatChart threats={threats} />
            <RecentAlerts threats={threats} />
          </section>
        </>
      ) : null}

      {tab === 'threats' ? (
        <section className="panel section page-panel">
          <div className="section-head">
            <h3>Threat Intelligence Feed</h3>
            <span>Live classified network events</span>
          </div>
          <ThreatTable threats={threats} onStatusChange={handleStatusChange} />
        </section>
      ) : null}

      {tab === 'analyzer' ? (
        <section className="page-grid">
          <ClassifyPanel
            onToast={showToast}
            onClassified={(data) => setClassifiedType(data?.threat_type || null)}
          />
          <RemediationPanel threatType={classifiedType} />
        </section>
      ) : null}

      {tab === 'reports' ? (
        <section className="page-grid">
          <ReportPanel
            summary={summary}
            onDownload={handleDownload}
            downloading={downloading}
          />
          <div className="panel section">
            <div className="section-head">
              <h3>Report Snapshot</h3>
              <span>Decision support</span>
            </div>
            <div className="snapshot-grid">
              <div>
                <div className="stat-label">Open cases</div>
                <div className="stat-value">{stats?.open_threats ?? '—'}</div>
              </div>
              <div>
                <div className="stat-label">High severity</div>
                <div className="stat-value">{stats?.by_severity?.high ?? 0}</div>
              </div>
              <div>
                <div className="stat-label">Monitor cycles</div>
                <div className="stat-value">{monitor?.cycles_completed ?? 0}</div>
              </div>
            </div>
          </div>
        </section>
      ) : null}

      {tab === 'sources' ? (
        <section className="page-grid sources-page">
          <div className="panel section">
            <div className="section-head">
              <h3>Network Collection</h3>
              <span>Continuous LAN monitoring</span>
            </div>
            <p className="muted source-copy">
              Live host/port/connection scanning runs in the background. Pause anytime, or force an
              immediate scan of the current network.
            </p>
            <div className="action-bar compact">
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
                Refresh
              </button>
            </div>
            <div className="source-status mono">
              <div>
                Status:{' '}
                <strong>
                  {monitor?.scanning
                    ? 'Scanning…'
                    : monitor?.enabled
                      ? 'Monitoring'
                      : 'Paused'}
                </strong>
              </div>
              <div>Interval: {monitor?.interval_seconds ?? '—'}s</div>
              <div>Cycles: {monitor?.cycles_completed ?? 0}</div>
              <div>Subnet: {health?.scan_subnet || monitor?.last_subnet || '—'}</div>
              <div>Local IP: {health?.local_ip || monitor?.last_local_ip || '—'}</div>
              <div>Last message: {monitor?.last_message || '—'}</div>
            </div>
          </div>
          <IngestPanel onIngested={refresh} onToast={showToast} />
        </section>
      ) : null}

      {tab === 'demo' ? (
        <DemoLabPage
          demoFeed={demoFeed}
          onInjectAll={handleInjectAllThreats}
          onToggleAuto={handleToggleDemoFeed}
          injectBusy={injectBusy}
          autoBusy={demoBusy}
          lastInjected={lastInjected}
        />
      ) : null}

      <ThreatPopup items={threatPopups} onDismiss={dismissThreatPopup} />
      {toast ? <div className="toast">{toast}</div> : null}
    </div>
  )
}

export default App
