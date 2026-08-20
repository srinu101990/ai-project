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
import { ClassificationChart, SeverityChart, SourceChart } from './components/ThreatCharts'
import ThreatTable from './components/ThreatTable'
import ClassifyPanel from './components/ClassifyPanel'
import IngestPanel from './components/IngestPanel'
import ReportPanel from './components/ReportPanel'
import LogAnalyzer from './components/LogAnalyzer'
import TopNav from './components/TopNav'
import SystemMetaRow from './components/SystemMetaRow'
import RemediationPanel from './components/RemediationPanel'
import ThreatPopup from './components/ThreatPopup'
import ThreatDetailModal from './components/ThreatDetailModal'
import ThreatDefinitions from './components/ThreatDefinitions'
import MailGuardPanel from './components/MailGuardPanel'
import LiveSourcesPanel from './components/LiveSourcesPanel'
import ConnectedPCs from './components/ConnectedPCs'
import ClientBanner from './components/ClientBanner'
import FileGuardPanel from './components/FileGuardPanel'

function useClock() {
  const [now, setNow] = useState(() => new Date())
  useEffect(() => {
    const timer = window.setInterval(() => setNow(new Date()), 1000)
    return () => window.clearInterval(timer)
  }, [])
  return now
}

function buildLiveStats(rows) {
  const byType = {}
  const bySeverity = {}
  const bySource = {}
  let open = 0
  let confSum = 0
  let confN = 0
  for (const item of rows || []) {
    const type = item.threat_type || 'unknown'
    const severity = item.severity || 'low'
    const source = item.source || 'unknown'
    byType[type] = (byType[type] || 0) + 1
    bySeverity[severity] = (bySeverity[severity] || 0) + 1
    bySource[source] = (bySource[source] || 0) + 1
    if (item.status === 'open' || item.status === 'investigating') open += 1
    if (type !== 'benign') {
      confSum += Number(item.confidence) || 0
      confN += 1
    }
  }
  const ranked = Object.entries(byType).sort((left, right) => right[1] - left[1])
  return {
    total_threats: (rows || []).length,
    open_threats: open,
    by_type: byType,
    by_severity: bySeverity,
    by_source: bySource,
    timeline: [],
    recent_confidence_avg: confN ? confSum / confN : 0,
    top_threat_type: ranked[0] ? ranked[0][0] : '—',
  }
}

function App() {
  const [tab, setTab] = useState('dashboard')
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
  const [sourceStatus, setSourceStatus] = useState(null)
  const [agentStatus, setAgentStatus] = useState(null)
  const [mailStatus, setMailStatus] = useState(null)
  const [sweeping, setSweeping] = useState(false)
  const [bursting, setBursting] = useState(false)
  const [classifiedType, setClassifiedType] = useState(null)
  const [unreadCount, setUnreadCount] = useState(0)
  const [notifications, setNotifications] = useState([])
  const [bellOpen, setBellOpen] = useState(false)
  const [threatPopups, setThreatPopups] = useState([])
  const [detailThreat, setDetailThreat] = useState(null)
  const [fileStatus, setFileStatus] = useState(null)
  const knownThreatIds = useRef(new Set())
  const popupQueue = useRef([])
  const primed = useRef(false)
  const now = useClock()

  const showToast = useCallback((message) => {
    setToast(message)
    window.setTimeout(() => setToast(''), 4200)
  }, [])

  const dismissThreatPopup = useCallback((popupId) => {
    setThreatPopups((prev) => prev.filter((item) => item.popupId !== popupId))
  }, [])

  const pushThreatPopups = useCallback((incoming) => {
    const chronological = [...incoming].reverse()
    popupQueue.current = chronological.slice(0, 1)
  }, [])

  const ingestFromServer = useCallback((incoming) => {
    const rows = (incoming || []).filter((item) => item?.id)
    if (!primed.current) {
      primed.current = true
      for (const item of rows) knownThreatIds.current.add(item.id)
      setThreats(rows.filter((item) => item.threat_type && item.threat_type !== 'benign'))
      return
    }
    const fresh = rows.filter((item) => !knownThreatIds.current.has(item.id))
    for (const item of fresh) knownThreatIds.current.add(item.id)
    const alerts = fresh.filter((item) => item.threat_type && item.threat_type !== 'benign')
    if (!alerts.length) return
    setThreats((prev) => {
      const ids = new Set(prev.map((row) => row.id))
      return [...alerts.filter((row) => !ids.has(row.id)), ...prev]
    })
    setUnreadCount((count) => count + alerts.length)
    setNotifications((prev) => [...alerts].reverse().concat(prev).slice(0, 20))
    pushThreatPopups([alerts[alerts.length - 1]])
  }, [pushThreatPopups])

  const refresh = useCallback(async () => {
    try {
      const [
        threatData,
        reportData,
        healthData,
        monitorData,
        demoData,
        sourceData,
        agentData,
        mailData,
        filesData,
      ] = await Promise.all([
          api.getThreats({ limit: 200 }),
          api.reportSummary(),
          api.health().catch(() => null),
          api.monitorStatus().catch(() => null),
          api.demoFeedStatus().catch(() => null),
          api.liveSources().catch(() => null),
          api.remoteAgents().catch(() => null),
          api.mailStatus().catch(() => null),
          api.fileStatus().catch(() => null),
        ])
      setThreats((prev) => {
        const fresh = new Map((threatData || []).map((item) => [item.id, item]))
        return prev.map((row) => fresh.get(row.id) || row)
      })
      setSummary(reportData)
      if (healthData) setHealth(healthData)
      if (monitorData) setMonitor(monitorData)
      if (demoData) setDemoFeed(demoData)
      if (sourceData) setSourceStatus(sourceData)
      if (agentData) setAgentStatus(agentData)
      if (mailData) setMailStatus(mailData)
      if (filesData) setFileStatus(filesData)
      ingestFromServer(threatData)
      setLastRefresh(new Date())
    } catch (err) {
      showToast(err.message || 'Failed to load dashboard data')
    } finally {
      setLoading(false)
    }
  }, [ingestFromServer, showToast])

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

  useEffect(() => {
    refresh()
    const timer = window.setInterval(refresh, 3000)
    return () => window.clearInterval(timer)
  }, [refresh])

  useEffect(() => {
    if (tab !== 'reports') return undefined
    refresh()
    return undefined
  }, [tab, refresh])

  useEffect(() => {
    const timer = window.setInterval(() => {
      setThreatPopups((prev) => {
        if (prev.length) return prev
        const next = popupQueue.current.shift()
        if (!next) return prev
        return [{ ...next, popupId: `${next.id}-${Date.now()}` }]
      })
    }, 400)
    return () => window.clearInterval(timer)
  }, [])

  useEffect(() => {
    if (!threatPopups[0]) return undefined
    const timer = window.setTimeout(() => {
      dismissThreatPopup(threatPopups[0].popupId)
    }, 5000)
    return () => window.clearTimeout(timer)
  }, [threatPopups, dismissThreatPopup])

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
      const result = await api.collect(1, 'network')
      const detail = [
        result.message || `Collected ${result.events_collected} events`,
        result.live_sources?.length
          ? `${result.live_sources.length} live sources`
          : null,
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

  async function handleSweepSources() {
    setSweeping(true)
    try {
      const result = await api.sweepSources()
      showToast(
        result.message ||
          `Swept ${result.live_sources?.length || 6} sources · ${result.events_collected} events`,
      )
      await refresh()
    } catch (err) {
      showToast(err.message || 'Multi-source sweep failed')
    } finally {
      setSweeping(false)
    }
  }

  async function handleProjectionBurst() {
    setBursting(true)
    try {
      const result = await api.projectionBurst()
      showToast(
        result.message ||
          `Projection burst: ${result.burst_events} sources fired together`,
      )
      await refresh()
    } catch (err) {
      showToast(err.message || 'Projection burst failed')
    } finally {
      setBursting(false)
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
        showToast('Dummy Demo stopped')
      } else {
        const started = await api.startDemoFeed(30)
        setDemoFeed(started)
        showToast('Dummy Demo started — fake catalog events, not a live laptop scan')
      }
      await refresh()
    } catch (err) {
      showToast(err.message || 'Could not update demo feed')
    } finally {
      setDemoBusy(false)
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

  async function handleDownload(filters = {}) {
    setDownloading(true)
    try {
      await api.downloadReport(filters)
      showToast('PDF report downloaded')
      return true
    } catch (err) {
      showToast(err.message || 'Report download failed')
      return false
    } finally {
      setDownloading(false)
    }
  }

  const stats = buildLiveStats(threats)
  const critical = stats.by_severity.critical || 0
  const containedResolved = (threats || []).filter((t) =>
    ['contained', 'resolved'].includes(t.status),
  ).length
  const confidencePct = `${((stats.recent_confidence_avg || 0) * 100).toFixed(1)}%`
  const dominant = stats.top_threat_type
  const latestRemote = (threats || []).find((item) =>
    String(item.source || '').toLowerCase().includes('remote agent'),
  )
  const latestThreat = latestRemote || threats[0] || null
  const orderedThreats = [...(threats || [])].sort((left, right) => {
    const leftRemote = String(left.source || '').toLowerCase().includes('remote agent') ? 0 : 1
    const rightRemote = String(right.source || '').toLowerCase().includes('remote agent') ? 0 : 1
    if (leftRemote !== rightRemote) return leftRemote - rightRemote
    return (right.id || 0) - (left.id || 0)
  })

  const timeLabel = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
  const dateLabel = now
    .toLocaleDateString('en-GB', { day: '2-digit', month: '2-digit', year: 'numeric' })
    .replace(/\//g, '-')
  const demoMenuLabel = demoBusy
    ? 'Updating…'
    : demoFeed?.enabled
      ? demoFeed.current_type
        ? `Stop Dummy · ${demoFeed.current_type}`
        : 'Stop Dummy Demo'
      : 'Dummy Demo'

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
        demoEnabled={Boolean(demoFeed?.enabled)}
        demoBusy={demoBusy}
        demoLabel={demoMenuLabel}
        onDemoToggle={handleToggleDemoFeed}
      />
      <SystemMetaRow health={health} monitor={monitor} lastRefresh={lastRefresh} />
      <ClientBanner agentStatus={agentStatus} />
      {fileStatus ? (
        <div className={`mail-watch-banner ${fileStatus.usb_drives?.length ? 'on' : ''}`}>
          <span className="live-dot" />
          {fileStatus.usb_message || 'USB watch starting…'}
        </div>
      ) : null}

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

          <LiveSourcesPanel
            sourceStatus={sourceStatus}
            onSweep={handleSweepSources}
            onBurst={handleProjectionBurst}
            sweeping={sweeping || collecting}
            bursting={bursting}
          />
        </>
      ) : null}

      {tab === 'threats' ? (
        <section className="threats-page">
          <div className="panel section page-panel">
            <div className="section-head">
              <h3>Threat Intelligence Feed</h3>
              <span>Live classified network events</span>
            </div>
            <ThreatTable
              threats={orderedThreats}
              onStatusChange={handleStatusChange}
              onOpen={setDetailThreat}
            />
          </div>
        </section>
      ) : null}

      {tab === 'known' ? (
        <section className="threats-page">
          <ThreatDefinitions />
        </section>
      ) : null}

      {tab === 'mail' ? (
        <section className="page-grid single">
          <MailGuardPanel
            onToast={showToast}
            onChecked={(data) => setClassifiedType(data?.threat_type || null)}
            onPolled={refresh}
            mailStatus={mailStatus}
          />
        </section>
      ) : null}

      {tab === 'files' ? (
        <section className="page-grid">
          <div className="panel section">
            <div className="section-head">
              <h3>Continuous network scan</h3>
              <span>Entire LAN — not this laptop only</span>
            </div>
            <p className="muted source-copy">
              The dashboard watches the whole subnet in the background: live hosts, risky
              ports, and the six collectors (Network IDS, Endpoint, Firewall, DNS, Email,
              Auth) at the same time. New findings are classified by the AI module and
              appear on Dashboard charts and the Threat Intelligence feed.
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
                    ? 'Pause network scan'
                    : 'Resume network scan'}
              </button>
              <button className="btn btn-primary" onClick={handleCollect} disabled={collecting}>
                <Radar size={16} />
                {collecting ? 'Scanning network…' : 'Scan network now'}
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
                  {monitor?.scanning || sourceStatus?.sweeping
                    ? 'Scanning network…'
                    : monitor?.enabled
                      ? 'Monitoring entire network'
                      : 'Paused'}
                </strong>
              </div>
              <div>Interval: {monitor?.interval_seconds ?? '—'}s</div>
              <div>Cycles: {monitor?.cycles_completed ?? 0}</div>
              <div>
                Live sources: {sourceStatus?.live_source_count ?? 0}/
                {sourceStatus?.source_count ?? 6}
              </div>
              <div>Subnet: {health?.scan_subnet || monitor?.last_subnet || '—'}</div>
              <div>Local IP: {health?.local_ip || monitor?.last_local_ip || '—'}</div>
              <div>Last message: {sourceStatus?.last_message || monitor?.last_message || '—'}</div>
            </div>
          </div>
          <FileGuardPanel
            onToast={showToast}
            onChecked={(data) => setClassifiedType(data?.threat_type || null)}
            fileStatus={fileStatus}
          />
        </section>
      ) : null}

      {tab === 'analyzer' ? (
        <section className="page-grid">
          <ClassifyPanel
            onToast={showToast}
            onClassified={(data) => setClassifiedType(data?.threat_type || null)}
          />
          <RemediationPanel threatType={classifiedType} context="analyzer" />
        </section>
      ) : null}

      {tab === 'reports' ? (
        <section className="page-grid reports-page">
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
                <div className="stat-value">{summary?.open_threats ?? stats?.open_threats ?? '—'}</div>
              </div>
              <div>
                <div className="stat-label">High severity</div>
                <div className="stat-value">{summary?.high_count ?? stats?.by_severity?.high ?? 0}</div>
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
          <SourceChart stats={stats || { by_source: {} }} />
          <IngestPanel onIngested={refresh} onToast={showToast} />
          <ConnectedPCs agentStatus={agentStatus} onToast={showToast} />
        </section>
      ) : null}

      <ThreatPopup items={threatPopups} onDismiss={dismissThreatPopup} />
      <ThreatDetailModal threat={detailThreat} onClose={() => setDetailThreat(null)} />
      {toast ? <div className="toast">{toast}</div> : null}
    </div>
  )
}

export default App
