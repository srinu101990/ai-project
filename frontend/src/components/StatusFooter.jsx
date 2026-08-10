import {
  Activity,
  Cpu,
  Database,
  Network,
  RefreshCw,
  ShieldCheck,
} from 'lucide-react'

export default function StatusFooter({ lastRefresh, onRefresh, loading, health, monitor }) {
  const modeLabel = monitor?.enabled
    ? 'Continuous Network Monitoring'
    : health?.network_detection === false
      ? 'Simulated Collection'
      : 'Live Network Detection'
  const subnet = health?.scan_subnet || monitor?.last_subnet || 'auto subnet'
  const lastScan = monitor?.last_finished_at
    ? new Date(monitor.last_finished_at).toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      })
    : null

  return (
    <footer className="status-footer panel">
      <div className="footer-weather">
        <Network size={18} />
        <span>
          {modeLabel} · {subnet}
          {lastScan ? ` · Last scan ${lastScan}` : ''}
        </span>
      </div>

      <div className="footer-badges">
        <span className={`footer-chip ${monitor?.enabled ? 'live' : 'ok'}`}>
          <Activity size={14} />
          {monitor?.scanning
            ? 'Scanner Running'
            : monitor?.enabled
              ? 'Auto Monitor On'
              : 'Auto Monitor Off'}
        </span>
        <span className="footer-chip ok">
          <ShieldCheck size={14} />
          AI Protection Active
        </span>
        <span className="footer-chip ok">
          <Database size={14} />
          Threat Intel DB Updated
        </span>
        <span className="footer-chip ok">
          <Cpu size={14} />
          Analytics Engine Online
        </span>
      </div>

      <button className="footer-updated" onClick={onRefresh} disabled={loading}>
        <RefreshCw size={14} className={loading ? 'spin' : undefined} />
        Last Updated{' '}
        {lastRefresh
          ? lastRefresh.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
          : '—'}
      </button>
    </footer>
  )
}
