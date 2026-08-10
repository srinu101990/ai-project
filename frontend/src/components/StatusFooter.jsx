import {
  Activity,
  Cpu,
  Database,
  Network,
  RefreshCw,
  ShieldCheck,
} from 'lucide-react'

export default function StatusFooter({ lastRefresh, onRefresh, loading, health }) {
  const modeLabel =
    health?.network_detection === false ? 'Simulated Collection' : 'Live Network Detection'
  const subnet = health?.scan_subnet || 'auto subnet'

  return (
    <footer className="status-footer panel">
      <div className="footer-weather">
        <Network size={18} />
        <span>
          {modeLabel} · {subnet}
        </span>
      </div>

      <div className="footer-badges">
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
        <span className="footer-chip live">
          <Activity size={14} />
          Dashboard Status Live
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
