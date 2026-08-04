import {
  CloudSun,
  Database,
  Activity,
  ShieldCheck,
  RefreshCw,
  Cpu,
} from 'lucide-react'

export default function StatusFooter({ lastRefresh, onRefresh, loading }) {
  return (
    <footer className="status-footer panel">
      <div className="footer-weather">
        <CloudSun size={18} />
        <span>27°C Partly Sunny</span>
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
