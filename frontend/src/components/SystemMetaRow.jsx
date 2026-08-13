export default function SystemMetaRow({ health, monitor, lastRefresh }) {
  const mode = monitor?.enabled
    ? 'NETWORK'
    : health?.network_detection === false
      ? 'SIMULATED'
      : 'LOCAL'
  const source = monitor?.enabled
    ? `${health?.live_source_count || 6} live sources · ${health?.scan_subnet || 'auto subnet'}`
    : 'Manual / Network · SQLite'
  const updated = lastRefresh
    ? lastRefresh.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
    : '—'

  return (
    <section className="meta-row" aria-label="System metadata">
      <div className="meta-pill">
        <span className="meta-label">System Mode</span>
        <strong>{mode}</strong>
      </div>
      <div className="meta-pill">
        <span className="meta-label">Data Source</span>
        <strong>{source}</strong>
      </div>
      <div className="meta-pill">
        <span className="meta-label">AI Engine</span>
        <strong>Local Model</strong>
      </div>
      <div className="meta-pill">
        <span className="meta-label">Last Updated</span>
        <strong className="mono">{updated}</strong>
      </div>
    </section>
  )
}
