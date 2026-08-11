export default function SystemMetaRow({
  health,
  monitor,
  lastRefresh,
  demoFeed,
  onToggleDemo,
  demoBusy,
}) {
  const mode = monitor?.enabled
    ? 'NETWORK'
    : health?.network_detection === false
      ? 'SIMULATED'
      : 'LOCAL'
  const source = monitor?.enabled
    ? `Live LAN Scan · ${health?.scan_subnet || 'auto subnet'}`
    : 'Manual / Network · SQLite'
  const updated = lastRefresh
    ? lastRefresh.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
    : '—'

  const demoLabel = demoBusy
    ? 'Updating…'
    : demoFeed?.enabled
      ? demoFeed.current_type
        ? `Stop Demo · ${demoFeed.current_type}`
        : 'Stop Threat Demo'
      : 'Threat Demo'

  return (
    <section className="meta-row with-action" aria-label="System metadata">
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
      <div className="meta-pill meta-pill-action">
        <div className="meta-updated-block">
          <span className="meta-label">Last Updated</span>
          <strong className="mono">{updated}</strong>
        </div>
        <button
          type="button"
          className={`btn meta-demo-btn ${demoFeed?.enabled ? 'btn-ghost' : 'btn-primary'}`}
          onClick={onToggleDemo}
          disabled={demoBusy}
          title={
            demoFeed?.enabled
              ? `Sequential demo running. Next: ${demoFeed.next_type || '—'}`
              : 'Start sequential threat demo (one type every 30s)'
          }
        >
          {demoLabel}
        </button>
      </div>
    </section>
  )
}
