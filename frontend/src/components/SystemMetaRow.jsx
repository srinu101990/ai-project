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
        <strong title={(health?.lan_ips || []).join(', ') || undefined}>
          {health?.lan_ip
            ? `LAN ${health.lan_ip} · ${health?.live_source_count || 6} sources${
                health?.connected_agents
                  ? ` · ${health.connected_agents} remote PC${
                      health.connected_agents === 1 ? '' : 's'
                    }`
                  : ''
              }`
            : source}
        </strong>
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
