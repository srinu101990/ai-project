import { Copy, Download, MonitorSmartphone } from 'lucide-react'

function formatTime(value) {
  if (!value) return 'waiting'
  try {
    return new Date(value).toLocaleTimeString([], {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    })
  } catch {
    return 'waiting'
  }
}

export default function ConnectedPCs({ agentStatus, onToast }) {
  const agents = agentStatus?.agents || []
  const command = agentStatus?.join_command || 'python sentinel_agent.py --server http://<dashboard-ip>:8000'
  const downloadHref = agentStatus?.agent_download || '/agent/sentinel_agent.py'

  async function copyCommand() {
    try {
      await navigator.clipboard.writeText(command)
      onToast?.('Join command copied')
    } catch {
      onToast?.('Copy failed — select the command manually')
    }
  }

  return (
    <section className="panel section connected-pcs-panel">
      <div className="section-head">
        <h3>Connected PCs</h3>
        <span>
          {agentStatus?.connected ?? 0} remote agent
          {(agentStatus?.connected ?? 0) === 1 ? '' : 's'} online
        </span>
      </div>
      <p className="muted source-copy">
        The dashboard PC cannot read processes inside other computers by itself. Install this
        agent on each PC you are allowed to monitor. That PC then sends hostname, IP, processes,
        and open ports here for AI classification.
      </p>
      <div className="join-box">
        <div className="muted" style={{ fontSize: '0.78rem', marginBottom: '0.35rem' }}>
          On another PC on the same LAN (Python 3, no extra install):
        </div>
        <code className="join-command mono">{command}</code>
        <div className="action-bar compact" style={{ marginTop: '0.7rem', marginBottom: 0 }}>
          <a className="btn btn-primary" href={downloadHref} download="sentinel_agent.py">
            <Download size={16} />
            Download agent
          </a>
          <button type="button" className="btn btn-ghost" onClick={copyCommand}>
            <Copy size={16} />
            Copy command
          </button>
        </div>
      </div>
      {agents.length === 0 ? (
        <div className="empty">No remote PCs yet. Run the agent on a second computer, then wait ~20 seconds.</div>
      ) : (
        <div className="connected-pc-grid">
          {agents.map((pc) => (
            <article
              key={`${pc.hostname}-${pc.source_ip}`}
              className={`live-source-card ${pc.online ? 'online' : 'idle'}`}
            >
              <div className="live-source-top">
                <span className={`live-source-icon ${pc.online ? 'on' : ''}`}>
                  <MonitorSmartphone size={18} />
                </span>
                <span className={`live-source-badge ${pc.online ? 'on' : ''}`}>
                  <span className="live-dot" />
                  {pc.online ? 'LIVE' : 'OFF'}
                </span>
              </div>
              <h4>{pc.hostname}</h4>
              <div className="muted live-source-channel">{pc.os_name || 'Remote PC'}</div>
              <div className="live-source-meta mono">
                <div>IP: {pc.source_ip}</div>
                <div>Last: {pc.last_threat_type || '—'}</div>
                <div>{formatTime(pc.last_seen)}</div>
              </div>
            </article>
          ))}
        </div>
      )}
    </section>
  )
}
