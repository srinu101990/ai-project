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
  const injectCommand =
    agentStatus?.inject_command || `${command} --inject phishing`
  const injectAllCommand =
    agentStatus?.inject_all_command || `${command} --inject-all --delay 8`
  const downloadHref = agentStatus?.agent_download || '/agent/sentinel_agent.py'
  const launcherHref = agentStatus?.agent_launcher || '/agent/start-agent.bat'
  const lanUrl = agentStatus?.lan_url || ''

  async function copyText(value, label) {
    try {
      await navigator.clipboard.writeText(value)
      onToast?.(label)
    } catch {
      onToast?.('Copy failed — select the command manually')
    }
  }

  return (
    <section className="panel section connected-pcs-panel">
      <div className="section-head">
        <h3>Laptop live demo</h3>
        <span>
          {agentStatus?.connected ?? 0} remote PC
          {(agentStatus?.connected ?? 0) === 1 ? '' : 's'} online
        </span>
      </div>
      <p className="muted source-copy">
        This dashboard scans the LAN in real time. To show mail and malware from{' '}
        <strong> another laptop</strong>, run the agent on that PC (same Wi-Fi). When you
        send a phishing mail or inject virus / worm / trojan / ransomware there, this
        screen pops up, the charts update, and the threat feed lists it as if the whole
        network is being watched.
      </p>
      {lanUrl ? (
        <div className="muted mono" style={{ fontSize: '0.78rem', marginBottom: '0.7rem' }}>
          Main laptop LAN URL (allow Windows Firewall): {lanUrl}
        </div>
      ) : null}
      <p className="muted source-copy">
        Use the IPv4 under <strong>Wireless LAN adapter Wi-Fi</strong> only. Ignore
        VMware <code>192.168.x</code> adapters. Phone hotspot IPs often look like{' '}
        <code>192.168.43.x</code> (Android) or <code>172.20.10.x</code> (iPhone); some
        hotspots use <code>10.x</code>. Both laptops must show the same first three
        numbers.
      </p>
      <ol className="mail-steps">
        <li>On the second laptop, copy <code>agent/</code> or download the files below.</li>
        <li>
          Double-click <code>start-agent.bat</code> (or run the watch command) and paste the
          LAN URL.
        </li>
        <li>
          Wait until this card shows <strong>LIVE</strong>, then inject <strong>phishing</strong>.
          A popup appears here within a few seconds.
        </li>
        <li>Inject the other malware types one by one. Graphs update as each family arrives.</li>
      </ol>
      <div className="join-box">
        <div className="muted" style={{ fontSize: '0.78rem', marginBottom: '0.35rem' }}>
          Watch command (leave it running):
        </div>
        <code className="join-command mono">{command}</code>
        <div className="muted" style={{ fontSize: '0.78rem', margin: '0.65rem 0 0.35rem' }}>
          Phishing from that laptop:
        </div>
        <code className="join-command mono">{injectCommand}</code>
        <div className="muted" style={{ fontSize: '0.78rem', margin: '0.65rem 0 0.35rem' }}>
          Every family, one by one:
        </div>
        <code className="join-command mono">{injectAllCommand}</code>
        <div className="action-bar compact" style={{ marginTop: '0.7rem', marginBottom: 0 }}>
          <a className="btn btn-primary" href={downloadHref} download="sentinel_agent.py">
            <Download size={16} />
            Download agent
          </a>
          <a className="btn btn-secondary" href={launcherHref} download="start-agent.bat">
            <Download size={16} />
            Download start-agent.bat
          </a>
          <button type="button" className="btn btn-ghost" onClick={() => copyText(command, 'Watch command copied')}>
            <Copy size={16} />
            Copy watch command
          </button>
          <button
            type="button"
            className="btn btn-ghost"
            onClick={() => copyText(injectCommand, 'Phishing inject command copied')}
          >
            <Copy size={16} />
            Copy phishing inject
          </button>
        </div>
      </div>
      {agents.length === 0 ? (
        <div className="empty">
          No second laptop yet. Start the agent on the other PC, then wait a few seconds.
        </div>
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
