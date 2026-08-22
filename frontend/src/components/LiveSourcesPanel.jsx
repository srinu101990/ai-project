import {
  Mail,
  Network,
  Radar,
  Shield,
  ShieldCheck,
  Sparkles,
  Waypoints,
} from 'lucide-react'

const ICONS = {
  ids: Network,
  endpoint: Shield,
  firewall: ShieldCheck,
  dns: Waypoints,
  email: Mail,
  auth: Radar,
}

const FALLBACK = [
  { id: 'ids', name: 'Network IDS Sensor', channel: 'LAN hosts & risky ports' },
  { id: 'endpoint', name: 'Endpoint Detection Agent', channel: 'Local processes' },
  { id: 'firewall', name: 'Firewall Flow Logs', channel: 'TCP/UDP sessions' },
  { id: 'dns', name: 'DNS Sinkhole', channel: 'Port 53 / resolver' },
  { id: 'email', name: 'Email Gateway', channel: 'SMTP / IMAP / POP' },
  { id: 'auth', name: 'Auth Gateway', channel: 'SSH / RDP / VNC' },
]

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

export default function LiveSourcesPanel({
  sourceStatus,
  onSweep,
  onBurst,
  sweeping,
  bursting,
}) {
  const rows = sourceStatus?.sources?.length ? sourceStatus.sources : FALLBACK
  const liveCount = sourceStatus?.live_source_count ?? rows.filter((row) => row.online).length
  const total = sourceStatus?.source_count ?? rows.length

  return (
    <section className="panel section live-sources-panel">
      <div className="section-head">
        <h3>Live Multi-Source Collection</h3>
        <span>
          {liveCount}/{total} sources streaming in parallel
        </span>
      </div>
      <p className="muted source-copy">
        Six collectors inspect different channels at the same time: LAN hosts, endpoint
        processes, firewall sockets, DNS, email, and login services. That is the live
        network scan. Use Sweep All Sources Now during the demo; Projection Burst lights
        every card at once so you can say the pipeline watches the whole LAN.
      </p>
      <div className="action-bar compact">
        <button className="btn btn-primary" onClick={onSweep} disabled={sweeping || bursting}>
          <Radar size={16} />
          {sweeping ? 'Sweeping all sources…' : 'Sweep All Sources Now'}
        </button>
        <button className="btn btn-secondary" onClick={onBurst} disabled={sweeping || bursting}>
          <Sparkles size={16} />
          {bursting ? 'Firing burst…' : 'Projection Burst'}
        </button>
      </div>
      <div className="live-source-grid">
        {rows.map((source) => {
          const Icon = ICONS[source.id] || Shield
          const online = Boolean(source.online)
          return (
            <article
              key={source.id}
              className={`live-source-card ${online ? 'online' : 'idle'} ${
                source.sweeping ? 'sweeping' : ''
              }`}
            >
              <div className="live-source-top">
                <span className={`live-source-icon ${online ? 'on' : ''}`}>
                  <Icon size={18} />
                </span>
                <span className={`live-source-badge ${online ? 'on' : ''}`}>
                  <span className="live-dot" />
                  {source.sweeping ? 'SWEEP' : online ? 'LIVE' : 'IDLE'}
                </span>
              </div>
              <h4>{source.name}</h4>
              <div className="muted live-source-channel">{source.channel}</div>
              <div className="live-source-meta mono">
                <div>Events: {source.events_stored ?? 0}</div>
                <div>Last: {source.last_threat_type || '—'}</div>
                <div>{formatTime(source.last_at)}</div>
              </div>
            </article>
          )
        })}
      </div>
    </section>
  )
}
