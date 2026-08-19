import { Activity, Globe, Mail, Network, Radar, Server } from 'lucide-react'

const FALLBACK_SOURCES = [
  {
    source_id: 'ids',
    source_name: 'Network IDS Sensor',
    channel: 'LAN hosts & risky ports',
    description: 'TCP probes of nearby hosts for SMB, RDP, Telnet, and database exposure.',
    online: false,
    observed: 0,
    findings: 0,
    message: 'Waiting for first collection cycle.',
  },
  {
    source_id: 'endpoint',
    source_name: 'Endpoint Detection Agent',
    channel: 'Local processes',
    description: 'Inspects running processes and command lines on this workstation.',
    online: false,
    observed: 0,
    findings: 0,
    message: 'Waiting for first collection cycle.',
  },
  {
    source_id: 'firewall',
    source_name: 'Firewall Flow Logs',
    channel: 'TCP/UDP sessions',
    description: 'Reads the live socket table for listeners and suspicious outbound flows.',
    online: false,
    observed: 0,
    findings: 0,
    message: 'Waiting for first collection cycle.',
  },
  {
    source_id: 'dns',
    source_name: 'DNS Sinkhole',
    channel: 'Port 53 / resolver',
    description: 'Watches DNS client and server sessions for query or sinkhole activity.',
    online: false,
    observed: 0,
    findings: 0,
    message: 'Waiting for first collection cycle.',
  },
  {
    source_id: 'email',
    source_name: 'Email Gateway',
    channel: 'SMTP / IMAP / POP',
    description: 'Monitors mail-protocol listeners and sessions used in phishing delivery.',
    online: false,
    observed: 0,
    findings: 0,
    message: 'Waiting for first collection cycle.',
  },
  {
    source_id: 'proxy',
    source_name: 'Web Proxy',
    channel: 'HTTP-alt / proxy ports',
    description: 'Tracks web-proxy listeners and outbound HTTP(S) sessions on the host.',
    online: false,
    observed: 0,
    findings: 0,
    message: 'Waiting for first collection cycle.',
  },
]

const ICONS = {
  ids: Radar,
  endpoint: Activity,
  firewall: Network,
  dns: Globe,
  email: Mail,
  proxy: Server,
}

function formatTime(value) {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '—'
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

export default function LiveSourcesPanel({ catalog }) {
  const sources = catalog?.sources?.length ? catalog.sources : FALLBACK_SOURCES

  return (
    <div className="panel section">
      <div className="section-head">
        <h3>Simultaneous Network Sources</h3>
        <span>
          {catalog?.hostname ? `${catalog.hostname}` : 'Live sensors'} ·{' '}
          {catalog?.source_count || sources.length || 6} collectors
        </span>
      </div>
      <p className="muted source-copy">
        Step 1 collects cyber threat information from the network using six sensors at the same
        time: LAN IDS, endpoint processes, firewall flows, DNS, email, and web proxy.
      </p>
      <div className="sources-grid">
        {sources.map((source) => {
          const Icon = ICONS[source.source_id] || Radar
          return (
            <article
              key={source.source_id}
              className={`source-card ${source.online ? 'online' : 'idle'}`}
            >
              <div className="source-card-head">
                <div className="source-icon">
                  <Icon size={16} />
                </div>
                <div>
                  <h4>{source.source_name}</h4>
                  <span className="source-channel">{source.channel}</span>
                </div>
                <span className={`source-pill ${source.online ? 'on' : 'off'}`}>
                  <span className="source-dot" />
                  {source.online ? 'ONLINE' : 'IDLE'}
                </span>
              </div>
              <p className="source-desc">{source.description}</p>
              <div className="source-metrics mono">
                <span>Observed {source.observed ?? 0}</span>
                <span>Findings {source.findings ?? 0}</span>
                <span>{formatTime(source.last_at)}</span>
              </div>
              <div className="source-msg">{source.message || 'Waiting for first collection cycle.'}</div>
            </article>
          )
        })}
      </div>
    </div>
  )
}
