import { UserRound } from 'lucide-react'

export default function LogAnalyzer({ threat }) {
  if (!threat) {
    return (
      <div className="panel section log-analyzer">
        <div className="section-head">
          <h3>Log Analyzer Terminal</h3>
          <span className="term-badge">IDLE</span>
        </div>
        <div className="empty">Awaiting network telemetry…</div>
      </div>
    )
  }

  return (
    <div className="panel section log-analyzer">
      <div className="section-head">
        <h3>Log Analyzer Terminal</h3>
        <span className="term-badge">LIVE</span>
      </div>

      <div className="log-terminal">
        <div className="log-meta">
          <div>
            <span className="log-label">Target / Source IP</span>
            <div className="log-value mono">{threat.source_ip}</div>
          </div>
          <div>
            <span className="log-label">Destination</span>
            <div className="log-value mono">{threat.destination_ip || '—'}</div>
          </div>
        </div>

        <div className="log-payload-block">
          <div className="log-art" aria-hidden="true">
            <UserRound size={42} strokeWidth={1.4} />
          </div>
          <div>
            <span className="log-label">Log Payload / Incident Text</span>
            <p className="log-payload">{threat.raw_payload}</p>
          </div>
        </div>

        <div className="log-footer-row">
          <span className={`badge ${threat.threat_type}`}>{threat.threat_type}</span>
          <span className={`badge ${threat.severity}`}>{threat.severity}</span>
          <span className="mono muted">
            conf {Math.round((threat.confidence || 0) * 100)}%
          </span>
          <span className="mono muted">{threat.protocol}</span>
        </div>
      </div>
    </div>
  )
}
