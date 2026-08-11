import { cityForThreat } from '../utils/cities'

export default function RecentAlerts({ threats }) {
  const alerts = (threats || []).slice(0, 8)

  return (
    <div className="panel section alerts-panel">
      <div className="section-head">
        <h3>Recent Security Alerts</h3>
        <span>Live feed</span>
      </div>

      {alerts.length === 0 ? (
        <div className="empty">No alerts yet — network monitor is listening…</div>
      ) : (
        <ul className="alert-list">
          {alerts.map((threat) => (
            <li key={threat.id} className="alert-item">
              <div className="alert-main">
                <div className="alert-title">
                  <span className={`badge ${threat.threat_type}`}>{threat.threat_type}</span>
                  <strong>· {cityForThreat(threat)}</strong>
                </div>
                <div className="alert-meta mono muted">
                  {threat.source} · {threat.protocol || 'TCP'} · {threat.status}
                </div>
              </div>
              <span className={`badge ${threat.severity}`}>{threat.severity}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
