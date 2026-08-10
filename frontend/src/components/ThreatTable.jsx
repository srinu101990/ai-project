const STATUSES = ['open', 'investigating', 'contained', 'resolved']

export default function ThreatTable({ threats, onStatusChange }) {
  if (!threats?.length) {
    return <div className="empty">No threat events yet. Run a network collection scan.</div>
  }

  return (
    <div className="threat-table-wrap">
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Type</th>
            <th>Severity</th>
            <th>Source</th>
            <th>Origin</th>
            <th>IPs</th>
            <th>Confidence</th>
            <th>Status</th>
            <th>Payload</th>
          </tr>
        </thead>
        <tbody>
          {threats.map((threat) => (
            <tr key={threat.id}>
              <td className="mono">#{threat.id}</td>
              <td>
                <span className={`badge ${threat.threat_type}`}>{threat.threat_type}</span>
              </td>
              <td>
                <span className={`badge ${threat.severity}`}>{threat.severity}</span>
              </td>
              <td>
                <div>{threat.source}</div>
                <div className="muted mono">{threat.protocol}</div>
              </td>
              <td>
                <span className={`badge ${threat.is_simulated ? 'benign' : 'malware'}`}>
                  {threat.is_simulated ? 'simulated' : 'live'}
                </span>
              </td>
              <td className="mono">
                <div>{threat.source_ip}</div>
                <div className="muted">{threat.destination_ip || '—'}</div>
              </td>
              <td className="mono">{Math.round(threat.confidence * 100)}%</td>
              <td>
                <select
                  className="status-select"
                  value={threat.status}
                  onChange={(e) => onStatusChange(threat.id, e.target.value)}
                >
                  {STATUSES.map((status) => (
                    <option key={status} value={status}>
                      {status}
                    </option>
                  ))}
                </select>
              </td>
              <td style={{ maxWidth: 220 }}>
                <div className="muted" style={{ fontSize: '0.82rem', lineHeight: 1.4 }}>
                  {threat.raw_payload.slice(0, 90)}
                  {threat.raw_payload.length > 90 ? '…' : ''}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
