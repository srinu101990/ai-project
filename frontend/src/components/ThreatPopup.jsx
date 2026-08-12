export default function ThreatPopup({ items = [], onDismiss }) {
  if (!items.length) return null

  return (
    <div className="threat-popup-stack" aria-live="polite" aria-atomic="false">
      {items.map((item) => (
        <div
          key={item.popupId}
          className={`threat-popup severity-${item.severity || 'medium'}`}
          role="status"
        >
          <div className="threat-popup-head">
            <span className="threat-popup-label">New Threat Detected</span>
            <button
              type="button"
              className="threat-popup-close"
              aria-label="Dismiss notification"
              onClick={() => onDismiss(item.popupId)}
            >
              ×
            </button>
          </div>
          <div className="threat-popup-title">
            <span className={`badge ${item.threat_type}`}>{item.threat_type}</span>
            <strong>{item.source || 'Unknown source'}</strong>
          </div>
          <div className="threat-popup-meta mono muted">
            {(item.severity || 'info').toUpperCase()}
            {item.protocol ? ` · ${item.protocol}` : ''}
            {item.status ? ` · ${item.status}` : ''}
          </div>
        </div>
      ))}
    </div>
  )
}
