import { useEffect } from 'react'
import { createPortal } from 'react-dom'
import { ShieldAlert, X } from 'lucide-react'

export default function ThreatPopup({ items = [], onDismiss }) {
  const item = items[0] || null

  useEffect(() => {
    if (!item) return undefined
    function onKeyDown(event) {
      if (event.key === 'Escape') onDismiss(item.popupId)
    }
    document.addEventListener('keydown', onKeyDown)
    return () => document.removeEventListener('keydown', onKeyDown)
  }, [item, onDismiss])

  if (!item || typeof document === 'undefined') return null

  return createPortal(
    <div
      className="threat-popup-overlay"
      role="presentation"
      onClick={() => onDismiss(item.popupId)}
    >
      <div
        className={`threat-popup-modal severity-${item.severity || 'medium'}`}
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="threat-popup-title"
        aria-describedby="threat-popup-message"
        onClick={(event) => event.stopPropagation()}
      >
        <button
          type="button"
          className="threat-popup-close"
          aria-label="Close alert"
          onClick={() => onDismiss(item.popupId)}
        >
          <X size={18} />
        </button>

        <div className="threat-popup-icon" aria-hidden="true">
          <ShieldAlert size={28} />
        </div>

        <h3 id="threat-popup-title" className="threat-popup-heading">
          {(item.threat_type || 'threat').replace(/-/g, ' ').toUpperCase()} DETECTED
        </h3>

        <div className="threat-popup-title" id="threat-popup-message">
          <span className={`badge ${item.threat_type}`}>{item.threat_type}</span>
          <strong>{item.source || 'Unknown source'}</strong>
        </div>

        <p className="threat-popup-body">
          {item.raw_payload || 'A new detection was classified by CYBER_SENTINEL.AI.'}
        </p>

        <div className="threat-popup-meta mono muted">
          {(item.severity || 'info').toUpperCase()}
          {item.protocol ? ` · ${item.protocol}` : ''}
          {item.status ? ` · ${item.status}` : ''}
          {items.length > 1 ? ` · +${items.length - 1} more waiting` : ''}
        </div>

        <button
          type="button"
          className="btn btn-primary threat-popup-ok"
          onClick={() => onDismiss(item.popupId)}
        >
          Close
        </button>
      </div>
    </div>,
    document.body,
  )
}
