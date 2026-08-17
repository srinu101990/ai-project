import { useEffect } from 'react'
import { createPortal } from 'react-dom'
import { X } from 'lucide-react'

export default function ThreatDetailModal({ threat, onClose }) {
  useEffect(() => {
    if (!threat) return undefined
    function onKeyDown(event) {
      if (event.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', onKeyDown)
    return () => document.removeEventListener('keydown', onKeyDown)
  }, [threat, onClose])

  if (!threat || typeof document === 'undefined') return null

  return createPortal(
    <div className="threat-popup-overlay" role="presentation" onClick={onClose}>
      <div
        className={`threat-popup-modal threat-detail-modal severity-${threat.severity || 'medium'}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby="threat-detail-title"
        onClick={(event) => event.stopPropagation()}
      >
        <button
          type="button"
          className="threat-popup-close"
          aria-label="Close details"
          onClick={onClose}
        >
          <X size={18} />
        </button>
        <h3 id="threat-detail-title" className="threat-popup-heading">
          Event #{threat.id}
        </h3>
        <div className="threat-popup-title">
          <span className={`badge ${threat.threat_type}`}>{threat.threat_type}</span>
          <span className={`badge ${threat.severity}`}>{threat.severity}</span>
          <strong>{threat.source || 'Unknown source'}</strong>
        </div>
        <dl className="threat-detail-grid mono">
          <div>
            <dt>Protocol</dt>
            <dd>{threat.protocol || '—'}</dd>
          </div>
          <div>
            <dt>Source IP</dt>
            <dd>{threat.source_ip || '—'}</dd>
          </div>
          <div>
            <dt>Destination</dt>
            <dd>{threat.destination_ip || '—'}</dd>
          </div>
          <div>
            <dt>Confidence</dt>
            <dd>{Math.round((threat.confidence || 0) * 100)}%</dd>
          </div>
          <div>
            <dt>Status</dt>
            <dd>{threat.status || '—'}</dd>
          </div>
          <div>
            <dt>Origin</dt>
            <dd>{threat.is_simulated ? 'simulated' : 'live'}</dd>
          </div>
        </dl>
        {threat.indicators ? (
          <p className="muted" style={{ textAlign: 'left', fontSize: '0.82rem' }}>
            {threat.indicators}
          </p>
        ) : null}
        <pre className="threat-detail-payload">{threat.raw_payload || 'No payload stored.'}</pre>
        <button type="button" className="btn btn-primary threat-popup-ok" onClick={onClose}>
          Close
        </button>
      </div>
    </div>,
    document.body,
  )
}
