import { useEffect, useRef } from 'react'
import { Bell } from 'lucide-react'

export default function NotificationBell({
  count = 0,
  open = false,
  notifications = [],
  onToggle,
  onClear,
  onSelect,
}) {
  const rootRef = useRef(null)

  useEffect(() => {
    if (!open) return undefined
    function onPointerDown(event) {
      if (rootRef.current && !rootRef.current.contains(event.target)) {
        onToggle(false)
      }
    }
    function onKeyDown(event) {
      if (event.key === 'Escape') onToggle(false)
    }
    document.addEventListener('pointerdown', onPointerDown)
    document.addEventListener('keydown', onKeyDown)
    return () => {
      document.removeEventListener('pointerdown', onPointerDown)
      document.removeEventListener('keydown', onKeyDown)
    }
  }, [open, onToggle])

  const badge = count > 99 ? '99+' : String(count)

  return (
    <div className="notif-bell-wrap" ref={rootRef}>
      <button
        type="button"
        className={`notif-bell ${open ? 'open' : ''} ${count > 0 ? 'has-new' : ''}`}
        aria-label={count > 0 ? `${count} new detections` : 'Notifications'}
        aria-expanded={open}
        aria-haspopup="true"
        onClick={() => onToggle(!open)}
      >
        <Bell size={18} />
        {count > 0 ? <span className="notif-badge">{badge}</span> : null}
      </button>

      {open ? (
        <div className="notif-panel" role="dialog" aria-label="New detections">
          <div className="notif-panel-head">
            <strong>New Detections</strong>
            <button type="button" className="notif-clear" onClick={onClear} disabled={count === 0}>
              Clear
            </button>
          </div>
          {notifications.length === 0 ? (
            <div className="notif-empty">No new detections</div>
          ) : (
            <ul className="notif-list">
              {notifications.map((item) => (
                <li key={item.id}>
                  <button
                    type="button"
                    className="notif-item"
                    onClick={() => onSelect?.(item)}
                  >
                    <span className={`badge ${item.threat_type}`}>{item.threat_type}</span>
                    <span className="notif-item-body">
                      <strong>{item.source || 'Unknown source'}</strong>
                      <span className="mono muted">
                        {(item.severity || 'info').toUpperCase()}
                        {item.protocol ? ` · ${item.protocol}` : ''}
                      </span>
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      ) : null}
    </div>
  )
}
