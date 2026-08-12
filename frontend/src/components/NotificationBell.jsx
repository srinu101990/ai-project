import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
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
  const buttonRef = useRef(null)
  const panelRef = useRef(null)
  const [panelStyle, setPanelStyle] = useState(null)

  useLayoutEffect(() => {
    if (!open || !buttonRef.current) {
      setPanelStyle(null)
      return undefined
    }

    function placePanel() {
      const rect = buttonRef.current.getBoundingClientRect()
      const width = Math.min(320, window.innerWidth - 16)
      const left = Math.min(
        Math.max(8, rect.right - width),
        window.innerWidth - width - 8,
      )
      const top = Math.min(rect.bottom + 8, window.innerHeight - 120)
      setPanelStyle({
        position: 'fixed',
        top: `${top}px`,
        left: `${left}px`,
        width: `${width}px`,
        maxHeight: `${Math.max(160, window.innerHeight - top - 12)}px`,
        zIndex: 10000,
      })
    }

    placePanel()
    window.addEventListener('resize', placePanel)
    window.addEventListener('scroll', placePanel, true)
    return () => {
      window.removeEventListener('resize', placePanel)
      window.removeEventListener('scroll', placePanel, true)
    }
  }, [open])

  useEffect(() => {
    if (!open) return undefined
    function onPointerDown(event) {
      const target = event.target
      const inBell = rootRef.current?.contains(target)
      const inPanel = panelRef.current?.contains(target)
      if (!inBell && !inPanel) onToggle(false)
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

  const panel =
    open && typeof document !== 'undefined'
      ? createPortal(
          <div
            ref={panelRef}
            className="notif-panel"
            role="dialog"
            aria-label="New detections"
            style={panelStyle || undefined}
          >
            <div className="notif-panel-head">
              <strong>New Detections</strong>
              <button
                type="button"
                className="notif-clear"
                onClick={onClear}
                disabled={count === 0}
              >
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
          </div>,
          document.body,
        )
      : null

  return (
    <div className="notif-bell-wrap" ref={rootRef}>
      <button
        ref={buttonRef}
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
      {panel}
    </div>
  )
}
