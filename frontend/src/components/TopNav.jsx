import NotificationBell from './NotificationBell'

const TABS = [
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'threats', label: 'Threat Intelligence' },
  { id: 'analyzer', label: 'AI Analyzer' },
  { id: 'reports', label: 'Reports' },
  { id: 'sources', label: 'Sources' },
  { id: 'demo', label: 'Threat Demo' },
]

export default function TopNav({
  active,
  onChange,
  unreadCount = 0,
  notifications = [],
  bellOpen = false,
  onBellToggle,
  onClearNotifications,
  onSelectNotification,
}) {
  return (
    <nav className="top-nav" aria-label="Main sections">
      <div className="top-nav-tabs">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            type="button"
            className={`nav-tab ${active === tab.id ? 'active' : ''}`}
            onClick={() => onChange(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </div>
      <NotificationBell
        count={unreadCount}
        open={bellOpen}
        notifications={notifications}
        onToggle={onBellToggle}
        onClear={onClearNotifications}
        onSelect={onSelectNotification}
      />
    </nav>
  )
}
