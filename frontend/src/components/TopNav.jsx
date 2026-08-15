import NotificationBell from './NotificationBell'

const TABS = [
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'threats', label: 'Threat Intelligence' },
  { id: 'mail', label: 'My Mail' },
  { id: 'files', label: 'Network Scan' },
  { id: 'analyzer', label: 'AI Analyzer' },
  { id: 'reports', label: 'Reports' },
  { id: 'sources', label: 'Sources' },
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
  demoEnabled = false,
  demoBusy = false,
  demoLabel = 'Threat Demo',
  onDemoToggle,
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
        <button
          type="button"
          className={`nav-tab nav-demo-tab ${demoEnabled ? 'demo-active' : ''}`}
          onClick={onDemoToggle}
          disabled={demoBusy}
          title={
            demoEnabled
              ? 'Stop dummy catalog feed'
              : 'Dummy Demo injects fake catalog events — not a live laptop scan'
          }
        >
          {demoBusy ? 'Updating…' : demoLabel}
        </button>
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
