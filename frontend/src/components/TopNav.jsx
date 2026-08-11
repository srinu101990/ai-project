const TABS = [
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'threats', label: 'Threat Intelligence' },
  { id: 'analyzer', label: 'AI Analyzer' },
  { id: 'reports', label: 'Reports' },
  { id: 'sources', label: 'Sources' },
]

export default function TopNav({ active, onChange }) {
  return (
    <nav className="top-nav" aria-label="Main sections">
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
    </nav>
  )
}
