import {
  Bug,
  Fish,
  KeyRound,
  LockKeyhole,
  PauseCircle,
  PlayCircle,
  ShieldCheck,
  Sparkles,
  Users,
  Wifi,
} from 'lucide-react'
import ThreatDefinitions from './ThreatDefinitions'

const TYPE_ICONS = {
  phishing: Fish,
  malware: Bug,
  ransomware: LockKeyhole,
  ddos: Wifi,
  'brute-force': KeyRound,
  'brute force': KeyRound,
  social: Users,
  benign: ShieldCheck,
}

export default function DemoLabPage({
  demoFeed,
  onInjectAll,
  onToggleAuto,
  injectBusy,
  autoBusy,
  lastInjected = [],
}) {
  const types =
    demoFeed?.supported_types?.length > 0
      ? demoFeed.supported_types
      : ['phishing', 'malware', 'ransomware', 'ddos', 'brute-force', 'social', 'benign']

  return (
    <section className="demo-lab">
      <div className="panel section demo-hero">
        <div className="section-head">
          <h3>Threat Demo Lab</h3>
          <span>Separate presentation page</span>
        </div>
        <p className="muted source-copy">
          Use <strong>Inject All Threat Types</strong> for a one-shot demo, or start sequential mode
          (one virus type every 30 seconds). You can also start sequential mode from the Dashboard
          <strong> Threat Demo</strong> button beside Last Updated.
        </p>

        <div className="demo-type-grid">
          {types.map((type) => {
            const Icon = TYPE_ICONS[type] || Sparkles
            return (
              <div key={type} className="demo-type-chip">
                <Icon size={16} />
                <span>{type}</span>
              </div>
            )
          })}
        </div>

        <div className="action-bar compact">
          <button className="btn btn-primary" onClick={onInjectAll} disabled={injectBusy}>
            <Sparkles size={16} />
            {injectBusy ? 'Injecting all threats…' : 'Inject All Threat Types'}
          </button>
          <button
            className={`btn ${demoFeed?.enabled ? 'btn-ghost' : 'btn-secondary'}`}
            onClick={onToggleAuto}
            disabled={autoBusy}
          >
            {demoFeed?.enabled ? <PauseCircle size={16} /> : <PlayCircle size={16} />}
            {autoBusy
              ? 'Updating…'
              : demoFeed?.enabled
                ? 'Stop Sequential Demo'
                : 'Start Sequential (30s)'}
          </button>
        </div>

        <div className="source-status mono">
          <div>
            Status:{' '}
            <strong>
              {demoFeed?.injecting
                ? 'Classifying…'
                : demoFeed?.enabled
                  ? 'Auto demo running'
                  : 'Ready'}
            </strong>
          </div>
          <div>Last cycle types: {(demoFeed?.last_types || []).join(', ') || '—'}</div>
          <div>Cycles completed: {demoFeed?.cycles_completed ?? 0}</div>
          <div>Message: {demoFeed?.last_message || '—'}</div>
        </div>
      </div>

      <ThreatDefinitions />

      <div className="panel section">
        <div className="section-head">
          <h3>Last AI Classifications</h3>
          <span>From Demo Lab inject</span>
        </div>
        {lastInjected.length === 0 ? (
          <div className="empty">Click “Inject All Threat Types” to see AI classifications here.</div>
        ) : (
          <div className="demo-result-grid">
            {lastInjected.map((item) => (
              <article key={`${item.id}-${item.threat_type}`} className="demo-result-card">
                <div className="demo-result-top">
                  <span className={`badge ${item.threat_type}`}>{item.threat_type}</span>
                  <span className={`badge ${item.severity}`}>{item.severity}</span>
                </div>
                <div className="mono muted" style={{ fontSize: '0.78rem', marginBottom: '0.35rem' }}>
                  confidence {Math.round((item.confidence || 0) * 100)}%
                </div>
                <p className="demo-result-payload">{item.raw_payload}</p>
              </article>
            ))}
          </div>
        )}
      </div>
    </section>
  )
}
