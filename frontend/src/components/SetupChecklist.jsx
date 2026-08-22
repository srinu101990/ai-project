import { CheckCircle2, Circle, ListChecks } from 'lucide-react'

export default function SetupChecklist({ setup, onGo }) {
  const steps = setup?.steps || []
  const completed = setup?.completed ?? 0
  const required = setup?.required ?? steps.filter((step) => !step.optional).length

  return (
    <section className="panel section setup-checklist" aria-label="Demo setup checklist">
      <div className="section-head">
        <h3>
          <ListChecks size={16} style={{ marginRight: 8, verticalAlign: '-2px' }} />
          Download-and-test checklist
        </h3>
        <span>
          {setup?.ready ? 'Required laptop steps are on' : `${completed}/${required || 4} required steps ready`}
        </span>
      </div>
      <p className="muted source-copy">
        Do these once after you start the app. Inbox watch needs your Gmail/Outlook app password.
        Folder watch and LAN monitoring start by themselves.
      </p>
      <ul className="setup-steps">
        {steps.map((step) => (
          <li key={step.id} className={step.done ? 'done' : ''}>
            {step.done ? <CheckCircle2 size={16} /> : <Circle size={16} />}
            <div>
              <button type="button" className="setup-link" onClick={() => onGo?.(step.tab || 'dashboard')}>
                {step.title}
                {step.optional ? ' (optional)' : ''}
              </button>
              <div className="muted" style={{ fontSize: '0.78rem' }}>
                {step.detail}
              </div>
            </div>
          </li>
        ))}
      </ul>
    </section>
  )
}
