import { Activity, ClipboardList, ListOrdered, Tag } from 'lucide-react'
import { remediationFor } from '../utils/remediation'

export default function RemediationPanel({ threatType, context = 'analyzer' }) {
  const guide = remediationFor(threatType)
  const idleCopy =
    context === 'mail'
      ? {
          title: 'Check an email to see rectification steps',
          detail:
            'After a mail is classified, this panel shows Detected Type, Behavior, and Precautions.',
        }
      : {
          title: 'Classify a sample to see type, behavior, and precautions',
          detail:
            'Paste payload text on the left, then click Classify with AI. Guidance appears as Detected Type → Behavior → Precautions.',
        }

  return (
    <div className="panel section remediation-panel">
      <div className="section-head">
        <h3>Rectification & Precautions</h3>
        <span>{guide ? 'Auto guidance' : 'Waiting for a classification'}</span>
      </div>

      {guide ? (
        <div className="remediation-sections">
          <section className="remediation-block">
            <header className="remediation-block-head">
              <Tag size={16} />
              <h4>1. Detected Type</h4>
            </header>
            <div className="remediation-detected">
              <span className={`badge ${threatType}`}>{guide.title}</span>
              <div className="remediation-detected-meta mono muted">
                Code: {threatType}
                {guide.examples ? ` · Examples: ${guide.examples}` : ''}
              </div>
              <div className="remediation-evidence-box compact">
                <div className="remediation-evidence-row">
                  <span className="meta-label">Evidence to record</span>
                  <strong>{guide.evidence}</strong>
                </div>
              </div>
            </div>
          </section>

          <section className="remediation-block">
            <header className="remediation-block-head">
              <Activity size={16} />
              <h4>2. Behavior</h4>
            </header>
            <p className="remediation-behavior">{guide.behavior}</p>
          </section>

          <section className="remediation-block">
            <header className="remediation-block-head">
              <ListOrdered size={16} />
              <h4>3. Precautions</h4>
            </header>
            <ol className="remediation-list">
              {guide.steps.map((step, index) => (
                <li key={`${index}-${step}`}>{step}</li>
              ))}
            </ol>
          </section>
        </div>
      ) : (
        <div className="remediation-head">
          <ClipboardList size={18} />
          <div>
            <strong>{idleCopy.title}</strong>
            <div className="muted" style={{ fontSize: '0.78rem', marginTop: 2 }}>
              {idleCopy.detail}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
