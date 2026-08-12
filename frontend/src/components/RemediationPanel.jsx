import { Activity, ClipboardList, ListOrdered, Tag } from 'lucide-react'
import { remediationFor, VIRUS_EVIDENCE_CATALOG } from '../utils/remediation'

export default function RemediationPanel({ threatType }) {
  const guide = remediationFor(threatType)

  return (
    <div className="panel section remediation-panel">
      <div className="section-head">
        <h3>Rectification & Precautions</h3>
        <span>{guide ? 'Auto guidance' : 'Virus evidence reference'}</span>
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
        <>
          <div className="remediation-head">
            <ClipboardList size={18} />
            <div>
              <strong>Classify a sample to unlock guided response steps</strong>
              <div className="muted" style={{ fontSize: '0.78rem', marginTop: 2 }}>
                Paste payload text on the left, then click Classify with AI. Guidance appears as:
                Detected Type → Behavior → Precautions.
              </div>
            </div>
          </div>
          <p className="muted remediation-intro">
            Updated virus catalog — record the family/detection evidence shown below:
          </p>
          <div className="evidence-table-wrap">
            <table className="evidence-table">
              <thead>
                <tr>
                  <th>Virus / malware type</th>
                  <th>Evidence to record</th>
                </tr>
              </thead>
              <tbody>
                {VIRUS_EVIDENCE_CATALOG.map((item) => (
                  <tr key={item.id}>
                    <td>
                      <span className={`badge ${item.id}`}>{item.title}</span>
                    </td>
                    <td>
                      <div>{item.evidence}</div>
                      {item.examples ? (
                        <div className="mono muted evidence-examples">{item.examples}</div>
                      ) : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  )
}
