import { ClipboardList, ShieldAlert } from 'lucide-react'
import { remediationFor, VIRUS_EVIDENCE_CATALOG } from '../utils/remediation'

export default function RemediationPanel({ threatType }) {
  const guide = remediationFor(threatType)

  return (
    <div className="panel section remediation-panel">
      <div className="section-head">
        <h3>Rectification & Precautions</h3>
        <span>{guide ? 'Auto guidance for detected type' : 'Virus evidence reference'}</span>
      </div>

      {guide ? (
        <>
          <div className="remediation-head">
            <ShieldAlert size={18} />
            <div>
              <strong>{guide.title} — Precautions & Rectification</strong>
              <div className="muted" style={{ fontSize: '0.78rem', marginTop: 2 }}>
                Detected type:{' '}
                <span className={`badge ${threatType}`}>{threatType}</span>
              </div>
            </div>
          </div>

          <div className="remediation-evidence-box">
            <div className="remediation-evidence-row">
              <span className="meta-label">Evidence to record</span>
              <strong>{guide.evidence}</strong>
            </div>
            {guide.examples ? (
              <div className="remediation-evidence-row">
                <span className="meta-label">Example families</span>
                <strong className="mono">{guide.examples}</strong>
              </div>
            ) : null}
          </div>

          <ol className="remediation-list">
            {guide.steps.map((step) => (
              <li key={step}>{step}</li>
            ))}
          </ol>
        </>
      ) : (
        <>
          <div className="remediation-head">
            <ClipboardList size={18} />
            <div>
              <strong>Classify a sample to unlock guided response steps</strong>
              <div className="muted" style={{ fontSize: '0.78rem', marginTop: 2 }}>
                Paste payload text on the left, then click Classify with AI.
              </div>
            </div>
          </div>
          <p className="muted remediation-intro">
            For virus detections, record the family/detection name and hash where required:
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
