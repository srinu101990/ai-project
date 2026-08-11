import { ShieldAlert } from 'lucide-react'
import { remediationFor } from '../utils/remediation'

export default function RemediationPanel({ threatType }) {
  const guide = remediationFor(threatType)

  return (
    <div className="panel section">
      <div className="section-head">
        <h3>{guide ? 'Rectification & Precautions' : 'Analyzer Tips'}</h3>
        <span>{guide ? 'Auto guidance' : 'Awaiting classification'}</span>
      </div>

      {!guide ? (
        <ul className="report-list">
          <li>Paste suspicious email text, URLs, or process logs.</li>
          <li>Click <strong>Classify with AI</strong> to detect the threat category and severity.</li>
          <li>This panel will automatically show precautions for that threat type.</li>
        </ul>
      ) : (
        <>
          <div className="remediation-head">
            <ShieldAlert size={18} />
            <div>
              <strong>{guide.title}</strong>
              <div className="muted" style={{ fontSize: '0.78rem', marginTop: 2 }}>
                Detected type:{' '}
                <span className={`badge ${threatType}`}>{threatType}</span>
              </div>
            </div>
          </div>
          <ol className="remediation-list">
            {guide.steps.map((step) => (
              <li key={step}>{step}</li>
            ))}
          </ol>
        </>
      )}
    </div>
  )
}
