import { FileDown, ShieldAlert } from 'lucide-react'

export default function ReportPanel({ summary, onDownload, downloading }) {
  return (
    <div className="panel section">
      <div className="section-head">
        <h3>Decision Support Report</h3>
        <span>Cybersecurity recommendations</span>
      </div>

      {!summary ? (
        <div className="empty">Loading report summary…</div>
      ) : (
        <>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '0.65rem' }}>
            <div className="stat-card total">
              <div className="stat-label">Total</div>
              <div className="stat-value" style={{ fontSize: '1.35rem' }}>
                {summary.total_threats}
              </div>
            </div>
            <div className="stat-card open">
              <div className="stat-label">Open</div>
              <div className="stat-value" style={{ fontSize: '1.35rem' }}>
                {summary.open_threats}
              </div>
            </div>
            <div className="stat-card critical">
              <div className="stat-label">Critical</div>
              <div className="stat-value" style={{ fontSize: '1.35rem' }}>
                {summary.critical_count}
              </div>
            </div>
          </div>

          <p className="muted" style={{ margin: '0.9rem 0 0.55rem', fontSize: '0.9rem' }}>
            Dominant threat: <strong style={{ color: 'var(--text)' }}>{summary.top_threat_type}</strong>
          </p>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', marginBottom: '0.45rem' }}>
            <ShieldAlert size={16} color="#f59e0b" />
            <strong style={{ fontSize: '0.92rem' }}>Recommended actions</strong>
          </div>
          <ul className="report-list">
            {summary.recommendations?.map((rec) => (
              <li key={rec}>{rec}</li>
            ))}
          </ul>

          <div style={{ marginTop: '1rem' }}>
            <button className="btn btn-primary" onClick={onDownload} disabled={downloading}>
              <FileDown size={16} />
              {downloading ? 'Generating PDF…' : 'Download PDF Report'}
            </button>
          </div>
        </>
      )}
    </div>
  )
}
