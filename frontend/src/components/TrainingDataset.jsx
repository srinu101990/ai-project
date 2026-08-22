import { useEffect, useState } from 'react'
import { Database, GraduationCap } from 'lucide-react'
import { api } from '../api'

export default function TrainingDataset() {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    let cancelled = false
    api
      .classifierDataset()
      .then((payload) => {
        if (!cancelled) setData(payload)
      })
      .catch((err) => {
        if (!cancelled) setError(err.message || 'Could not load dataset')
      })
    return () => {
      cancelled = true
    }
  }, [])

  const metrics = data?.metrics || {}
  const rows = data?.sample_rows || []

  return (
    <div className="panel section">
      <div className="section-head">
        <h3>Training dataset & model</h3>
        <span>Generated SOC corpus + v4 metrics</span>
      </div>
      {error ? <p className="muted">{error}</p> : null}
      <p className="muted" style={{ marginTop: 0 }}>
        {data?.honesty ||
          'Excel sample CSV = 2,200 rows. Screenshots 400,000 = in-memory train size. Run python -m scripts.export_full_corpus to write the full file.'}
      </p>
      <div className="snapshot-grid">
        <div>
          <div className="stat-label">Excel sample CSV</div>
          <div className="stat-value">2,200</div>
        </div>
        <div>
          <div className="stat-label">Train events</div>
          <div className="stat-value">{metrics.train_samples?.toLocaleString?.() || '—'}</div>
        </div>
        <div>
          <div className="stat-label">Holdout test</div>
          <div className="stat-value">{metrics.test_samples?.toLocaleString?.() || '—'}</div>
        </div>
        <div>
          <div className="stat-label">Accuracy</div>
          <div className="stat-value">
            {metrics.accuracy != null ? `${Math.round(metrics.accuracy * 10000) / 100}%` : '—'}
          </div>
        </div>
        <div>
          <div className="stat-label">Algorithm</div>
          <div className="stat-value" style={{ fontSize: '1.05rem' }}>
            <GraduationCap size={16} /> TF-IDF + LR
          </div>
        </div>
      </div>
      <div className="section-head" style={{ marginTop: '1rem' }}>
        <h3>Sample rows</h3>
        <span>
          <Database size={14} /> {rows.length} preview rows
        </span>
      </div>
      <div className="dataset-table-wrap">
        <table className="dataset-table">
          <thead>
            <tr>
              <th>Split</th>
              <th>Type</th>
              <th>Event text</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row, index) => (
              <tr key={`${row.threat_type}-${index}`}>
                <td className="mono">{row.split}</td>
                <td>
                  <span className={`badge ${row.threat_type}`}>{row.threat_type}</span>
                </td>
                <td>{row.event_text}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
