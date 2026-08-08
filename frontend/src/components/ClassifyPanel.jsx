import { useState } from 'react'
import { BrainCircuit } from 'lucide-react'
import { api } from '../api'

const SAMPLES = [
  'Urgent action required: verify your account and click the login portal link',
  'PowerShell -enc base64 payload launched reverse shell to C2 beacon',
  'Your files have been encrypted. Pay bitcoin wallet for decryption key',
]

export default function ClassifyPanel({ onToast }) {
  const [text, setText] = useState(SAMPLES[0])
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)

  async function handleClassify(e) {
    e.preventDefault()
    if (!text.trim()) return
    setLoading(true)
    try {
      const data = await api.classify(text.trim())
      setResult(data)
      onToast?.(`Classified as ${data.threat_type} (${Math.round(data.confidence * 100)}%)`)
    } catch (err) {
      onToast?.(err.message || 'Classification failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="panel section">
      <div className="section-head">
        <h3>AI Threat Classification</h3>
        <span>Phishing · Malware · Ransomware</span>
      </div>
      <form className="form" onSubmit={handleClassify}>
        <label>
          Threat / network payload text
          <textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder="Paste email content, process command, or network indicator text…"
          />
        </label>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.45rem' }}>
          {SAMPLES.map((sample) => (
            <button
              key={sample}
              type="button"
              className="btn btn-ghost"
              style={{ fontSize: '0.78rem', padding: '0.4rem 0.65rem' }}
              onClick={() => setText(sample)}
            >
              {sample.split(' ').slice(0, 3).join(' ')}…
            </button>
          ))}
        </div>
        <button className="btn btn-primary" type="submit" disabled={loading}>
          <BrainCircuit size={16} />
          {loading ? 'Classifying…' : 'Classify with AI'}
        </button>
      </form>
      {result && (
        <div className="result-box">
          <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '0.5rem' }}>
            <span className={`badge ${result.threat_type}`}>{result.threat_type}</span>
            <span className={`badge ${result.severity}`}>{result.severity}</span>
            <span className="mono muted">confidence {Math.round(result.confidence * 100)}%</span>
          </div>
          <div className="muted" style={{ fontSize: '0.85rem' }}>
            Indicators:{' '}
            {result.indicators?.length ? result.indicators.join(' · ') : 'Model probability only'}
          </div>
        </div>
      )}
    </div>
  )
}
