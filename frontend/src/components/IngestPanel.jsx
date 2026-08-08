import { useState } from 'react'
import { Upload } from 'lucide-react'
import { api } from '../api'

const empty = {
  source: 'Network IDS Sensor',
  source_ip: '10.0.0.25',
  destination_ip: '203.0.113.40',
  protocol: 'HTTPS',
  raw_payload: '',
}

export default function IngestPanel({ onIngested, onToast }) {
  const [form, setForm] = useState(empty)
  const [loading, setLoading] = useState(false)

  function update(field, value) {
    setForm((prev) => ({ ...prev, [field]: value }))
  }

  async function handleSubmit(e) {
    e.preventDefault()
    if (!form.raw_payload.trim()) return
    setLoading(true)
    try {
      const event = await api.ingest(form)
      onToast?.(`Ingested event #${event.id} as ${event.threat_type}`)
      setForm((prev) => ({ ...prev, raw_payload: '' }))
      onIngested?.()
    } catch (err) {
      onToast?.(err.message || 'Ingest failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="panel section">
      <div className="section-head">
        <h3>Network Data Collection</h3>
        <span>Manual ingest + classify</span>
      </div>
      <form className="form" onSubmit={handleSubmit}>
        <label>
          Source
          <input value={form.source} onChange={(e) => update('source', e.target.value)} />
        </label>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.65rem' }}>
          <label>
            Source IP
            <input value={form.source_ip} onChange={(e) => update('source_ip', e.target.value)} />
          </label>
          <label>
            Destination IP
            <input
              value={form.destination_ip}
              onChange={(e) => update('destination_ip', e.target.value)}
            />
          </label>
        </div>
        <label>
          Protocol
          <select value={form.protocol} onChange={(e) => update('protocol', e.target.value)}>
            {['HTTPS', 'HTTP', 'DNS', 'SMTP', 'SMB', 'TCP', 'UDP'].map((p) => (
              <option key={p} value={p}>
                {p}
              </option>
            ))}
          </select>
        </label>
        <label>
          Raw payload / indicator text
          <textarea
            value={form.raw_payload}
            onChange={(e) => update('raw_payload', e.target.value)}
            placeholder="Example: Ransom note detected — files encrypted, bitcoin wallet demanded"
          />
        </label>
        <button className="btn btn-secondary" type="submit" disabled={loading}>
          <Upload size={16} />
          {loading ? 'Ingesting…' : 'Ingest & Classify'}
        </button>
      </form>
    </div>
  )
}
