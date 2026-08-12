import { useState } from 'react'
import { BrainCircuit } from 'lucide-react'
import { api } from '../api'

const SAMPLES = [
  {
    label: 'Virus',
    text: 'File infector virus Win32/Expiro detected sha256:a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff00',
  },
  {
    label: 'Worm',
    text: 'Worm WannaCry self-replicating across SMB shares on the LAN',
  },
  {
    label: 'Trojan',
    text: 'Banking trojan Emotet downloaded via malicious Office macro',
  },
  {
    label: 'Ransomware',
    text: 'LockBit ransomware locked files as .locked and demanded crypto payment',
  },
  {
    label: 'Spyware',
    text: 'Spyware Pegasus exfiltrating contacts messages location from mobile endpoint',
  },
  {
    label: 'RAT',
    text: 'Remote access trojan AsyncRAT opened unauthorized remote control session',
  },
  {
    label: 'Keylogger',
    text: 'Keylogger Agent Tesla keystroke logging sha256:11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff',
  },
  {
    label: 'Cryptominer',
    text: 'Cryptominer XMRig unauthorized mining sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
  },
  {
    label: 'Phishing',
    text: 'Urgent action required: verify your account and click the login portal link',
  },
]

export default function ClassifyPanel({ onToast, onClassified }) {
  const [text, setText] = useState(SAMPLES[0].text)
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)

  async function handleClassify(e) {
    e.preventDefault()
    if (!text.trim()) return
    setLoading(true)
    try {
      const data = await api.classify(text.trim())
      setResult(data)
      onClassified?.(data)
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
        <span>All threat categories</span>
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
              key={sample.label}
              type="button"
              className="btn btn-ghost"
              style={{ fontSize: '0.78rem', padding: '0.4rem 0.65rem' }}
              onClick={() => setText(sample.text)}
            >
              {sample.label}
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
