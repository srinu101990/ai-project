import { useEffect, useState } from 'react'
import { FolderSearch, ShieldAlert, ShieldCheck, Upload } from 'lucide-react'
import { api } from '../api'

export default function FileGuardPanel({ onToast, onChecked, fileStatus }) {
  const [status, setStatus] = useState(fileStatus || null)
  const [result, setResult] = useState(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (fileStatus) setStatus(fileStatus)
  }, [fileStatus])

  useEffect(() => {
    api.fileStatus()
      .then(setStatus)
      .catch(() => {})
  }, [])

  async function run(action, successMessage) {
    setBusy(true)
    try {
      const data = await action()
      if (data?.folders || data?.enabled !== undefined) setStatus(data)
      if (data?.verdict) {
        setResult(data)
        onChecked?.(data)
      }
      if (data?.last?.verdict) {
        setResult(data.last)
        onChecked?.(data.last)
      }
      onToast?.(data?.message || data?.last_message || successMessage)
      return data
    } catch (err) {
      onToast?.(err.message || 'File watch failed')
      return null
    } finally {
      setBusy(false)
    }
  }

  async function handleUpload(e) {
    const file = e.target.files?.[0]
    e.target.value = ''
    if (!file) return
    setBusy(true)
    try {
      const data = await api.uploadFile(file)
      setResult(data)
      onChecked?.(data)
      onToast?.(data.verdict || 'File classified')
    } catch (err) {
      onToast?.(err.message || 'Could not classify that file')
    } finally {
      setBusy(false)
    }
  }

  const watching = Boolean(status?.enabled)
  const malicious = result?.malicious || result?.threat_type === 'ransomware'

  return (
    <div className="panel section mail-guard-panel">
      <div className="section-head">
        <h3>Watch my laptop folders</h3>
        <span>{watching ? 'LIVE — new files are being checked' : 'Folder watch is off'}</span>
      </div>
      <p className="muted source-copy">
        This laptop and any live second-laptop agent watch Downloads, Desktop, Documents,
        USB sticks, and <code>file_drop/</code>. Suspicious names on a USB stick
        (virus.exe, invoice.pdf.exe, README_FOR_DECRYPT) are classified one at a time.
      </p>
      <ol className="mail-steps">
        <li>Leave folder watch on (it starts with the app)</li>
        <li>
          Plug a USB stick into this laptop, or into the second laptop while{' '}
          <code>sentinel_agent.py</code> stays open
        </li>
        <li>The USB line below should list the drive from that PC within a few seconds</li>
        <li>A popup appears for a new suspicious file on that stick</li>
      </ol>

      <div className={`mail-watch-banner ${watching ? 'on' : ''}`}>
        <span className="live-dot" />
        {watching
          ? `Watching ${status.folders?.length || 0} folder(s) every ${status.interval_seconds}s`
          : 'Folder watch is off'}
        {status?.total_malicious ? ` · hits: ${status.total_malicious}` : ''}
      </div>

      <div className={`mail-watch-banner ${status?.usb_drives?.length ? 'on' : ''}`}>
        <span className="live-dot" />
        {status?.usb_message || 'USB: checking…'}
      </div>
      {status?.usb_drives?.length ? (
        <ul className="mail-steps">
          {status.usb_drives.map((drive) => (
            <li key={drive}>
              USB in list: <code>{drive}</code>
            </li>
          ))}
        </ul>
      ) : null}

      <div className="action-bar compact">
        <button
          className="btn btn-primary"
          type="button"
          disabled={busy || watching}
          onClick={() => run(() => api.startFileWatch(), 'Folder watch started')}
        >
          {busy ? 'Working…' : 'Start folder watch'}
        </button>
        <button
          type="button"
          className="btn btn-ghost"
          disabled={busy || !watching}
          onClick={() => run(() => api.scanFiles(), 'Folders scanned')}
        >
          Scan folders now
        </button>
        <button
          type="button"
          className="btn btn-secondary"
          disabled={busy}
          onClick={() => run(() => api.testFileSample(), 'Test files written and classified')}
        >
          <FolderSearch size={16} />
          Drop test samples
        </button>
        <button
          type="button"
          className="btn btn-ghost"
          disabled={busy || !watching}
          onClick={() => run(() => api.stopFileWatch(), 'Folder watch stopped')}
        >
          Stop
        </button>
      </div>

      {status?.last_message ? (
        <div className="muted mono" style={{ fontSize: '0.78rem' }}>
          {status.last_error ? `Error: ${status.last_error}` : status.last_message}
        </div>
      ) : null}

      <div className="muted" style={{ fontSize: '0.8rem', marginTop: '0.55rem' }}>
        Folders: {(status?.folders || []).join(' · ') || 'waiting'}
      </div>

      {result ? (
        <div className={`mail-verdict ${malicious ? 'bad' : 'ok'}`}>
          {malicious ? <ShieldAlert size={22} /> : <ShieldCheck size={22} />}
          <div>
            <strong>{result.verdict}</strong>
            <div className="muted" style={{ fontSize: '0.85rem' }}>
              {result.filename || result.threat_type} · {Math.round((result.confidence || 0) * 100)}%
            </div>
          </div>
        </div>
      ) : null}

      <details className="mail-manual">
        <summary>Or upload one file to classify</summary>
        <label className="btn btn-secondary">
          <Upload size={16} />
          Upload a file
          <input type="file" hidden onChange={handleUpload} />
        </label>
      </details>
    </div>
  )
}
