import { useState } from 'react'
import { MailWarning, ShieldCheck, Upload } from 'lucide-react'
import { api } from '../api'

const SAMPLE_PHISH = {
  sender: 'security@paypa1-login.com',
  subject: 'Urgent action required: verify your account',
  body:
    'Dear customer, we noticed unusual sign-in activity. Your account has been limited. ' +
    'Click here to verify your account and confirm your identity on the login portal. ' +
    'Failure to verify within 24 hours will suspend the bank account. Update billing payment now: https://paypa1-login.com/login',
}

const SAMPLE_SAFE = {
  sender: 'noreply@company.com',
  subject: 'Weekly project notes',
  body:
    'Hi team, the weekly notes are in the shared drive. No password reset is required. See you in the standup tomorrow.',
}

export default function MailGuardPanel({ onToast, onChecked }) {
  const [sender, setSender] = useState('')
  const [subject, setSubject] = useState('')
  const [body, setBody] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [imapHost, setImapHost] = useState('imap.gmail.com')
  const [imapUser, setImapUser] = useState('')
  const [imapPass, setImapPass] = useState('')
  const [imapStatus, setImapStatus] = useState(null)
  const [imapBusy, setImapBusy] = useState(false)

  async function checkMail(payload) {
    setLoading(true)
    try {
      const data = await api.checkMail(payload)
      setResult(data)
      onChecked?.(data)
      onToast?.(data.verdict || `Mail classified as ${data.threat_type}`)
    } catch (err) {
      onToast?.(err.message || 'Mail check failed')
    } finally {
      setLoading(false)
    }
  }

  async function handleSubmit(e) {
    e.preventDefault()
    if (!body.trim()) return
    await checkMail({ sender, subject, body: body.trim() })
  }

  async function handleUpload(e) {
    const file = e.target.files?.[0]
    e.target.value = ''
    if (!file) return
    setLoading(true)
    try {
      const data = await api.uploadMail(file)
      setResult(data)
      setSender(data.sender || '')
      setSubject(data.subject || '')
      onChecked?.(data)
      onToast?.(data.verdict || 'Saved email classified')
    } catch (err) {
      onToast?.(err.message || 'Could not read .eml file')
    } finally {
      setLoading(false)
    }
  }

  async function handleDropScan() {
    setLoading(true)
    try {
      const data = await api.scanMailDrop()
      if (data.last) setResult(data.last)
      onToast?.(data.message)
      onChecked?.(data.last)
    } catch (err) {
      onToast?.(err.message || 'Drop folder scan failed')
    } finally {
      setLoading(false)
    }
  }

  async function handleImapConnect(e) {
    e.preventDefault()
    setImapBusy(true)
    try {
      const status = await api.connectMailImap({
        host: imapHost,
        username: imapUser,
        password: imapPass,
        mailbox: 'INBOX',
      })
      setImapStatus(status)
      onToast?.(status.last_message || 'IMAP watch started')
    } catch (err) {
      onToast?.(err.message || 'IMAP connect failed — use an app password, not your main password')
    } finally {
      setImapBusy(false)
    }
  }

  async function handleImapPoll() {
    setImapBusy(true)
    try {
      const status = await api.pollMailImap()
      setImapStatus(status)
      onToast?.(status.message || status.last_message || 'Inbox polled')
    } catch (err) {
      onToast?.(err.message || 'IMAP poll failed')
    } finally {
      setImapBusy(false)
    }
  }

  async function handleImapStop() {
    setImapBusy(true)
    try {
      const status = await api.stopMailImap()
      setImapStatus(status)
      onToast?.('IMAP watch stopped')
    } catch (err) {
      onToast?.(err.message || 'Could not stop IMAP')
    } finally {
      setImapBusy(false)
    }
  }

  const phishing = result?.phishing || result?.threat_type === 'phishing'

  return (
    <div className="panel section mail-guard-panel">
      <div className="section-head">
        <h3>Laptop Mail Phishing Guard</h3>
        <span>Step 1 — this PC only</span>
      </div>
      <p className="muted source-copy">
        This does <strong>not</strong> read Gmail/Outlook by itself. Paste a mail, upload a saved
        .eml, or connect IMAP with an app password. The AI then says if it is phishing.
      </p>

      <form className="form" onSubmit={handleSubmit}>
        <label>
          From
          <input value={sender} onChange={(e) => setSender(e.target.value)} placeholder="sender@example.com" />
        </label>
        <label>
          Subject
          <input value={subject} onChange={(e) => setSubject(e.target.value)} placeholder="Email subject" />
        </label>
        <label>
          Email body
          <textarea
            value={body}
            onChange={(e) => setBody(e.target.value)}
            placeholder="Paste the full email text from Gmail or Outlook…"
          />
        </label>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.45rem' }}>
          <button
            type="button"
            className="btn btn-ghost"
            onClick={() => {
              setSender(SAMPLE_PHISH.sender)
              setSubject(SAMPLE_PHISH.subject)
              setBody(SAMPLE_PHISH.body)
            }}
          >
            Load sample phishing
          </button>
          <button
            type="button"
            className="btn btn-ghost"
            onClick={() => {
              setSender(SAMPLE_SAFE.sender)
              setSubject(SAMPLE_SAFE.subject)
              setBody(SAMPLE_SAFE.body)
            }}
          >
            Load sample safe mail
          </button>
        </div>
        <button className="btn btn-primary" type="submit" disabled={loading}>
          <MailWarning size={16} />
          {loading ? 'Checking…' : 'Check this email'}
        </button>
      </form>

      {result ? (
        <div className={`mail-verdict ${phishing ? 'bad' : 'ok'}`}>
          {phishing ? <MailWarning size={22} /> : <ShieldCheck size={22} />}
          <div>
            <strong>{result.verdict}</strong>
            <div className="muted" style={{ fontSize: '0.85rem' }}>
              {result.threat_type} · {result.severity} · {Math.round((result.confidence || 0) * 100)}%
              {result.indicators?.length ? ` · ${result.indicators.join(', ')}` : ''}
            </div>
          </div>
        </div>
      ) : null}

      <div className="mail-extra">
        <label className="btn btn-secondary">
          <Upload size={16} />
          Upload .eml file
          <input type="file" accept=".eml,.txt" hidden onChange={handleUpload} />
        </label>
        <button type="button" className="btn btn-ghost" onClick={handleDropScan} disabled={loading}>
          Scan inbox_drop folder
        </button>
      </div>

      <form className="form" onSubmit={handleImapConnect} style={{ marginTop: '1rem' }}>
        <div className="section-head" style={{ padding: 0 }}>
          <h3 style={{ fontSize: '1rem' }}>Optional: watch my inbox</h3>
          <span>Gmail / Outlook IMAP</span>
        </div>
        <p className="muted source-copy">
          Gmail: create an App Password, then use imap.gmail.com. Outlook: outlook.office365.com.
          Do not use your main email password.
        </p>
        <label>
          IMAP host
          <select value={imapHost} onChange={(e) => setImapHost(e.target.value)}>
            <option value="imap.gmail.com">Gmail (imap.gmail.com)</option>
            <option value="outlook.office365.com">Outlook (outlook.office365.com)</option>
          </select>
        </label>
        <label>
          Email address
          <input value={imapUser} onChange={(e) => setImapUser(e.target.value)} placeholder="you@gmail.com" />
        </label>
        <label>
          App password
          <input
            type="password"
            value={imapPass}
            onChange={(e) => setImapPass(e.target.value)}
            placeholder="App password, not your login password"
          />
        </label>
        <div className="action-bar compact">
          <button className="btn btn-primary" type="submit" disabled={imapBusy || !imapUser || !imapPass}>
            {imapBusy ? 'Working…' : 'Start inbox watch'}
          </button>
          <button type="button" className="btn btn-ghost" onClick={handleImapPoll} disabled={imapBusy}>
            Poll now
          </button>
          <button type="button" className="btn btn-ghost" onClick={handleImapStop} disabled={imapBusy}>
            Stop
          </button>
        </div>
        {imapStatus?.last_message ? (
          <div className="muted mono" style={{ fontSize: '0.78rem' }}>
            {imapStatus.enabled ? 'WATCHING' : 'OFF'} · {imapStatus.last_message}
          </div>
        ) : null}
      </form>
    </div>
  )
}
