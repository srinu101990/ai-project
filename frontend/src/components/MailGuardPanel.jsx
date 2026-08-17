import { useEffect, useState } from 'react'
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

export default function MailGuardPanel({ onToast, onChecked, mailStatus }) {
  const [sender, setSender] = useState('')
  const [subject, setSubject] = useState('')
  const [body, setBody] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [imapHost, setImapHost] = useState('imap.gmail.com')
  const [imapUser, setImapUser] = useState('')
  const [imapPass, setImapPass] = useState('')
  const [imapStatus, setImapStatus] = useState(mailStatus || null)
  const [imapBusy, setImapBusy] = useState(false)
  const [outlookBusy, setOutlookBusy] = useState(false)

  useEffect(() => {
    if (mailStatus) setImapStatus(mailStatus)
  }, [mailStatus])

  useEffect(() => {
    api.mailStatus()
      .then((status) => {
        setImapStatus(status)
        if (status?.username) setImapUser(status.username)
        if (status?.host) setImapHost(status.host)
      })
      .catch(() => {})
  }, [])

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

  async function handleImapConnect(e) {
    e.preventDefault()
    setImapBusy(true)
    try {
      const status = await api.connectMailImap({
        host: imapHost,
        username: imapUser,
        password: imapPass,
        mailbox: 'INBOX',
        interval_seconds: 20,
      })
      setImapStatus(status)
      if (status.last_phishing) {
        onToast?.(`PHISHING DETECTED in ${status.last_phishing} mail(s)`)
      } else {
        onToast?.(status.message || status.last_message || 'Inbox watch started')
      }
    } catch (err) {
      onToast?.(
        err.message ||
          'Could not open inbox. Enable IMAP and use a Gmail/Outlook app password, not your normal password.',
      )
    } finally {
      setImapBusy(false)
    }
  }

  async function handleImapPoll() {
    setImapBusy(true)
    try {
      const status = await api.pollMailImap()
      setImapStatus(status)
      if (status.last_phishing) {
        onChecked?.({ threat_type: 'phishing' })
        onToast?.(`PHISHING DETECTED in ${status.last_phishing} mail(s)`)
      } else {
        onToast?.(status.message || status.last_message || 'Inbox checked')
      }
    } catch (err) {
      onToast?.(err.message || 'Inbox poll failed')
    } finally {
      setImapBusy(false)
    }
  }

  async function handleImapStop() {
    setImapBusy(true)
    try {
      const status = await api.stopMailImap()
      setImapStatus(status)
      onToast?.('Inbox watch stopped')
    } catch (err) {
      onToast?.(err.message || 'Could not stop inbox watch')
    } finally {
      setImapBusy(false)
    }
  }

  async function handleOutlookStart() {
    setOutlookBusy(true)
    try {
      const status = await api.startOutlookWatch()
      setImapStatus(status)
      if (status.last_phishing) {
        onToast?.(`PHISHING DETECTED in ${status.last_phishing} Outlook mail(s)`)
      } else {
        onToast?.(status.message || status.last_message || 'Outlook inbox watch started')
      }
    } catch (err) {
      onToast?.(
        err.message ||
          'Could not read Outlook. Open classic Outlook, sign in, then click Allow if Windows asks.',
      )
    } finally {
      setOutlookBusy(false)
    }
  }

  const phishing = result?.phishing || result?.threat_type === 'phishing'
  const watching = Boolean(imapStatus?.enabled)
  const outlookMode = imapStatus?.channel === 'outlook'
  const outlookInstalled = Boolean(imapStatus?.outlook_installed)
  const busy = imapBusy || outlookBusy

  return (
    <div className="panel section mail-guard-panel">
      <div className="section-head">
        <h3>Watch my email inbox</h3>
        <span>
          {watching
            ? outlookMode
              ? 'LIVE — Outlook on this laptop'
              : 'LIVE — IMAP inbox'
            : 'Not watching yet'}
        </span>
      </div>
      <p className="muted source-copy">
        Chrome or Edge being signed into Gmail cannot be scanned. Google does not allow any app to
        reuse that browser login. If <strong>classic Outlook</strong> is installed and already signed
        in on this laptop, use the button below — no password. Otherwise use a Gmail App Password.
      </p>

      <div className={`mail-watch-banner ${watching ? 'on' : ''}`}>
        <span className="live-dot" />
        {watching
          ? `Watching ${imapStatus.username || 'inbox'} every ${imapStatus.interval_seconds}s`
          : 'Inbox watch is off'}
        {imapStatus?.last_phishing ? ` · phishing hits: ${imapStatus.last_phishing}` : ''}
      </div>

      <div className="action-bar compact" style={{ marginBottom: '0.85rem' }}>
        <button
          type="button"
          className="btn btn-primary"
          disabled={busy}
          onClick={handleOutlookStart}
        >
          {outlookBusy ? 'Connecting…' : 'Watch Outlook already signed in on this PC'}
        </button>
        <button type="button" className="btn btn-ghost" onClick={handleImapPoll} disabled={busy || !watching}>
          Check inbox now
        </button>
        <button type="button" className="btn btn-ghost" onClick={handleImapStop} disabled={busy || !watching}>
          Stop
        </button>
      </div>
      <p className="muted" style={{ fontSize: '0.8rem', marginTop: 0 }}>
        {outlookInstalled
          ? 'Classic Outlook was found on this PC. Open Outlook, stay signed in, then click the button. If Windows asks to allow access, click Allow.'
          : 'Classic Outlook was not found. The new Outlook Store app and Gmail-in-Chrome cannot be read. Use Gmail App Password below, or install classic Outlook.'}
      </p>
      {imapStatus?.last_message || imapStatus?.last_error ? (
        <div className="muted mono" style={{ fontSize: '0.78rem', marginBottom: '0.85rem' }}>
          {imapStatus.last_error ? `Error: ${imapStatus.last_error}` : imapStatus.last_message}
        </div>
      ) : null}

      <details className="mail-manual" open={!outlookInstalled}>
        <summary>Gmail / web Outlook — App Password (required; browser login will not work)</summary>
        <ol className="mail-steps">
          <li>Gmail: Settings → See all settings → Forwarding and POP/IMAP → Enable IMAP</li>
          <li>Google Account → Security → 2-Step Verification → App passwords → create one for Mail</li>
          <li>Paste email + 16-character app password, then start watch</li>
        </ol>
        <form className="form" onSubmit={handleImapConnect}>
          <label>
            Mail provider
            <select value={imapHost} onChange={(e) => setImapHost(e.target.value)}>
              <option value="imap.gmail.com">Gmail (imap.gmail.com)</option>
              <option value="outlook.office365.com">Outlook / Hotmail (outlook.office365.com)</option>
            </select>
          </label>
          <label>
            Email address
            <input
              value={imapUser}
              onChange={(e) => setImapUser(e.target.value)}
              placeholder="you@gmail.com"
              autoComplete="username"
            />
          </label>
          <label>
            App password
            <input
              type="password"
              value={imapPass}
              onChange={(e) => setImapPass(e.target.value)}
              placeholder="16-character app password"
              autoComplete="current-password"
            />
          </label>
          <div className="action-bar compact">
            <button className="btn btn-primary" type="submit" disabled={busy || !imapUser || !imapPass}>
              {imapBusy ? 'Connecting…' : 'Start Gmail/IMAP watch'}
            </button>
          </div>
        </form>
      </details>

      {result ? (
        <div className={`mail-verdict ${phishing ? 'bad' : 'ok'}`}>
          {phishing ? <MailWarning size={22} /> : <ShieldCheck size={22} />}
          <div>
            <strong>{result.verdict}</strong>
            <div className="muted" style={{ fontSize: '0.85rem' }}>
              {result.subject || result.sender || result.threat_type} · {Math.round((result.confidence || 0) * 100)}%
            </div>
          </div>
        </div>
      ) : null}

      <details className="mail-manual">
        <summary>Or check one email manually / upload .eml</summary>
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
              placeholder="Paste the full email text…"
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
        <div className="mail-extra">
          <label className="btn btn-secondary">
            <Upload size={16} />
            Upload .eml file
            <input type="file" accept=".eml,.txt" hidden onChange={handleUpload} />
          </label>
        </div>
      </details>
    </div>
  )
}
