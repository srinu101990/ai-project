import { useMemo, useState } from 'react'
import {
  Activity,
  ArrowLeft,
  Bug,
  Binary,
  Bot,
  Crosshair,
  Download,
  Eye,
  Fingerprint,
  Fish,
  Ghost,
  HardDrive,
  KeyRound,
  LockKeyhole,
  MonitorSmartphone,
  Pickaxe,
  ShieldCheck,
  Siren,
  Skull,
  Users,
  Wifi,
  Worm,
} from 'lucide-react'
import { REMEDIATION_BY_TYPE } from '../utils/remediation'

const SEVERITY_BY_TYPE = {
  ransomware: 'critical',
  worm: 'critical',
  rootkit: 'critical',
  rat: 'critical',
  backdoor: 'critical',
  botnet: 'critical',
  fileless: 'high',
  trojan: 'high',
  virus: 'high',
  spyware: 'high',
  keylogger: 'high',
  downloader: 'high',
  cryptominer: 'medium',
  adware: 'medium',
  ddos: 'high',
  'brute-force': 'high',
  phishing: 'medium',
  social: 'medium',
}

const INTEL = {
  virus: {
    category: 'Malware family',
    spreads:
      'Attaches to host files and shared documents. Spreads when an infected program is copied or executed on another system.',
    affects: 'Executable files, documents, mapped drives, and user profiles on Windows endpoints.',
    indicators: 'Unexpected file changes, AV family detections (for example Win32/Expiro), and matching SHA-256 hashes.',
    activity: 'File infection, payload execution, and attempts to modify or corrupt legitimate programs.',
    precautions: 'Keep real-time AV/EDR on, avoid unknown executables, and scan removable media before use.',
    prevention: 'Patch OS and apps, disable autorun, and block unsigned binaries with application control.',
    controls: 'EDR quarantine, hash block lists, software allow-listing, and offline backup restore points.',
    userActions: 'Do not open unexpected attachments. Report AV alerts instead of ignoring them.',
  },
  worm: {
    category: 'Malware family',
    spreads:
      'Self-replicates across the LAN through exposed services such as SMB or RDP, without waiting for a user to click.',
    affects: 'Networked Windows hosts, file shares, and unpatched remote-access services.',
    indicators: 'Sudden lateral traffic, worm family names (WannaCry, Conficker), and many hosts alerting at once.',
    activity: 'Scanning neighbors, exploiting wormable ports, dropping copies of itself, and disrupting services.',
    precautions: 'Turn off unused file sharing, restrict RDP, and keep wormable CVEs patched immediately.',
    prevention: 'Segment the LAN, close SMB to the internet, and apply emergency patches for wormable bugs.',
    controls: 'Host firewalls, SMB signing, VPN-only remote access, and rapid isolation playbooks.',
    userActions: 'Disconnect a rapidly spreading PC from Wi-Fi and report it to the SOC before cleaning it.',
  },
  trojan: {
    category: 'Malware family',
    spreads: 'Arrives disguised as a useful installer, cracked app, or Office macro document (for example Emotet).',
    affects: 'User workstations, browsers, email clients, and any credentials stored on the host.',
    indicators: 'Unexpected new programs, macro-enabled documents, and family detections such as Emotet or TrickBot.',
    activity: 'Credential theft, secondary downloads, and opening covert access for the attacker.',
    precautions: 'Do not install pirated software. Disable macros from the internet and verify publishers.',
    prevention: 'Email attachment sandboxing, SmartScreen, and blocking known trojan hashes and C2 domains.',
    controls: 'Application allow-listing, macro policies, and credential rotation after a confirmed trojan.',
    userActions: 'Uninstall the unexpected app, change passwords from a clean device, and report the file name.',
  },
  ransomware: {
    category: 'Malware family',
    spreads: 'Phishing, exposed RDP, and lateral SMB movement after the first host is encrypted.',
    affects: 'User files, backups/shadow copies, mapped drives, and sometimes hypervisors or NAS shares.',
    indicators: 'Ransom notes, mass file extension changes, failed backups, and families such as LockBit or Conti.',
    activity: 'File encryption, backup deletion, privilege escalation, and a payment demand.',
    precautions: 'Keep offline backups, disable unused SMB, and never pay a ransom from a student/lab host.',
    prevention: 'Immutable backups, least-privilege admin, and rapid isolation of the first encrypted host.',
    controls: 'EDR ransomware behavior rules, network segmentation, and restore-from-backup runbooks.',
    userActions: 'Unplug the PC from the network immediately and do not delete the ransom note (it is evidence).',
  },
  spyware: {
    category: 'Malware family',
    spreads: 'Malicious apps, watered-hole sites, or targeted mobile implants such as Pegasus-class spyware.',
    affects: 'Messages, contacts, location, camera/mic, and browser sessions on PCs and phones.',
    indicators: 'Unusual battery drain, unexpected permissions, and privacy-tool detections of spyware families.',
    activity: 'Silent monitoring and exfiltration of personal or corporate data with little visible damage.',
    precautions: 'Review app permissions, avoid unofficial app stores, and lock screens when away from the device.',
    prevention: 'Mobile device management, least-privilege apps, and traffic inspection for known exfil destinations.',
    controls: 'Token revocation, device wipe/reimage, and privacy incident notification if personal data leaked.',
    userActions: 'Stop using the device for banking/mail until it is checked. Rotate passwords from a clean system.',
  },
  adware: {
    category: 'Malware family',
    spreads: 'Bundled freeware installers, fake update prompts, and browser extension marketplaces.',
    affects: 'Browsers, homepage/search settings, and user privacy through tracking cookies.',
    indicators: 'Pop-up ads, hijacked search, and detections such as Bundlore or Adware.Generic.',
    activity: 'Injecting ads, tracking installs, and sometimes opening the door to riskier PUPs.',
    precautions: 'Use the official browser store only and decline bundled “optional offers” during installs.',
    prevention: 'Software allow-listing, extension control, and blocking known adware publisher certificates.',
    controls: 'Browser reset policies, scheduled AV scans, and removal of unexpected scheduled tasks.',
    userActions: 'Remove unknown extensions, reset the browser, and run a full AV scan.',
  },
  rootkit: {
    category: 'Malware family',
    spreads: 'Follows an earlier exploit or malicious driver install, then hides at kernel or boot level.',
    affects: 'OS kernel, drivers, boot records, and security tools that can no longer see hidden processes.',
    indicators: 'Missing processes in Task Manager vs EDR, driver signing failures, families such as TDSS.',
    activity: 'Hiding files/processes, protecting other malware, and surviving ordinary uninstalls.',
    precautions: 'Enable Secure Boot and do not install unsigned drivers from random sites.',
    prevention: 'Driver signature enforcement, firmware updates, and boot-time scanning.',
    controls: 'Offline scans from trusted media and full reimage when kernel integrity cannot be proven.',
    userActions: 'Do not keep using a PC that “looks clean” but EDR still flags a rootkit. Hand it to IT.',
  },
  botnet: {
    category: 'Malware family',
    spreads: 'Weak default passwords on IoT cameras/routers (Mirai-class) or PC malware that joins a swarm.',
    affects: 'Cameras, routers, PCs, and the wider network when the swarm is used for floods or spam.',
    indicators: 'Devices calling known C2, outbound flood traffic, and families such as Mirai or Emotet botnet.',
    activity: 'Beaconing to a bot-herder, waiting for commands, then joining DDoS or spam campaigns.',
    precautions: 'Change default IoT passwords and keep cameras off the main student LAN when possible.',
    prevention: 'Firmware updates, unique credentials, and blocking known botnet C2 domains.',
    controls: 'VLAN isolation for IoT, egress filtering, and sinkholing of bot-herder domains.',
    userActions: 'Unplug an infected camera/router, factory-reset it, and set a new strong password.',
  },
  keylogger: {
    category: 'Malware family',
    spreads: 'Trojanized apps, phishing attachments, or infostealer loaders such as Agent Tesla.',
    affects: 'Keystrokes, clipboard, saved browser passwords, and authentication to mail/banking sites.',
    indicators: 'Unexpected keyboard hooks, clipboard theft, and families such as Agent Tesla or Formbook.',
    activity: 'Recording typed secrets and shipping them to attacker-controlled C2.',
    precautions: 'Use a password manager (it types for you) and enable MFA so stolen passwords are not enough.',
    prevention: 'Block known infostealer hashes, restrict unsigned software, and monitor C2 callbacks.',
    controls: 'Forced password resets, MFA enrollment, and review of logins during the infection window.',
    userActions: 'Change important passwords from a different clean device and enable MFA everywhere.',
  },
  rat: {
    category: 'Malware family',
    spreads: 'Cracked remote-admin tools, malicious email payloads, or fake “support” software.',
    affects: 'Desktop sessions, files, webcams, and any application the user can see or type into.',
    indicators: 'Unknown remote-access processes, families such as AsyncRAT, njRAT, or Quasar, and odd mouse activity.',
    activity: 'Interactive remote control, file theft, screenshotting, and dropping extra implants.',
    precautions: 'Do not install unsolicited remote-support tools. Lock the screen when leaving the PC.',
    prevention: 'Block common RAT C2 ports/domains and alert on new remote-access binaries.',
    controls: 'Kill unauthorized remote sessions, rotate credentials, and hunt for secondary payloads.',
    userActions: 'Disconnect from Wi-Fi, do not enter passwords, and report if the mouse moves on its own.',
  },
  downloader: {
    category: 'Malware family',
    spreads: 'First-stage phishing documents or drive-by downloads (Guloader, SmokeLoader).',
    affects: 'The initially compromised host, then whatever stage-2 malware it fetches next.',
    indicators: 'Small loader hashes, unusual PowerShell/HTTP fetches, and follow-on trojan or ransomware alerts.',
    activity: 'Fetching or unpacking a more dangerous second payload after the first foothold.',
    precautions: 'Do not enable macros. Treat “open this invoice” files from unknown senders as hostile.',
    prevention: 'Attachment sandboxing, URL rewriting, and blocking known loader hashes and delivery URLs.',
    controls: 'Hunt for stage-2 files in %TEMP%, remove loader persistence, and block the delivery path.',
    userActions: 'Do not reopen the original attachment. Tell IT the exact file name and sender.',
  },
  backdoor: {
    category: 'Malware family',
    spreads: 'Webshells on exposed apps, or beacons such as Cobalt Strike after an earlier breach.',
    affects: 'Servers, web roots, service accounts, and long-term access to the environment.',
    indicators: 'Unexpected admin tools, China Chopper-style webshells, and periodic beacon traffic.',
    activity: 'Covert remote commands without normal login, persistence, and data staging.',
    precautions: 'Do not expose admin panels to the internet. Use MFA and unique service passwords.',
    prevention: 'Web-root integrity checks, least-privilege app pools, and outbound C2 detection.',
    controls: 'Remove webshells/beacons, rotate service accounts, and close unused management ports.',
    userActions: 'Report mystery “.aspx/.php” files or unknown admin utilities instead of deleting them quietly.',
  },
  fileless: {
    category: 'Malware family',
    spreads: 'Living-off-the-land scripts (PowerShell, WMI) launched from a document or existing access.',
    affects: 'Memory, scheduled tasks, WMI subscriptions, and trusted OS tools rather than a file on disk.',
    indicators: 'Encoded PowerShell, Empire-like tradecraft, and alerts with little or no dropped EXE.',
    activity: 'In-memory execution, credential access, and persistence through scripts instead of files.',
    precautions: 'Treat unexpected PowerShell windows as an incident. Do not run emailed .ps1/.vbs files.',
    prevention: 'Constrained language mode, script-block logging, and disabling unused script hosts.',
    controls: 'Capture memory, clear malicious WMI/tasks, and reboot into a known-good state after cleanup.',
    userActions: 'Close the script window, disconnect the PC, and do not save or forward the script.',
  },
  cryptominer: {
    category: 'Malware family',
    spreads: 'Weak servers, cracked software, or worms that drop miners such as XMRig after entry.',
    affects: 'CPU/GPU performance, electricity/heat, and any service that becomes slow or unstable.',
    indicators: 'High CPU with XMRig/Lemon Duck families, mining-pool DNS, and fans at full speed while idle.',
    activity: 'Hijacking hardware to mine cryptocurrency and calling mining pools on the internet.',
    precautions: 'Watch for unexplained high CPU. Do not run unknown “optimizer” or crack tools.',
    prevention: 'Block mining pools on egress, keep servers patched, and alert on sustained CPU anomalies.',
    controls: 'Kill miner processes, remove persistence jobs, and investigate how the miner was installed.',
    userActions: 'Note if the laptop is suddenly slow/hot, then run a scan and report pool domains if shown.',
  },
  phishing: {
    category: 'Network / social attack',
    spreads: 'Deceptive email, SMS, or chat lures that impersonate banks, HR, or IT help desks.',
    affects: 'User credentials, mailbox access, and any payload launched from a malicious link or attachment.',
    indicators: 'Look-alike domains, urgent payment/login language, and credential-harvest form pages.',
    activity: 'Tricking the user into revealing secrets or installing malware that follows the click.',
    precautions: 'Hover links, never send passwords by mail, and verify HR/payroll requests in person or by known chat.',
    prevention: 'MFA, advanced email filtering, and reporting buttons on the mail client.',
    controls: 'Quarantine the message, block the sender domain/URL, and reset any entered passwords.',
    userActions: 'Do not click. Report the mail to security. Change the password if you already typed it.',
  },
  ddos: {
    category: 'Network / social attack',
    spreads: 'Botnets and rented flood services sending SYN, UDP, or HTTP traffic at a target.',
    affects: 'Internet-facing websites, APIs, VPN concentrators, and LAN bandwidth.',
    indicators: 'Capacity exhaustion, error spikes, and floods from many source addresses.',
    activity: 'Denying legitimate users access by saturating CPU, bandwidth, or application threads.',
    precautions: 'Keep unused ports closed and know how to fail over to a CDN or scrubbing service.',
    prevention: 'Rate-limits, WAF/CDN, and anycast or cloud offload for public services.',
    controls: 'Geo/IP blocking, blackholing confirmed attack ranges, and capacity monitoring until baseline returns.',
    userActions: 'Report sudden “site down” plus network slowness; do not try to “fix” it by disabling the firewall.',
  },
  'brute-force': {
    category: 'Network / social attack',
    spreads: 'Password spraying and credential stuffing against SSH, RDP, VPN, or web logins.',
    affects: 'User accounts, remote-access gateways, and any service with weak or reused passwords.',
    indicators: 'Bursts of failed logins, password-spray patterns, and success after many failures.',
    activity: 'Guessing or reusing leaked passwords until an account opens.',
    precautions: 'Unique passwords and MFA on VPN/SSH/RDP. Do not expose RDP to the whole internet.',
    prevention: 'Account lockout, MFA, allow-listed admin IPs, and non-default service ports where appropriate.',
    controls: 'Block attacking IPs, force resets, and review logs for successful logins in the spray window.',
    userActions: 'If you see many failed sign-ins, change the password and tell IT before the attacker succeeds.',
  },
  social: {
    category: 'Network / social attack',
    spreads: 'Phone, chat, or in-person impersonation of executives, IT, or vendors (CEO fraud, help-desk scams).',
    affects: 'People, payment processes, MFA codes, and any access a human can approve.',
    indicators: 'Urgent secrecy, unusual payment/MFA requests, and pressure to skip normal checks.',
    activity: 'Manipulating a person into breaking policy rather than exploiting a software bug.',
    precautions: 'Verify unusual money or MFA requests on a known second channel. Slow down under pressure.',
    prevention: 'Awareness training, dual-control payments, and help-desk identity verification scripts.',
    controls: 'Revoke shared tokens, alert finance/help-desk, and document the conversation for IR.',
    userActions: 'Stop, verify, report. Never read an MFA code to an unsolicited caller.',
  },
}

const VIRUS_CATALOG = [
  { id: 'virus', title: 'Virus', color: 'var(--threat-virus)', Icon: Bug, description: 'File-infecting malware such as Win32/Expiro that attaches to host programs.' },
  { id: 'worm', title: 'Worm', color: 'var(--threat-worm)', Icon: Worm, description: 'Self-replicating malware that spreads across networks without user action.' },
  { id: 'trojan', title: 'Trojan', color: 'var(--threat-trojan)', Icon: Skull, description: 'Disguised malicious programs that steal data or open attacker access.' },
  { id: 'ransomware', title: 'Ransomware', color: 'var(--threat-ransomware)', Icon: LockKeyhole, description: 'Encrypts files and demands payment, locking victims out until a ransom is paid.' },
  { id: 'spyware', title: 'Spyware', color: 'var(--threat-spyware)', Icon: Eye, description: 'Secretly monitors activity and exfiltrates personal or corporate data.' },
  { id: 'adware', title: 'Adware', color: 'var(--threat-adware)', Icon: MonitorSmartphone, description: 'Unwanted software that injects ads, hijacks browsers, or tracks installs.' },
  { id: 'rootkit', title: 'Rootkit', color: 'var(--threat-rootkit)', Icon: Ghost, description: 'Hides processes, drivers, or files to conceal attacker presence.' },
  { id: 'botnet', title: 'Bot / Botnet', color: 'var(--threat-botnet)', Icon: Bot, description: 'Compromised devices controlled as a swarm for floods or spam.' },
  { id: 'keylogger', title: 'Keylogger', color: 'var(--threat-keylogger)', Icon: Fingerprint, description: 'Captures keystrokes to steal credentials and sensitive input.' },
  { id: 'rat', title: 'RAT', color: 'var(--threat-rat)', Icon: Crosshair, description: 'Remote Access Trojans that give attackers interactive control of hosts.' },
  { id: 'downloader', title: 'Downloader / Dropper', color: 'var(--threat-downloader)', Icon: Download, description: 'Fetches or unpacks secondary payloads after initial compromise.' },
  { id: 'backdoor', title: 'Backdoor', color: 'var(--threat-backdoor)', Icon: HardDrive, description: 'Persistent covert access channel such as Cobalt Strike or webshells.' },
  { id: 'fileless', title: 'Fileless Malware', color: 'var(--threat-fileless)', Icon: Binary, description: 'Runs in memory or via living-off-the-land tools to evade disk scanners.' },
  { id: 'cryptominer', title: 'Cryptominer', color: 'var(--threat-cryptominer)', Icon: Pickaxe, description: 'Hijacks CPU/GPU resources for unauthorized cryptocurrency mining.' },
  { id: 'phishing', title: 'Phishing', color: 'var(--threat-phishing)', Icon: Fish, description: 'Deceptive messages that trick users into revealing credentials or installing payloads.' },
  { id: 'ddos', title: 'DDoS', color: 'var(--threat-ddos)', Icon: Wifi, description: 'Floods networks or services with traffic to exhaust capacity and deny availability.' },
  { id: 'brute-force', title: 'Brute Force', color: 'var(--threat-brute)', Icon: KeyRound, description: 'Repeated login attempts that guess passwords until access is forced open.' },
  { id: 'social', title: 'Social Engineering', color: 'var(--threat-social)', Icon: Users, description: 'Manipulates people into breaking security procedures or sharing sensitive access.' },
]

function enrich(item) {
  const guide = REMEDIATION_BY_TYPE[item.id] || {}
  const extra = INTEL[item.id] || {}
  return {
    ...item,
    category: extra.category || 'Threat',
    severity: SEVERITY_BY_TYPE[item.id] || 'medium',
    examples: guide.examples,
    evidence: guide.evidence,
    behavior: guide.behavior,
    mitigation: guide.steps || [],
    ...extra,
  }
}

function ThreatCard({ title, color, Icon, description, index, onOpen }) {
  return (
    <button
      type="button"
      className="threat-def-card panel"
      style={{ '--accent': color, animationDelay: `${index * 0.03}s` }}
      onClick={onOpen}
    >
      <header className="threat-def-head">
        <span className="threat-def-icon">
          <Icon size={14} />
        </span>
        <h3>{title}</h3>
      </header>
      <div className="threat-def-art" aria-hidden="true">
        <Icon size={34} strokeWidth={1.35} />
        <div className="threat-def-ring" />
      </div>
      <p>{description}</p>
    </button>
  )
}

function VirusDetail({ item, onBack }) {
  const Icon = item.Icon
  return (
    <article className="panel section known-virus-detail">
      <div className="known-virus-detail-bar">
        <button type="button" className="btn btn-ghost" onClick={onBack}>
          <ArrowLeft size={16} />
          Back to catalog
        </button>
        <span className={`badge ${item.severity}`}>{item.severity}</span>
      </div>
      <header className="known-virus-detail-head">
        <span className="threat-def-icon" style={{ '--accent': item.color, width: 36, height: 36 }}>
          <Icon size={18} />
        </span>
        <div>
          <h3>{item.title}</h3>
          <span className="muted">{item.category}</span>
        </div>
      </header>

      <nav className="known-virus-jump" aria-label="Detail sections">
        <a href="#virus-about">About</a>
        <a href="#virus-behavior">Behavior</a>
        <a href="#virus-prevention">Prevention</a>
      </nav>

      <section id="virus-about" className="known-virus-section">
        <h4>1. About</h4>
        <dl className="known-virus-meta">
          <div>
            <dt>Name</dt>
            <dd>{item.title}</dd>
          </div>
          <div>
            <dt>Category / type</dt>
            <dd>{item.category}</dd>
          </div>
          <div>
            <dt>Severity / risk</dt>
            <dd className={`badge ${item.severity}`}>{item.severity}</dd>
          </div>
          <div>
            <dt>Examples</dt>
            <dd>{item.examples || '—'}</dd>
          </div>
          <div>
            <dt>Evidence to record</dt>
            <dd>{item.evidence || '—'}</dd>
          </div>
        </dl>
        <p>{item.description}</p>
      </section>

      <section id="virus-behavior" className="known-virus-section">
        <h4>
          <Activity size={16} /> 2. Behavior
        </h4>
        <p>{item.behavior}</p>
        <dl className="known-virus-meta">
          <div>
            <dt>How it spreads</dt>
            <dd>{item.spreads}</dd>
          </div>
          <div>
            <dt>What it can affect</dt>
            <dd>{item.affects}</dd>
          </div>
          <div>
            <dt>Common indicators</dt>
            <dd>{item.indicators}</dd>
          </div>
          <div>
            <dt>Typical malicious activity</dt>
            <dd>{item.activity}</dd>
          </div>
        </dl>
      </section>

      <section id="virus-prevention" className="known-virus-section">
        <h4>
          <ShieldCheck size={16} /> 3. Prevention
        </h4>
        <p>{item.precautions}</p>
        <div className="known-virus-split">
          <div>
            <strong>Steps to prevent infection</strong>
            <p>{item.prevention}</p>
          </div>
          <div>
            <strong>Security controls</strong>
            <p>{item.controls}</p>
          </div>
          <div>
            <strong>Recommended user actions</strong>
            <p>{item.userActions}</p>
          </div>
        </div>
        <strong>Mitigation / remediation</strong>
        <ol className="remediation-list">
          {(item.mitigation || []).map((step) => (
            <li key={step}>{step}</li>
          ))}
        </ol>
      </section>
    </article>
  )
}

export default function ThreatDefinitions() {
  const catalog = useMemo(() => VIRUS_CATALOG.map(enrich), [])
  const [selectedId, setSelectedId] = useState(null)
  const selected = catalog.find((item) => item.id === selectedId) || null

  if (selected) {
    return <VirusDetail item={selected} onBack={() => setSelectedId(null)} />
  }

  return (
    <div className="panel section threat-defs-wrap">
      <div className="section-head threat-defs-heading">
        <h3>
          <Siren size={16} /> Known Virus
        </h3>
        <span>Select a threat card for about, behavior, and prevention details</span>
      </div>
      <section className="threat-defs threat-defs-known" aria-label="Known virus catalog">
        {catalog.map((item, index) => (
          <ThreatCard
            key={item.id}
            {...item}
            index={index}
            onOpen={() => setSelectedId(item.id)}
          />
        ))}
      </section>
    </div>
  )
}
