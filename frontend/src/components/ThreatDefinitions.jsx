import {
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
  Network,
  Pickaxe,
  ShieldAlert,
  Siren,
  Skull,
  Users,
  Wifi,
  Worm,
} from 'lucide-react'

/** Virus / malware catalog shown on Threat Intelligence. */
const VIRUS_CATALOG = [
  {
    id: 'virus',
    title: 'Virus',
    color: 'var(--threat-virus)',
    Icon: Bug,
    evidence: 'Detection/family name + SHA-256 hash',
    description: 'File-infecting malware such as Win32/Expiro that attaches to host programs.',
  },
  {
    id: 'worm',
    title: 'Worm',
    color: 'var(--threat-worm)',
    Icon: Worm,
    evidence: 'Family name, e.g. WannaCry',
    description: 'Self-replicating malware that spreads across networks without user action.',
  },
  {
    id: 'trojan',
    title: 'Trojan',
    color: 'var(--threat-trojan)',
    Icon: Skull,
    evidence: 'Family name, e.g. Emotet',
    description: 'Disguised malicious programs that steal data or open attacker access.',
  },
  {
    id: 'ransomware',
    title: 'Ransomware',
    color: 'var(--threat-ransomware)',
    Icon: LockKeyhole,
    evidence: 'Family name, e.g. LockBit',
    description: 'Encrypts files and demands payment, locking victims out until a ransom is paid.',
  },
  {
    id: 'spyware',
    title: 'Spyware',
    color: 'var(--threat-spyware)',
    Icon: Eye,
    evidence: 'Family name, e.g. Pegasus',
    description: 'Secretly monitors activity and exfiltrates personal or corporate data.',
  },
  {
    id: 'adware',
    title: 'Adware',
    color: 'var(--threat-adware)',
    Icon: MonitorSmartphone,
    evidence: 'Detection/family name',
    description: 'Unwanted software that injects ads, hijacks browsers, or tracks installs.',
  },
  {
    id: 'rootkit',
    title: 'Rootkit',
    color: 'var(--threat-rootkit)',
    Icon: Ghost,
    evidence: 'Rootkit family/name',
    description: 'Hides processes, drivers, or files to conceal attacker presence.',
  },
  {
    id: 'botnet',
    title: 'Bot / Botnet',
    color: 'var(--threat-botnet)',
    Icon: Bot,
    evidence: 'Family name, e.g. Mirai',
    description: 'Compromised devices controlled as a swarm for floods or spam.',
  },
  {
    id: 'keylogger',
    title: 'Keylogger',
    color: 'var(--threat-keylogger)',
    Icon: Fingerprint,
    evidence: 'Family/name + hash',
    description: 'Captures keystrokes to steal credentials and sensitive input.',
  },
  {
    id: 'rat',
    title: 'RAT',
    color: 'var(--threat-rat)',
    Icon: Crosshair,
    evidence: 'Family name, e.g. AsyncRAT',
    description: 'Remote Access Trojans that give attackers interactive control of hosts.',
  },
  {
    id: 'downloader',
    title: 'Downloader / Dropper',
    color: 'var(--threat-downloader)',
    Icon: Download,
    evidence: 'Family/name + hash',
    description: 'Fetches or unpacks secondary payloads after initial compromise.',
  },
  {
    id: 'backdoor',
    title: 'Backdoor',
    color: 'var(--threat-backdoor)',
    Icon: HardDrive,
    evidence: 'Family/name + hash',
    description: 'Persistent covert access channel such as Cobalt Strike or webshells.',
  },
  {
    id: 'fileless',
    title: 'Fileless Malware',
    color: 'var(--threat-fileless)',
    Icon: Binary,
    evidence: 'Technique/family name',
    description: 'Runs in memory or via living-off-the-land tools to evade disk scanners.',
  },
  {
    id: 'cryptominer',
    title: 'Cryptominer',
    color: 'var(--threat-cryptominer)',
    Icon: Pickaxe,
    evidence: 'Family/name + hash',
    description: 'Hijacks CPU/GPU resources for unauthorized cryptocurrency mining.',
  },
]

/** Network / social classes already tracked by the platform. */
const NETWORK_CATALOG = [
  {
    id: 'phishing',
    title: 'Phishing',
    color: 'var(--threat-phishing)',
    Icon: Fish,
    evidence: 'Lure / credential harvest indicators',
    description: 'Deceptive messages that trick users into revealing credentials or installing payloads.',
  },
  {
    id: 'ddos',
    title: 'DDoS',
    color: 'var(--threat-ddos)',
    Icon: Wifi,
    evidence: 'Flood / capacity exhaustion indicators',
    description: 'Floods networks or services with traffic to exhaust capacity and deny availability.',
  },
  {
    id: 'brute-force',
    title: 'Brute Force',
    color: 'var(--threat-brute)',
    Icon: KeyRound,
    evidence: 'Repeated auth failures',
    description: 'Repeated login attempts that guess passwords until access is forced open.',
  },
  {
    id: 'social',
    title: 'Social Engineering',
    color: 'var(--threat-social)',
    Icon: Users,
    evidence: 'Human manipulation indicators',
    description: 'Manipulates people into breaking security procedures or sharing sensitive access.',
  },
]

function ThreatCard({ id, title, color, Icon, evidence, description, index }) {
  return (
    <article
      key={id}
      className="threat-def-card panel"
      style={{ '--accent': color, animationDelay: `${index * 0.03}s` }}
    >
      <header className="threat-def-head">
        <span className="threat-def-icon">
          <Icon size={18} />
        </span>
        <h3>{title}</h3>
      </header>
      <div className="threat-def-art" aria-hidden="true">
        <Icon size={48} strokeWidth={1.25} />
        <div className="threat-def-ring" />
      </div>
      <p className="threat-def-evidence mono">{evidence}</p>
      <p>{description}</p>
    </article>
  )
}

export default function ThreatDefinitions() {
  return (
    <div className="threat-defs-wrap">
      <div className="section-head threat-defs-heading">
        <h3>
          <Siren size={16} /> Virus & Malware Catalog
        </h3>
        <span>Family / detection evidence used by the classifier</span>
      </div>
      <section className="threat-defs threat-defs-dense" aria-label="Virus and malware definitions">
        {VIRUS_CATALOG.map((item, index) => (
          <ThreatCard key={item.id} {...item} index={index} />
        ))}
      </section>

      <div className="section-head threat-defs-heading">
        <h3>
          <Network size={16} /> Network & Social Attacks
        </h3>
        <span>Also classified by CYBER_SENTINEL.AI</span>
      </div>
      <section className="threat-defs threat-defs-network" aria-label="Network threat definitions">
        {NETWORK_CATALOG.map((item, index) => (
          <ThreatCard key={item.id} {...item} index={index} />
        ))}
      </section>
    </div>
  )
}
