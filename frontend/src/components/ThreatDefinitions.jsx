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
    description: 'File-infecting malware such as Win32/Expiro that attaches to host programs.',
  },
  {
    id: 'worm',
    title: 'Worm',
    color: 'var(--threat-worm)',
    Icon: Worm,
    description: 'Self-replicating malware that spreads across networks without user action.',
  },
  {
    id: 'trojan',
    title: 'Trojan',
    color: 'var(--threat-trojan)',
    Icon: Skull,
    description: 'Disguised malicious programs that steal data or open attacker access.',
  },
  {
    id: 'ransomware',
    title: 'Ransomware',
    color: 'var(--threat-ransomware)',
    Icon: LockKeyhole,
    description: 'Encrypts files and demands payment, locking victims out until a ransom is paid.',
  },
  {
    id: 'spyware',
    title: 'Spyware',
    color: 'var(--threat-spyware)',
    Icon: Eye,
    description: 'Secretly monitors activity and exfiltrates personal or corporate data.',
  },
  {
    id: 'adware',
    title: 'Adware',
    color: 'var(--threat-adware)',
    Icon: MonitorSmartphone,
    description: 'Unwanted software that injects ads, hijacks browsers, or tracks installs.',
  },
  {
    id: 'rootkit',
    title: 'Rootkit',
    color: 'var(--threat-rootkit)',
    Icon: Ghost,
    description: 'Hides processes, drivers, or files to conceal attacker presence.',
  },
  {
    id: 'botnet',
    title: 'Bot / Botnet',
    color: 'var(--threat-botnet)',
    Icon: Bot,
    description: 'Compromised devices controlled as a swarm for floods or spam.',
  },
  {
    id: 'keylogger',
    title: 'Keylogger',
    color: 'var(--threat-keylogger)',
    Icon: Fingerprint,
    description: 'Captures keystrokes to steal credentials and sensitive input.',
  },
  {
    id: 'rat',
    title: 'RAT',
    color: 'var(--threat-rat)',
    Icon: Crosshair,
    description: 'Remote Access Trojans that give attackers interactive control of hosts.',
  },
  {
    id: 'downloader',
    title: 'Downloader / Dropper',
    color: 'var(--threat-downloader)',
    Icon: Download,
    description: 'Fetches or unpacks secondary payloads after initial compromise.',
  },
  {
    id: 'backdoor',
    title: 'Backdoor',
    color: 'var(--threat-backdoor)',
    Icon: HardDrive,
    description: 'Persistent covert access channel such as Cobalt Strike or webshells.',
  },
  {
    id: 'fileless',
    title: 'Fileless Malware',
    color: 'var(--threat-fileless)',
    Icon: Binary,
    description: 'Runs in memory or via living-off-the-land tools to evade disk scanners.',
  },
  {
    id: 'cryptominer',
    title: 'Cryptominer',
    color: 'var(--threat-cryptominer)',
    Icon: Pickaxe,
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
    description: 'Deceptive messages that trick users into revealing credentials or installing payloads.',
  },
  {
    id: 'ddos',
    title: 'DDoS',
    color: 'var(--threat-ddos)',
    Icon: Wifi,
    description: 'Floods networks or services with traffic to exhaust capacity and deny availability.',
  },
  {
    id: 'brute-force',
    title: 'Brute Force',
    color: 'var(--threat-brute)',
    Icon: KeyRound,
    description: 'Repeated login attempts that guess passwords until access is forced open.',
  },
  {
    id: 'social',
    title: 'Social Engineering',
    color: 'var(--threat-social)',
    Icon: Users,
    description: 'Manipulates people into breaking security procedures or sharing sensitive access.',
  },
]

function ThreatCard({ title, color, Icon, description, index }) {
  return (
    <article
      className="threat-def-card panel"
      style={{ '--accent': color, animationDelay: `${index * 0.03}s` }}
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
        <span>Core malware families classified by the platform</span>
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
