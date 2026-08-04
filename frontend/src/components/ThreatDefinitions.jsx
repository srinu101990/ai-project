import {
  Bug,
  LockKeyhole,
  Fish,
  Wifi,
  KeyRound,
  Users,
} from 'lucide-react'

const THREATS = [
  {
    id: 'malware',
    title: 'Malware',
    color: 'var(--threat-malware)',
    Icon: Bug,
    description: 'Malicious software designed to damage, disrupt, or gain unauthorized access to systems.',
  },
  {
    id: 'ransomware',
    title: 'Ransomware',
    color: 'var(--threat-ransomware)',
    Icon: LockKeyhole,
    description: 'Encrypts files and demands payment, locking victims out until a ransom is paid.',
  },
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

export default function ThreatDefinitions() {
  return (
    <section className="threat-defs" aria-label="Threat definitions">
      {THREATS.map(({ id, title, color, Icon, description }, index) => (
        <article
          key={id}
          className="threat-def-card panel"
          style={{ '--accent': color, animationDelay: `${index * 0.05}s` }}
        >
          <header className="threat-def-head">
            <span className="threat-def-icon">
              <Icon size={18} />
            </span>
            <h3>{title}</h3>
          </header>
          <div className="threat-def-art" aria-hidden="true">
            <Icon size={54} strokeWidth={1.25} />
            <div className="threat-def-ring" />
          </div>
          <p>{description}</p>
        </article>
      ))}
    </section>
  )
}
