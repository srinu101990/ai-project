/** Precautions / rectification steps shown after AI classification. */

const MALWARE_BASE = [
  'Isolate the affected endpoint from the network immediately.',
  'Capture memory/disk evidence and quarantine the sample.',
  'Block related hashes, domains, and C2 destinations.',
  'Patch the exploited software and rotate local/admin credentials.',
  'Hunt for persistence before reconnecting the host.',
]

export const REMEDIATION_BY_TYPE = {
  virus: {
    title: 'Virus — Precautions & Rectification',
    steps: [
      'Quarantine infected files and record detection/family + SHA-256.',
      ...MALWARE_BASE.slice(0, 3),
      'Restore clean copies from backup after verifying hash integrity.',
    ],
  },
  worm: {
    title: 'Worm — Precautions & Rectification',
    steps: [
      'Segment the LAN and disable vulnerable SMB/RDP exposure (e.g. WannaCry paths).',
      'Patch wormable services and block lateral movement ports.',
      ...MALWARE_BASE.slice(1, 4),
    ],
  },
  trojan: {
    title: 'Trojan — Precautions & Rectification',
    steps: [
      'Remove the trojanized installer/app (e.g. Emotet) and related macros.',
      'Reset credentials that may have been harvested.',
      ...MALWARE_BASE.slice(0, 3),
    ],
  },
  ransomware: {
    title: 'Ransomware — Precautions & Rectification',
    steps: [
      'Disconnect infected systems from LAN/Wi-Fi to stop lateral spread.',
      'Do not pay the ransom; preserve evidence and notify incident response.',
      'Disable SMB where possible and revoke exposed RDP/VPN sessions.',
      'Restore critical files from offline / immutable backups.',
      'Hunt for persistence (scheduled tasks, services) before reconnecting hosts.',
    ],
  },
  spyware: {
    title: 'Spyware — Precautions & Rectification',
    steps: [
      'Revoke sessions/tokens and assume monitored data may be compromised (e.g. Pegasus).',
      'Factory-reset or reimage high-risk mobile/endpoints when needed.',
      'Block exfiltration destinations and rotate credentials.',
      ...MALWARE_BASE.slice(0, 2),
    ],
  },
  adware: {
    title: 'Adware — Precautions & Rectification',
    steps: [
      'Remove unwanted browser extensions and reset hijacked homepage/search.',
      'Scan for Bundlore/Adware.Generic remnants and PUP installers.',
      'Enforce software allow-listing for future installs.',
    ],
  },
  rootkit: {
    title: 'Rootkit — Precautions & Rectification',
    steps: [
      'Boot to trusted media and scan offline for TDSS/ZeroAccess-class rootkits.',
      'Reimage if kernel integrity cannot be restored.',
      'Verify Secure Boot / driver signing after cleanup.',
      ...MALWARE_BASE.slice(0, 2),
    ],
  },
  botnet: {
    title: 'Bot / Botnet — Precautions & Rectification',
    steps: [
      'Isolate IoT/hosts recruited into Mirai-like botnets.',
      'Change default device credentials and patch firmware.',
      'Block C2 and sinkhole known botnet domains.',
      'Monitor for continued bot herder callbacks.',
    ],
  },
  keylogger: {
    title: 'Keylogger — Precautions & Rectification',
    steps: [
      'Force password resets for accounts used while the keylogger was active.',
      'Remove Agent Tesla/Formbook-class loaders and related hashes.',
      'Enable MFA everywhere and review recent auth logs.',
      ...MALWARE_BASE.slice(0, 2),
    ],
  },
  rat: {
    title: 'RAT — Precautions & Rectification',
    steps: [
      'Kill AsyncRAT/njRAT sessions and revoke remote access tools.',
      'Block C2 and rotate any credentials exposed during remote control.',
      ...MALWARE_BASE,
    ],
  },
  downloader: {
    title: 'Downloader / Dropper — Precautions & Rectification',
    steps: [
      'Block the downloader family/hash (e.g. Guloader, SmokeLoader).',
      'Hunt for stage-2 payloads already dropped on disk/memory.',
      ...MALWARE_BASE.slice(0, 3),
    ],
  },
  backdoor: {
    title: 'Backdoor — Precautions & Rectification',
    steps: [
      'Remove webshells / Cobalt Strike beacons and related hashes.',
      'Rotate service accounts and close exposed management ports.',
      ...MALWARE_BASE,
    ],
  },
  fileless: {
    title: 'Fileless Malware — Precautions & Rectification',
    steps: [
      'Capture memory and review PowerShell/WMI living-off-the-land activity.',
      'Disable risky script hosts where policy allows.',
      'Clear malicious WMI subscriptions and scheduled tasks.',
      'Reboot into a known-good state after containment.',
    ],
  },
  cryptominer: {
    title: 'Cryptominer — Precautions & Rectification',
    steps: [
      'Kill XMRig/Lemon Duck mining processes and remove persistence.',
      'Block mining pools and related hashes on egress firewall.',
      'Investigate the initial access path that installed the miner.',
      'Monitor CPU/GPU baselines after cleanup.',
    ],
  },
  malware: {
    title: 'Malware — Precautions & Rectification',
    steps: MALWARE_BASE,
  },
  phishing: {
    title: 'Phishing — Precautions & Rectification',
    steps: [
      'Do not click suspicious links or open unexpected attachments.',
      'Reset passwords for any account mentioned in the lure and enable MFA.',
      'Quarantine the email and report it to the security / SOC team.',
      'Block the sender domain and related malicious URLs on the gateway.',
      'Run awareness reminder for users about urgent payment/login scams.',
    ],
  },
  ddos: {
    title: 'DDoS — Precautions & Rectification',
    steps: [
      'Enable rate-limiting and geo/IP blocking on the edge firewall/WAF.',
      'Scale or fail-over to scrubbing / CDN protection if available.',
      'Null-route or blackhole confirmed attack source ranges.',
      'Monitor bandwidth and service health until traffic returns to baseline.',
      'Review open internet-facing services and close unused ports.',
    ],
  },
  'brute-force': {
    title: 'Brute Force — Precautions & Rectification',
    steps: [
      'Temporarily lock the targeted accounts and force password resets.',
      'Enable MFA and account lockout after repeated failed logins.',
      'Block attacking source IPs on VPN/SSH/RDP gateways.',
      'Review auth logs for successful compromises during the spray window.',
      'Move admin services off default ports and restrict by allow-list.',
    ],
  },
  social: {
    title: 'Social Engineering — Precautions & Rectification',
    steps: [
      'Verify unusual payment/MFA requests through a known secondary channel.',
      'Revoke any access or tokens shared during the impersonation attempt.',
      'Alert finance/help-desk teams about CEO fraud and gift-card scams.',
      'Document the conversation and report to security awareness leads.',
      'Reinforce “stop–verify–report” procedure for urgent executive requests.',
    ],
  },
  benign: {
    title: 'Benign — Recommended Precautions',
    steps: [
      'No active incident response required for this sample.',
      'Continue routine monitoring of network and endpoint telemetry.',
      'Keep baselines updated so true anomalies stand out clearly.',
      'Retain the event for audit/history if needed.',
      'Re-classify if related indicators later appear suspicious.',
    ],
  },
}

export function remediationFor(threatType) {
  if (!threatType) return null
  return (
    REMEDIATION_BY_TYPE[threatType] ||
    REMEDIATION_BY_TYPE[String(threatType).toLowerCase()] ||
    null
  )
}
