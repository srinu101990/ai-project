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
    title: 'Virus',
    evidence: 'Detection/family name + SHA-256 hash',
    examples: 'Win32/Expiro, Generic.Virus',
    steps: [
      'Record the AV detection/family name and full SHA-256 of the sample.',
      'Quarantine or delete infected files after backup verification.',
      'Scan peer systems that shared the same file or download source.',
      'Block the hash on EDR/email gateway allow/deny lists.',
      'Restore clean copies from known-good backups.',
    ],
  },
  worm: {
    title: 'Worm',
    evidence: 'Family name, e.g. WannaCry',
    examples: 'WannaCry, Conficker',
    steps: [
      'Identify the worm family (e.g. WannaCry) from EDR/IDS alerts.',
      'Segment the LAN and disable vulnerable SMB/RDP exposure.',
      'Patch wormable services and block lateral-movement ports.',
      'Isolate infected hosts before cleanup to stop self-replication.',
      'Hunt for additional hosts with the same worm family signature.',
    ],
  },
  trojan: {
    title: 'Trojan',
    evidence: 'Family name, e.g. Emotet',
    examples: 'Emotet, TrickBot',
    steps: [
      'Confirm the trojan family (e.g. Emotet) from detection telemetry.',
      'Remove the trojanized installer/app and related Office macros.',
      'Reset credentials that may have been harvested.',
      'Block C2 domains/IPs linked to that family.',
      'Reimage if persistence cannot be fully removed.',
    ],
  },
  ransomware: {
    title: 'Ransomware',
    evidence: 'Family name, e.g. LockBit',
    examples: 'LockBit, Conti, WannaCry',
    steps: [
      'Note the ransomware family (e.g. LockBit) from the ransom note/EDR.',
      'Disconnect infected systems from LAN/Wi-Fi to stop lateral spread.',
      'Do not pay the ransom; preserve evidence and notify incident response.',
      'Disable SMB where possible and revoke exposed RDP/VPN sessions.',
      'Restore critical files from offline / immutable backups.',
    ],
  },
  spyware: {
    title: 'Spyware',
    evidence: 'Family name, e.g. Pegasus',
    examples: 'Pegasus, DarkHotel',
    steps: [
      'Record the spyware family (e.g. Pegasus) and affected device IDs.',
      'Revoke sessions/tokens; assume monitored data may be compromised.',
      'Factory-reset or reimage high-risk mobile/endpoints when needed.',
      'Block exfiltration destinations and rotate credentials.',
      'Notify legal/privacy stakeholders if personal data was exposed.',
    ],
  },
  adware: {
    title: 'Adware',
    evidence: 'Detection/family name',
    examples: 'Bundlore, Adware.Generic',
    steps: [
      'Capture the adware detection/family name from AV reports.',
      'Remove unwanted browser extensions and reset hijacked homepage/search.',
      'Uninstall PUP bundles and scan for leftover scheduled tasks.',
      'Enforce software allow-listing for future installs.',
      'Educate users about freeware installers that bundle adware.',
    ],
  },
  rootkit: {
    title: 'Rootkit',
    evidence: 'Rootkit family/name',
    examples: 'TDSS, ZeroAccess',
    steps: [
      'Identify the rootkit family/name (e.g. TDSS, ZeroAccess).',
      'Boot to trusted media and scan offline for hidden drivers.',
      'Reimage if kernel integrity cannot be restored.',
      'Verify Secure Boot / driver signing after cleanup.',
      'Monitor for reappearance of the same rootkit family.',
    ],
  },
  botnet: {
    title: 'Bot / Botnet malware',
    evidence: 'Family name, e.g. Mirai',
    examples: 'Mirai, Emotet botnet',
    steps: [
      'Confirm the botnet family (e.g. Mirai) from IoT/EDR telemetry.',
      'Isolate recruited hosts/cameras from the production network.',
      'Change default device credentials and patch firmware.',
      'Block C2 and sinkhole known botnet domains for that family.',
      'Monitor for continued bot-herder callbacks.',
    ],
  },
  keylogger: {
    title: 'Keylogger',
    evidence: 'Family/name + hash',
    examples: 'Agent Tesla, Formbook',
    steps: [
      'Record keylogger family/name and SHA-256 from quarantine.',
      'Force password resets for accounts used while it was active.',
      'Remove Agent Tesla/Formbook-class loaders and related hashes.',
      'Enable MFA everywhere and review recent auth logs.',
      'Check clipboard/browser-saved credentials for exposure.',
    ],
  },
  rat: {
    title: 'RAT (Remote Access Trojan)',
    evidence: 'Family name, e.g. AsyncRAT',
    examples: 'AsyncRAT, njRAT, Quasar',
    steps: [
      'Identify the RAT family (e.g. AsyncRAT) and active remote sessions.',
      'Kill RAT processes and revoke unauthorized remote-access tools.',
      'Block C2 destinations tied to that family.',
      'Rotate any credentials exposed during remote control.',
      'Hunt for secondary implants dropped by the RAT.',
    ],
  },
  downloader: {
    title: 'Downloader / Dropper',
    evidence: 'Family/name + hash',
    examples: 'Guloader, SmokeLoader',
    steps: [
      'Record downloader/dropper family and SHA-256.',
      'Block the hash and related delivery URLs on gateway/EDR.',
      'Hunt for stage-2 payloads already dropped on disk/memory.',
      'Remove persistence created by the loader.',
      'Trace the initial phishing/drive-by path that delivered it.',
    ],
  },
  backdoor: {
    title: 'Backdoor',
    evidence: 'Family/name + hash',
    examples: 'Cobalt Strike, China Chopper',
    steps: [
      'Capture backdoor family/name and SHA-256 (beacon/webshell).',
      'Remove Cobalt Strike beacons / China Chopper webshells.',
      'Rotate service accounts and close exposed management ports.',
      'Review web roots and unusual admin tools for implants.',
      'Validate that the backdoor hash no longer executes on hosts.',
    ],
  },
  fileless: {
    title: 'Fileless malware',
    evidence: 'Technique/family name',
    examples: 'PowerShell Empire, living-off-the-land',
    steps: [
      'Document the technique/family (e.g. PowerShell Empire, LotL).',
      'Capture memory and review PowerShell/WMI script block logs.',
      'Disable risky script hosts where policy allows.',
      'Clear malicious WMI subscriptions and scheduled tasks.',
      'Reboot into a known-good state after containment.',
    ],
  },
  cryptominer: {
    title: 'Cryptominer malware',
    evidence: 'Family/name + hash',
    examples: 'XMRig, Lemon Duck',
    steps: [
      'Record miner family/name and SHA-256 (e.g. XMRig).',
      'Kill mining processes and remove persistence jobs/services.',
      'Block mining pools and the sample hash on egress firewall.',
      'Investigate the initial access path that installed the miner.',
      'Monitor CPU/GPU baselines after cleanup.',
    ],
  },
  malware: {
    title: 'Malware (generic)',
    evidence: 'Detection/family name + hash when available',
    examples: 'Uncategorized malware',
    steps: MALWARE_BASE,
  },
  phishing: {
    title: 'Phishing',
    evidence: 'Sender, lure URL, and credential-harvest indicators',
    examples: 'Fake login portals, invoice lures',
    steps: [
      'Do not click suspicious links or open unexpected attachments.',
      'Reset passwords for any account mentioned in the lure and enable MFA.',
      'Quarantine the email and report it to the security / SOC team.',
      'Block the sender domain and related malicious URLs on the gateway.',
      'Run awareness reminder for users about urgent payment/login scams.',
    ],
  },
  ddos: {
    title: 'DDoS',
    evidence: 'Flood protocol, source ranges, and capacity metrics',
    examples: 'SYN/UDP/HTTP floods',
    steps: [
      'Enable rate-limiting and geo/IP blocking on the edge firewall/WAF.',
      'Scale or fail-over to scrubbing / CDN protection if available.',
      'Null-route or blackhole confirmed attack source ranges.',
      'Monitor bandwidth and service health until traffic returns to baseline.',
      'Review open internet-facing services and close unused ports.',
    ],
  },
  'brute-force': {
    title: 'Brute Force',
    evidence: 'Target account, source IPs, failed-auth counts',
    examples: 'Password spray, credential stuffing',
    steps: [
      'Temporarily lock the targeted accounts and force password resets.',
      'Enable MFA and account lockout after repeated failed logins.',
      'Block attacking source IPs on VPN/SSH/RDP gateways.',
      'Review auth logs for successful compromises during the spray window.',
      'Move admin services off default ports and restrict by allow-list.',
    ],
  },
  social: {
    title: 'Social Engineering',
    evidence: 'Impersonated identity and requested action',
    examples: 'CEO fraud, help-desk scam',
    steps: [
      'Verify unusual payment/MFA requests through a known secondary channel.',
      'Revoke any access or tokens shared during the impersonation attempt.',
      'Alert finance/help-desk teams about CEO fraud and gift-card scams.',
      'Document the conversation and report to security awareness leads.',
      'Reinforce “stop–verify–report” procedure for urgent executive requests.',
    ],
  },
  benign: {
    title: 'Benign',
    evidence: 'No malicious family/hash indicators',
    examples: 'Normal traffic / operations',
    steps: [
      'No active incident response required for this sample.',
      'Continue routine monitoring of network and endpoint telemetry.',
      'Keep baselines updated so true anomalies stand out clearly.',
      'Retain the event for audit/history if needed.',
      'Re-classify if related indicators later appear suspicious.',
    ],
  },
}

/** Ordered virus catalog for the Analyzer reference table. */
export const VIRUS_EVIDENCE_CATALOG = [
  'virus',
  'worm',
  'trojan',
  'ransomware',
  'spyware',
  'adware',
  'rootkit',
  'botnet',
  'keylogger',
  'rat',
  'downloader',
  'backdoor',
  'fileless',
  'cryptominer',
].map((id) => ({
  id,
  title: REMEDIATION_BY_TYPE[id].title,
  evidence: REMEDIATION_BY_TYPE[id].evidence,
  examples: REMEDIATION_BY_TYPE[id].examples,
}))

export function remediationFor(threatType) {
  if (!threatType) return null
  return (
    REMEDIATION_BY_TYPE[threatType] ||
    REMEDIATION_BY_TYPE[String(threatType).toLowerCase()] ||
    null
  )
}
