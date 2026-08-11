/** Precautions / rectification steps shown after AI classification. */

export const REMEDIATION_BY_TYPE = {
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
  malware: {
    title: 'Malware — Precautions & Rectification',
    steps: [
      'Isolate the affected endpoint from the network immediately.',
      'Kill suspicious processes and remove dropped executables/.dll payloads.',
      'Run a full EDR/antivirus scan and restore from a clean backup if needed.',
      'Block C2 / reverse-shell destinations on firewall and proxy.',
      'Patch the exploited software and rotate local/admin credentials.',
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
