"""Large generated SOC-style corpus for the local threat classifier.

This is not a download of one billion internet events. No public dataset of
1,000,000,000 labeled samples exists for this project's threat taxonomy, and
that volume would not fit this offline laptop dashboard.

The generator builds many unique event texts per class so the model can be
trained and scored honestly on a held-out split.
"""

from __future__ import annotations

import hashlib
import random

from .threat_types import THREAT_TYPES

HOSTS = (
    "DESKTOP-988C9GL",
    "DESKTOP-SBJAOKO",
    "LAPTOP-HR04",
    "WS-FINANCE-12",
    "LAB-PC-07",
    "MAIL-GW-1",
)
IPS = (
    "10.87.54.124",
    "10.87.54.218",
    "192.168.1.24",
    "172.20.10.5",
    "10.0.0.8",
    "8.8.8.8",
)
USERS = ("srinu", "akash", "demo", "helpdesk", "finance", "student")
FILES = (
    "invoice.pdf.exe",
    "salary-review.doc.exe",
    "setup.exe",
    "readme_for_decrypt.txt",
    "photo.jpg.scr",
    "update.msi",
    "report.xlsm",
)


def _hash(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def _fill(rng: random.Random, template: str) -> str:
    return template.format(
        host=rng.choice(HOSTS),
        ip=rng.choice(IPS),
        user=rng.choice(USERS),
        file=rng.choice(FILES),
        sha=_hash(f"{rng.random()}"),
        n=rng.randint(3, 48),
        port=rng.choice((22, 23, 445, 3389, 4444, 5555, 8080)),
    )


TEMPLATES: dict[str, tuple[str, ...]] = {
    "phishing": (
        "Urgent action required: verify your account and click the login portal {ip}",
        "Dear customer, unusual sign-in activity. Your account has been limited. Click here to verify your account",
        "Password expired. Reset credentials via the bank account login page now",
        "Action Required: Mandatory 2026 Employee Health Benefits Election. Hello Team, re-enroll to avoid a lapse in medical coverage. Deadline Friday 5:00 PM EST",
        "DHL parcel held. Kindly update billing payment at http://paypa1-login.com/login",
        "Shared a document with you. Failure to verify within {n} hours will suspend the bank account",
        "Credential harvest attempt via fake invoice scam and shortened bit.ly link",
        "Laptop mail from security@paypa1-login.com. Subject: Urgent action required: verify your account",
        "Hello team, confirm your identity on the login portal or coverage will lapse",
        "Mailbox lure: fake login portal harvests password after kindly verify click",
    ),
    "virus": (
        "File infector virus Win32/Expiro detected sha256:{sha}",
        "Polymorphic virus family Generic.Virus with SHA-256 hash in quarantine report",
        "USB stick on second laptop {host} ({ip}) has virus in {file} on removable drive",
        "AV quarantine: virus keyword file infector attached to host program {file}",
        "Win32/Expiro file infector virus spreading through shared folder on {host}",
        "Generic.Virus sample sha256:{sha} detected by endpoint scanner",
        "EDR alert: Expiro virus infected {file} and dropped a matching SHA-256 hash",
        "Second laptop {host} reported live virus. File infector Win32/Expiro in {file}",
    ),
    "worm": (
        "Worm WannaCry self-replicating across SMB shares on the LAN",
        "Conficker worm lateral spread worm activity observed on {host}",
        "Self-replicating worm scanning port 445 from {ip} without user action",
        "WannaCry worm family spreading laterally through exposed SMB",
        "Remote agent on {host} ({ip}) found worm artifact {file}",
        "IDS: Conficker worm copied itself to neighbor {ip} via SMB",
        "Laptop malware sweep: WannaCry worm self-replicating without a user click",
    ),
    "trojan": (
        "Banking trojan Emotet downloaded via malicious Office macro",
        "Trojan TrickBot credential theft module installed on {host}",
        "Trojanized installer {file} opened attacker access after user ran it",
        "Emotet trojan disguised as {file} stealing Outlook credentials",
        "QakBot banking trojan follow-on from Emotet loader on {ip}",
        "User launched {file}; Emotet banking trojan then called C2",
        "TrickBot trojan module harvested credentials on {host}",
    ),
    "ransomware": (
        "Your files have been encrypted. Pay bitcoin wallet for decryption key",
        "LockBit ransomware locked files as .locked and demanded crypto payment",
        "README_FOR_DECRYPT.txt how to decrypt. Shadow copies deleted on {host}",
        "Conti ransomware encrypted documents on {ip}. Pay in crypto",
        "Your files are encrypted. Do not turn off the PC. Bitcoin wallet demanded",
        "LockBit note on desktop: files locked, pay crypto for decryption key",
        "Host {host} hit by Conti ransomware after vssadmin delete shadows",
    ),
    "spyware": (
        "Spyware Pegasus exfiltrating contacts messages location from mobile endpoint",
        "Screen capture spyware stalkerware telemetry to unknown C2",
        "DarkHotel spyware monitoring {user} browser sessions on {host}",
        "Spyware family Pegasus privacy exfiltration of messages and location",
        "Stalkerware WebWatcher uploading screenshots from {ip}",
        "Pegasus spyware on the phone exfiltrating contacts and location to C2",
        "DarkHotel spyware captured {user} session cookies from {host}",
    ),
    "adware": (
        "Adware Bundlore browser hijacker injecting popup ads",
        "Unwanted adware detection family Adware.Generic changing homepage",
        "SearchProtect adware bundled with freeware on {host}",
        "Popup ads injector adware tracking installs for {user}",
        "Browser hijacking adware reset search engine to unknown site",
        "Bundlore adware hijacked Chrome homepage and injected popup ads",
        "Adware.Generic PUP changed search settings for {user}",
    ),
    "rootkit": (
        "Kernel-mode rootkit TDSS hiding malicious driver",
        "ZeroAccess rootkit family concealing processes on {host}",
        "Hidden driver rootkit Alureon surviving ordinary antivirus cleanup",
        "Rootkit hiding files and processes from Task Manager on {ip}",
        "TDSS / ZeroAccess kernel-mode rootkit detected in boot record",
        "Bootkit scan: TDSS rootkit hiding a malicious kernel driver",
        "ZeroAccess rootkit still concealing processes after reboot of {host}",
    ),
    "botnet": (
        "Mirai IoT botnet recruiting cameras into command-and-control botnet",
        "Botnet bot herder pushing new attack modules to {ip}",
        "Emotet botnet swarm waiting for C2 commands from bot herder",
        "IoT botnet Mirai brute-forcing cameras then joining DDoS swarm",
        "Command-and-control botnet callback from {host}",
        "Camera at {ip} joined the Mirai botnet after a default-password login",
        "Bot herder issued a new flood module to the Emotet botnet swarm",
    ),
    "keylogger": (
        "Keylogger Agent Tesla keystroke logging sha256:{sha}",
        "Formbook keylogger captured credentials keylog buffer flushed to C2",
        "HawkEye keylogger recording typed passwords for {user} on {host}",
        "Keystroke logging malware Agent Tesla plus clipboard theft",
        "Keylogger family Formbook shipping captured credentials to {ip}",
        "Agent Tesla keylogger flushed keystroke logs and clipboard to C2",
        "Formbook keylogger on {host} captured {user} banking passwords",
    ),
    "rat": (
        "Remote access trojan AsyncRAT opened unauthorized remote control session",
        "njRAT remote access trojan persistence on workstation {host}",
        "Quasar RAT viewing the screen and transferring files from {ip}",
        "Unauthorized remote control RAT listener on port {port}",
        "Remote Access Trojan AsyncRAT / njRAT / Quasar interactive session",
        "AsyncRAT remote access trojan took the desktop session on {host}",
        "Quasar RAT listener on port {port} moving files off {ip}",
    ),
    "downloader": (
        "Downloader Guloader stage-2 payload download sha256:{sha}",
        "SmokeLoader dropper downloaded secondary malware executable {file}",
        "Certutil -urlcache downloader fetched stage-2 payload from {ip}",
        "Bitsadmin /transfer living-off-the-land downloader on {host}",
        "Dropper unpacked secondary malware after phishing document {file}",
        "Guloader downloader pulled a stage-2 payload with sha256:{sha}",
        "SmokeLoader dropper on {host} fetched another executable from {ip}",
    ),
    "backdoor": (
        "Backdoor Cobalt Strike beacon sha256:{sha}",
        "China Chopper webshell backdoor planted on IIS server {host}",
        "Persistent backdoor beacon calling C2 every {n} seconds from {ip}",
        "Cobalt Strike backdoor and webshell on the web root",
        "Covert long-term access backdoor remaining after cleanup",
        "Cobalt Strike beacon backdoor hashed sha256:{sha} on {host}",
        "China Chopper webshell backdoor accepted commands without login",
    ),
    "fileless": (
        "Fileless PowerShell Empire living-off-the-land in-memory payload",
        "WMI persistence fileless technique with in-memory shellcode on {host}",
        "PowerShell -EncodedCommand fileless living-off-the-land on {ip}",
        "Fileless malware runs in memory via WMI and PowerShell Empire",
        "LotL fileless in-memory payload with no dropped EXE",
        "PowerShell Empire fileless in-memory payload with WMI persistence",
        "Encoded PowerShell living-off-the-land fileless implant on {host}",
    ),
    "cryptominer": (
        "Cryptominer XMRig unauthorized mining sha256:{sha}",
        "Lemon Duck coinminer Monero mining on compromised host {host}",
        "Unauthorized mining pool stratum+tcp from {ip} XMRig process",
        "Cryptominer hijacking CPU/GPU for Monero mining on {host}",
        "NiceHash / XMRig miner binary filename in {file}",
        "XMRig cryptominer connected to a Monero pool from {ip}",
        "Lemon Duck coinminer caused high CPU on {host} during unauthorized mining",
    ),
    "malware": (
        "Executable download of suspicious malware with registry persistence on {host}",
        "PowerShell -enc base64 payload launched reverse shell to C2 beacon",
        "Generic malware double extension dropper {file} with DLL injection",
        "Suspicious process malware and C2 beacon from {ip}",
        "Lure filename on dangerous attachment {file} classified as malware",
        "Malware dropper {file} used DLL injection and registry persistence",
        "Reverse shell malware with PowerShell -enc base64 payload to C2 beacon",
    ),
    "ddos": (
        "DDoS SYN flood exhausting bandwidth capacity on edge firewall",
        "HTTP flood denial of service against public web portal at {ip}",
        "UDP flood distributed denial of service from botnet sources",
        "Traffic flood exhausting capacity and denying availability",
        "SYN/UDP/HTTP floods DDoS against {host}",
        "Edge firewall: DDoS SYN flood exhausted bandwidth capacity",
        "Portal at {ip} hit by HTTP flood denial of service",
    ),
    "brute-force": (
        "Repeated login attempts and password spray against VPN gateway {ip}",
        "SSH auth failures indicate brute force password guessing on port {port}",
        "RDP login failures credential stuffing against {host}",
        "Brute force password spray of account {user} from {ip}",
        "Failed authentication burst then successful brute-force login",
        "VPN gateway {ip} under password spray brute force against {user}",
        "RDP brute force: repeated login attempts and credential stuffing on {host}",
    ),
    "social": (
        "Social engineering call impersonating help desk scam for MFA codes",
        "CEO fraud email asking staff to wire transfer urgently for {user}",
        "Help-desk scam impersonation requesting gift card purchase",
        "Social engineering pretends to be IT and manipulates employee for MFA",
        "Urgent wire transfer social engineering impersonating the director",
        "Help desk scam social engineering asked {user} for an MFA code",
        "CEO fraud social engineering: wire transfer urgently, do not tell finance",
    ),
    "benign": (
        "Normal outbound HTTPS traffic to corporate CDN from {host}",
        "Scheduled backup completed successfully on file server {ip}",
        "DNS lookup for known software update domain by {user}",
        "Employee joined a video conference meeting on {host}",
        "Weekly project notes are in the shared drive. No password reset is required",
        "Windows Update installed successfully. Reboot is not required now",
        "Printer queue cleared. User {user} printed 3 pages",
        "NTP time sync succeeded. Host {host} clock is correct",
        "Intranet wiki saved. {user} edited the meeting agenda on {host}",
        "Software inventory scan finished with no threats on {ip}",
    ),
}

def build_corpus(per_class: int = 4000, seed: int = 42) -> tuple[list[str], list[str]]:
    texts, labels, _split = build_template_split(per_class=per_class, seed=seed, holdout=0)
    return texts, labels


def build_template_split(
    *,
    per_class: int = 4000,
    seed: int = 42,
    holdout: int = 2,
) -> tuple[list[str], list[str], list[str]]:
    """If holdout>0, last N templates per class are used only for evaluation."""
    rng = random.Random(seed)
    texts: list[str] = []
    labels: list[str] = []
    splits: list[str] = []
    for threat_type in THREAT_TYPES:
        templates = TEMPLATES[threat_type]
        cut = max(1, len(templates) - holdout) if holdout else len(templates)
        train_tpl = templates[:cut] or templates
        test_tpl = templates[cut:] or templates[-1:]
        for index in range(per_class):
            template = train_tpl[index % len(train_tpl)]
            text = _fill(rng, template)
            if index >= len(train_tpl):
                text = f"{text} event-id {index} sensor {rng.choice(('ids', 'edr', 'mail', 'usb'))}"
            texts.append(text)
            labels.append(threat_type)
            splits.append("train")
        if holdout:
            test_n = max(150, per_class // 8)
            for index in range(test_n):
                template = test_tpl[index % len(test_tpl)]
                text = _fill(rng, template)
                text = f"{text} case {index} src {rng.choice(('laptop', 'agent', 'usb'))}"
                texts.append(text)
                labels.append(threat_type)
                splits.append("test")
    return texts, labels, splits
