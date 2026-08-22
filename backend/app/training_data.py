"""Large generated SOC-style corpus for the local threat classifier.

This is not a download of one billion internet events. No public dataset of
1,000,000,000 labeled samples exists for this project's threat taxonomy, and
that volume would not fit this offline laptop dashboard.

The generator builds many unique event texts per class so the model can be
trained and scored honestly on a held-out split. Last two templates per class
are held out so accuracy is measured on unseen wordings, not copies of train text.
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
    "PC-LIBRARY-03",
    "NURSE-STATION-2",
    "VM-STUDENT-09",
    "WS-ACCOUNTS-04",
    "LAPTOP-FACULTY-2",
    "PC-RECEPTION-01",
    "VM-SOC-LAB-11",
    "HOSTEL-PC-18",
    "WS-EXAM-CELL",
    "LAPTOP-HOD-CSE",
    "PC-LAB-NET-14",
    "VM-PROJECT-03",
    "KIOSK-FRONT-2",
    "SRV-AD-01",
)
IPS = (
    "10.87.54.124",
    "10.87.54.218",
    "192.168.1.24",
    "172.20.10.5",
    "10.0.0.8",
    "8.8.8.8",
    "192.168.43.12",
    "10.10.10.44",
    "10.87.54.31",
    "172.16.8.90",
    "203.0.113.77",
    "198.51.100.22",
    "10.87.54.9",
    "10.87.54.200",
    "192.168.0.55",
    "172.16.4.18",
)
USERS = (
    "srinu",
    "akash",
    "demo",
    "helpdesk",
    "finance",
    "student",
    "admin",
    "hr",
    "librarian",
    "faculty",
    "nurse",
    "registrar",
    "warden",
    "principal",
    "labtech",
    "cashier",
)
FILES = (
    "invoice.pdf.exe",
    "salary-review.doc.exe",
    "setup.exe",
    "readme_for_decrypt.txt",
    "photo.jpg.scr",
    "update.msi",
    "report.xlsm",
    "virus.exe",
    "ticket.pdf.bat",
    "resume.docx.exe",
    "payroll-2026.xls.exe",
    "benefits-form.pdf.js",
    "camera_backup.zip.exe",
    "decrypt_instructions.html",
    "kv_receipt.pdf.scr",
    "offer-letter.docx.exe",
    "fee-receipt.pdf.js",
    "exam-results.xlsm",
    "usb_autorun.inf",
    "winlogon.dll.bak",
)
CHANNELS = (
    "Network IDS",
    "Endpoint",
    "Firewall",
    "DNS",
    "Email",
    "Auth",
    "USB",
    "Remote Agent",
    "Laptop Mail Guard",
    "Laptop File Guard",
    "Sysmon",
    "Proxy",
    "EDR",
    "SIEM",
    "Windows Event Log",
)
SENSORS = ("ids", "edr", "mail", "usb", "agent", "firewall", "dns", "sysmon", "proxy", "siem")


def _hash(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def _host(rng: random.Random) -> str:
    if rng.random() < 0.22:
        return f"LAB-PC-{rng.randint(10, 99):02d}"
    return rng.choice(HOSTS)


def _ip(rng: random.Random) -> str:
    if rng.random() < 0.28:
        return f"10.87.54.{rng.randint(2, 250)}"
    return rng.choice(IPS)


def _fill(rng: random.Random, template: str) -> str:
    text = template.format(
        host=_host(rng),
        ip=_ip(rng),
        user=rng.choice(USERS),
        file=rng.choice(FILES),
        sha=_hash(f"{rng.random()}"),
        n=rng.randint(3, 48),
        port=rng.choice((22, 23, 445, 3389, 4444, 5555, 8080, 993, 445, 5985)),
        channel=rng.choice(CHANNELS),
        sensor=rng.choice(SENSORS),
    )
    extras = [
        f"source={rng.choice(CHANNELS)}",
        f"user={rng.choice(USERS)}",
        f"confidence={rng.choice(('high', 'medium', 'critical'))}",
        f"proto={rng.choice(('TCP', 'UDP', 'SMTP', 'HTTPS', 'SMB', 'FILE', 'RDP'))}",
        f"sensor={rng.choice(SENSORS)}",
        f"device={_host(rng)}",
        f"ts=2026-0{rng.randint(1, 8)}-{rng.randint(10, 28):02d}T{rng.randint(0, 23):02d}:{rng.randint(0, 59):02d}Z",
        f"evt={rng.randint(100000, 999999)}",
    ]
    rng.shuffle(extras)
    if rng.random() < 0.72:
        text = f"{text} [{' '.join(extras[:2])}]"
    return text


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
        "Spearphish: {user} received a fake OWA login portal for {host} from {ip}",
        "Mailbox lure: kindly verify payroll on http://paypa1-login.com/login or the bank account is locked",
        "HR spoof: {user} must click here to re-enroll benefits before coverage will lapse",
        "Delivery phishing: UPS parcel held, update billing payment or the shipment is cancelled",
        "Password reset lure emailed to {user}: unusual sign-in, confirm your identity now",
        "Fake invoice scam PDF {file} plus a shortened t.co link harvesting credentials",
        "Gmail lure: {user} clicked verify your account on a fake login portal from {ip}",
        "Kindly update billing payment for a held FedEx parcel or the bank account is limited",
        "Countdown phishing: you have {n} hours to confirm your identity or coverage will lapse",
        "Shared a document with you plus bit.ly credential harvest for {user} on {host}",
        "Mailbox Guard: unusual sign-in activity, password expired, reset via login page",
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
        "Virus scan on {host}: Win32/Expiro infected {file} and the SHA-256 hash matched",
        "Removable drive virus: file infector copied {file} onto {host} from USB",
        "Quarantine event: polymorphic virus Generic.Virus sha256:{sha} on {ip}",
        "Laptop File Guard: virus.exe file infector Win32/Expiro on {host}",
        "Second-PC USB virus: {file} reported as Generic.Virus with SHA-256 hash",
        "Shared folder virus outbreak: Expiro file infector spreading from {host}",
        "USB File Guard: virus keyword in {file} on {host}, SHA-256 {sha}",
        "Polymorphic virus Win32/Expiro attached itself to {file} then spread on {ip}",
        "Quarantine: Generic.Virus file infector found during a full scan of {host}",
        "Live agent virus report: {file} on second laptop matched Expiro SHA-256 hash",
        "EDR alert: Expiro virus infected {file} and dropped a matching SHA-256 hash",
        "Second laptop {host} reported live virus. File infector Win32/Expiro in {file}",
    ),
    "worm": (
        "Worm WannaCry self-replicating across SMB shares on the LAN",
        "Conficker worm lateral spread worm activity observed on {host}",
        "Self-replicating worm scanning port 445 from {ip} without user action",
        "WannaCry worm family spreading laterally through exposed SMB",
        "Remote agent on {host} ({ip}) found worm artifact {file}",
        "Worm Conficker copied itself to ADMIN$ on neighbor {ip} without a click",
        "SMB worm WannaCry self-replicating from {host} across the LAN",
        "Unattended worm activity: Conficker lateral spread scanning port 445",
        "Laptop malware sweep found a WannaCry worm artifact {file} on {host}",
        "IDS: self-replicating worm family spreading through exposed SMB from {ip}",
        "WannaCry worm scanned port 445 then copied {file} across SMB from {host}",
        "Conficker worm activity: self-replicating lateral spread with no user action",
        "Remote agent: worm artifact {file} matching WannaCry on {host} ({ip})",
        "LAN worm: Conficker copied itself to a neighbor share without a click",
        "IDS: Conficker worm copied itself to neighbor {ip} via SMB",
        "Laptop malware sweep: WannaCry worm self-replicating without a user click",
    ),
    "trojan": (
        "Banking trojan Emotet downloaded via malicious Office macro",
        "Trojan TrickBot credential theft module installed on {host}",
        "Trojanized installer {file} opened attacker access after user ran it",
        "Emotet trojan disguised as {file} stealing Outlook credentials",
        "QakBot banking trojan follow-on from Emotet loader on {ip}",
        "Office macro dropped the Emotet banking trojan then TrickBot on {host}",
        "User ran a trojanized installer {file}; Emotet then stole Outlook mail",
        "TrickBot trojan credential theft after a malicious Excel macro on {ip}",
        "Banking trojan QakBot follow-on from Emotet on workstation {host}",
        "Trojan family Emotet / TrickBot harvesting credentials from {user}",
        "Malicious Office macro installed a banking trojan Emotet on {host}",
        "TrickBot trojanized installer {file} stole Outlook credentials from {user}",
        "QakBot banking trojan follow-on after Emotet loader on {ip}",
        "User opened {file}; trojan TrickBot then harvested credentials",
        "User launched {file}; Emotet banking trojan then called C2",
        "TrickBot trojan module harvested credentials on {host}",
    ),
    "ransomware": (
        "Your files have been encrypted. Pay bitcoin wallet for decryption key",
        "LockBit ransomware locked files as .locked and demanded crypto payment",
        "README_FOR_DECRYPT.txt how to decrypt. Shadow copies deleted on {host}",
        "Conti ransomware encrypted documents on {ip}. Pay in crypto",
        "Your files are encrypted. Do not turn off the PC. Bitcoin wallet demanded",
        "LockBit ransomware dropped {file} then encrypted Documents on {host}",
        "vssadmin delete shadows then Conti ransomware locked files as .locked",
        "Ransom note README_FOR_DECRYPT.txt: pay bitcoin wallet for the decryption key",
        "Host {host}: files encrypted by LockBit, crypto payment demanded",
        "Desktop note: your files have been encrypted, do not turn off the PC",
        "LockBit ransomware encrypted Documents and demanded a bitcoin wallet on {host}",
        "Conti ransom note {file}: how to decrypt after shadow copies deleted",
        "Your files are encrypted. Pay crypto for the decryption key. Do not turn off the PC",
        "vssadmin delete shadows then LockBit locked files as .locked on {ip}",
        "LockBit note on desktop: files locked, pay crypto for decryption key",
        "Host {host} hit by Conti ransomware after vssadmin delete shadows",
    ),
    "spyware": (
        "Spyware Pegasus exfiltrating contacts messages location from mobile endpoint",
        "Screen capture spyware stalkerware telemetry to unknown C2",
        "DarkHotel spyware monitoring {user} browser sessions on {host}",
        "Spyware family Pegasus privacy exfiltration of messages and location",
        "Stalkerware WebWatcher uploading screenshots from {ip}",
        "Pegasus spyware privacy exfiltration of contacts and location from the phone",
        "Stalkerware on {host} captured screen telemetry and browser sessions for {user}",
        "DarkHotel spyware plus WebWatcher screenshots uploaded toward {ip}",
        "Mobile spyware Pegasus exfiltrating messages to an unknown C2",
        "Privacy spyware monitoring {user} location and contacts on {host}",
        "Stalkerware WebWatcher screen capture spyware uploading telemetry from {host}",
        "Pegasus spyware exfiltrating messages, contacts, and location to unknown C2",
        "DarkHotel spyware monitoring browser sessions and cookies for {user}",
        "Privacy exfiltration spyware on the phone: Pegasus family toward {ip}",
        "Pegasus spyware on the phone exfiltrating contacts and location to C2",
        "DarkHotel spyware captured {user} session cookies from {host}",
    ),
    "adware": (
        "Adware Bundlore browser hijacker injecting popup ads",
        "Unwanted adware detection family Adware.Generic changing homepage",
        "SearchProtect adware bundled with freeware on {host}",
        "Popup ads injector adware tracking installs for {user}",
        "Browser hijacking adware reset search engine to unknown site",
        "Bundlore adware injected popup ads after a freeware install on {host}",
        "Adware.Generic PUP hijacked the homepage and search engine for {user}",
        "SearchProtect adware bundled with {file} then changed Chrome search",
        "Unwanted adware tracking installs and injecting popup ads on {ip}",
        "Browser hijacker adware Bundlore reset the start page on {host}",
        "Adware.Generic changing homepage after freeware bundled with {file}",
        "SearchProtect adware injected popup ads and reset the search engine",
        "Unwanted PUP adware tracking installs for {user} on {host}",
        "Browser hijacking adware Bundlore on {ip} injecting popup ads",
        "Bundlore adware hijacked Chrome homepage and injected popup ads",
        "Adware.Generic PUP changed search settings for {user}",
    ),
    "rootkit": (
        "Kernel-mode rootkit TDSS hiding malicious driver",
        "ZeroAccess rootkit family concealing processes on {host}",
        "Hidden driver rootkit Alureon surviving ordinary antivirus cleanup",
        "Rootkit hiding files and processes from Task Manager on {ip}",
        "TDSS / ZeroAccess kernel-mode rootkit detected in boot record",
        "Bootkit TDSS kernel-mode rootkit hiding a malicious driver on {host}",
        "ZeroAccess rootkit concealing processes from Task Manager after reboot",
        "Alureon hidden driver rootkit survived ordinary antivirus cleanup on {ip}",
        "Kernel-mode rootkit family TDSS detected in the boot record of {host}",
        "Rootkit scan: ZeroAccess still hiding files and processes on {ip}",
        "Kernel-mode rootkit Alureon hiding a malicious driver from Task Manager",
        "TDSS bootkit in the boot record survived ordinary antivirus cleanup on {host}",
        "ZeroAccess rootkit family concealing processes after reboot of {ip}",
        "Hidden driver rootkit TDSS / ZeroAccess detected on {host}",
        "Bootkit scan: TDSS rootkit hiding a malicious kernel driver",
        "ZeroAccess rootkit still concealing processes after reboot of {host}",
    ),
    "botnet": (
        "Mirai IoT botnet recruiting cameras into command-and-control botnet",
        "Botnet bot herder pushing new attack modules to {ip}",
        "Emotet botnet swarm waiting for C2 commands from bot herder",
        "IoT botnet Mirai brute-forcing cameras then joining DDoS swarm",
        "Command-and-control botnet callback from {host}",
        "Mirai IoT botnet brute-forced a camera at {ip} then joined the DDoS swarm",
        "Bot herder pushed a new flood module to the Emotet botnet from C2",
        "Command-and-control botnet callback from {host} after camera recruitment",
        "IoT camera at {ip} recruited into the Mirai botnet with a default password",
        "Emotet botnet swarm waiting for bot herder commands toward {host}",
        "Mirai IoT botnet recruiting cameras into a command-and-control swarm from {ip}",
        "Bot herder pushing attack modules to the Emotet botnet callback on {host}",
        "Default-password camera joined the Mirai botnet then a DDoS swarm",
        "Command-and-control botnet C2 from {host} after IoT recruitment",
        "Camera at {ip} joined the Mirai botnet after a default-password login",
        "Bot herder issued a new flood module to the Emotet botnet swarm",
    ),
    "keylogger": (
        "Keylogger Agent Tesla keystroke logging sha256:{sha}",
        "Formbook keylogger captured credentials keylog buffer flushed to C2",
        "HawkEye keylogger recording typed passwords for {user} on {host}",
        "Keystroke logging malware Agent Tesla plus clipboard theft",
        "Keylogger family Formbook shipping captured credentials to {ip}",
        "Agent Tesla keylogger plus clipboard theft flushed keystrokes to C2",
        "Formbook keylogger captured {user} banking passwords on {host}",
        "HawkEye keystroke logging recorded typed passwords then called {ip}",
        "Keylogger family Agent Tesla sha256:{sha} shipping a keylog buffer",
        "Clipboard theft keylogger Formbook on {host} for account {user}",
        "HawkEye keylogger recording typed passwords and shipping a keylog buffer",
        "Agent Tesla keystroke logging plus clipboard theft sha256:{sha}",
        "Formbook keylogger flushed captured credentials for {user} to {ip}",
        "Keylogger family HawkEye on {host} captured banking passwords",
        "Agent Tesla keylogger flushed keystroke logs and clipboard to C2",
        "Formbook keylogger on {host} captured {user} banking passwords",
    ),
    "rat": (
        "Remote access trojan AsyncRAT opened unauthorized remote control session",
        "njRAT remote access trojan persistence on workstation {host}",
        "Quasar RAT viewing the screen and transferring files from {ip}",
        "Unauthorized remote control RAT listener on port {port}",
        "Remote Access Trojan AsyncRAT / njRAT / Quasar interactive session",
        "AsyncRAT remote access trojan opened an unauthorized desktop session on {host}",
        "njRAT persistence then Quasar RAT transferred files from {ip}",
        "Unauthorized remote control RAT listener on port {port} viewing the screen",
        "Remote access trojan family AsyncRAT interactive session on {host}",
        "Quasar RAT moving files off {ip} after an njRAT implant",
        "Unauthorized remote control: AsyncRAT viewing the screen on {host}",
        "njRAT remote access trojan persistence then file transfer from {ip}",
        "Quasar RAT listener on port {port} opened an interactive session",
        "Remote Access Trojan family AsyncRAT / njRAT on workstation {host}",
        "AsyncRAT remote access trojan took the desktop session on {host}",
        "Quasar RAT listener on port {port} moving files off {ip}",
    ),
    "downloader": (
        "Downloader Guloader stage-2 payload download sha256:{sha}",
        "SmokeLoader dropper downloaded secondary malware executable {file}",
        "Certutil -urlcache downloader fetched stage-2 payload from {ip}",
        "Bitsadmin /transfer living-off-the-land downloader on {host}",
        "Dropper unpacked secondary malware after phishing document {file}",
        "Guloader downloader used certutil -urlcache to fetch stage-2 from {ip}",
        "SmokeLoader dropper on {host} unpacked secondary malware executable {file}",
        "Bitsadmin /transfer living-off-the-land downloader pulled sha256:{sha}",
        "Stage-2 payload downloader Guloader after a phishing document {file}",
        "Dropper family SmokeLoader fetched another executable from {ip}",
        "Certutil -urlcache downloader Guloader fetched stage-2 payload {file}",
        "Bitsadmin living-off-the-land downloader on {host} pulled sha256:{sha}",
        "SmokeLoader dropper downloaded secondary malware after {file}",
        "Stage-2 payload dropper Guloader from {ip} unpacked on {host}",
        "Guloader downloader pulled a stage-2 payload with sha256:{sha}",
        "SmokeLoader dropper on {host} fetched another executable from {ip}",
    ),
    "backdoor": (
        "Backdoor Cobalt Strike beacon sha256:{sha}",
        "China Chopper webshell backdoor planted on IIS server {host}",
        "Persistent backdoor beacon calling C2 every {n} seconds from {ip}",
        "Cobalt Strike backdoor and webshell on the web root",
        "Covert long-term access backdoor remaining after cleanup",
        "Cobalt Strike beacon backdoor on {host} calling C2 every {n} seconds",
        "China Chopper webshell backdoor planted in the IIS web root",
        "Persistent covert long-term access backdoor remaining after cleanup on {ip}",
        "Backdoor family Cobalt Strike hashed sha256:{sha} plus a webshell",
        "IIS server {host} accepted China Chopper backdoor commands without login",
        "Persistent Cobalt Strike beacon backdoor calling C2 from {ip} every {n} seconds",
        "China Chopper webshell backdoor planted on the IIS web root of {host}",
        "Covert long-term access backdoor remaining after cleanup, sha256:{sha}",
        "Cobalt Strike backdoor plus webshell on {host} accepted commands without login",
        "Cobalt Strike beacon backdoor hashed sha256:{sha} on {host}",
        "China Chopper webshell backdoor accepted commands without login",
    ),
    "fileless": (
        "Fileless PowerShell Empire living-off-the-land in-memory payload",
        "WMI persistence fileless technique with in-memory shellcode on {host}",
        "PowerShell -EncodedCommand fileless living-off-the-land on {ip}",
        "Fileless malware runs in memory via WMI and PowerShell Empire",
        "LotL fileless in-memory payload with no dropped EXE",
        "PowerShell Empire fileless living-off-the-land in-memory payload on {host}",
        "WMI persistence plus encoded PowerShell fileless implant, no dropped EXE",
        "Fileless malware: PowerShell -EncodedCommand in-memory shellcode on {ip}",
        "LotL fileless technique using WMI and PowerShell Empire in memory",
        "In-memory fileless payload with living-off-the-land PowerShell on {host}",
        "Fileless WMI persistence with in-memory shellcode, no dropped EXE on {host}",
        "PowerShell -EncodedCommand living-off-the-land fileless implant on {ip}",
        "LotL fileless malware: PowerShell Empire in memory via WMI",
        "Fileless in-memory payload Empire with encoded PowerShell on {host}",
        "PowerShell Empire fileless in-memory payload with WMI persistence",
        "Encoded PowerShell living-off-the-land fileless implant on {host}",
    ),
    "cryptominer": (
        "Cryptominer XMRig unauthorized mining sha256:{sha}",
        "Lemon Duck coinminer Monero mining on compromised host {host}",
        "Unauthorized mining pool stratum+tcp from {ip} XMRig process",
        "Cryptominer hijacking CPU/GPU for Monero mining on {host}",
        "NiceHash / XMRig miner binary filename in {file}",
        "XMRig cryptominer unauthorized mining to a Monero pool from {ip}",
        "Lemon Duck coinminer caused high CPU on {host} during Monero mining",
        "stratum+tcp unauthorized mining pool from XMRig process sha256:{sha}",
        "Cryptominer NiceHash / XMRig binary {file} hijacking CPU/GPU",
        "Coinminer Lemon Duck unauthorized mining on compromised host {host}",
        "XMRig cryptominer hijacking CPU/GPU for Monero mining sha256:{sha}",
        "Unauthorized mining pool stratum+tcp NiceHash from {ip} on {host}",
        "Lemon Duck coinminer binary {file} caused high CPU during mining",
        "Cryptominer XMRig connected to a Monero pool, unauthorized mining",
        "XMRig cryptominer connected to a Monero pool from {ip}",
        "Lemon Duck coinminer caused high CPU on {host} during unauthorized mining",
    ),
    "malware": (
        "Executable download of suspicious malware with registry persistence on {host}",
        "PowerShell -enc base64 payload launched reverse shell to C2 beacon",
        "Generic malware double extension dropper {file} with DLL injection",
        "Suspicious process malware and C2 beacon from {ip}",
        "Lure filename on dangerous attachment {file} classified as malware",
        "Malware dropper {file} used DLL injection and registry persistence on {host}",
        "Reverse shell malware: PowerShell -enc base64 payload to a C2 beacon",
        "Suspicious malware executable download then C2 beacon from {ip}",
        "Double extension dropper {file} classified as generic malware",
        "Dangerous attachment {file} launched malware with registry persistence",
        "Generic malware double extension {file} plus DLL injection on {host}",
        "Suspicious process malware launched a reverse shell C2 beacon from {ip}",
        "PowerShell -enc base64 malware payload with registry persistence",
        "Lure attachment {file} classified as malware after executable download",
        "Malware dropper {file} used DLL injection and registry persistence",
        "Reverse shell malware with PowerShell -enc base64 payload to C2 beacon",
    ),
    "ddos": (
        "DDoS SYN flood exhausting bandwidth capacity on edge firewall",
        "HTTP flood denial of service against public web portal at {ip}",
        "UDP flood distributed denial of service from botnet sources",
        "Traffic flood exhausting capacity and denying availability",
        "SYN/UDP/HTTP floods DDoS against {host}",
        "Edge firewall DDoS: SYN flood exhausting bandwidth capacity toward {host}",
        "HTTP flood denial of service against the public web portal at {ip}",
        "UDP flood distributed denial of service from botnet sources hitting {host}",
        "Traffic flood exhausting capacity and denying availability on the edge firewall",
        "SYN/UDP/HTTP DDoS floods against {host} from botnet sources",
        "Distributed denial of service UDP flood exhausting capacity on {host}",
        "HTTP flood DDoS against the public web portal, denying availability",
        "Edge firewall SYN flood DDoS from botnet sources toward {ip}",
        "Traffic flood DDoS: SYN/UDP/HTTP exhausting bandwidth capacity",
        "Edge firewall: DDoS SYN flood exhausted bandwidth capacity",
        "Portal at {ip} hit by HTTP flood denial of service",
    ),
    "brute-force": (
        "Repeated login attempts and password spray against VPN gateway {ip}",
        "SSH auth failures indicate brute force password guessing on port {port}",
        "RDP login failures credential stuffing against {host}",
        "Brute force password spray of account {user} from {ip}",
        "Failed authentication burst then successful brute-force login",
        "VPN gateway {ip} password spray: repeated login attempts for {user}",
        "RDP credential stuffing and login failures against {host} from {ip}",
        "SSH brute force password guessing on port {port} then a successful login",
        "Failed authentication burst: brute force against account {user} on {host}",
        "Password spray brute force of the VPN gateway from {ip}",
        "SSH auth failures brute force password guessing then a successful login on {host}",
        "RDP login failures: credential stuffing and password spray against {user}",
        "Failed authentication burst brute-force of VPN gateway {ip} on port {port}",
        "Repeated login attempts indicate brute force against {host} from {ip}",
        "VPN gateway {ip} under password spray brute force against {user}",
        "RDP brute force: repeated login attempts and credential stuffing on {host}",
    ),
    "social": (
        "Social engineering call impersonating help desk scam for MFA codes",
        "CEO fraud email asking staff to wire transfer urgently for {user}",
        "Help-desk scam impersonation requesting gift card purchase",
        "Social engineering pretends to be IT and manipulates employee for MFA",
        "Urgent wire transfer social engineering impersonating the director",
        "Help desk scam social engineering asked {user} for an MFA code on a call",
        "CEO fraud: wire transfer urgently and do not tell finance, impersonating IT",
        "Social engineering gift-card purchase after a help-desk impersonation",
        "Director impersonation social engineering for an urgent wire transfer",
        "Pretends to be IT: social engineering call harvesting MFA from {user}",
        "Help-desk impersonation social engineering requesting a gift card purchase",
        "CEO fraud social engineering: urgent wire transfer, do not tell finance",
        "Social engineering call pretends to be IT and asks {user} for MFA codes",
        "Director impersonation: wire transfer urgently after a help desk scam",
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
        "SCCM patch Tuesday reboot completed successfully on {host}",
        "Defender definition update succeeded. No threats on {ip}",
        "{user} saved meeting notes {file} to Documents on {host}",
        "Normal outbound HTTPS to the corporate CDN. Weekly notes on the shared drive",
        "Scheduled backup and NTP time sync succeeded on file server {ip}",
        "Employee joined a video conference. Windows Update installed successfully",
        "Printer queue cleared. {user} printed pages. No password reset is required",
        "DNS lookup for a known software update domain from {host} by {user}",
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


def preview_corpus(
    *,
    train_per_class: int = 6,
    test_per_class: int = 2,
    seed: int = 42,
    holdout: int = 2,
) -> list[dict[str, str]]:
    """Small inspectable slice for CSV export and the dashboard. Not the full 400k rows."""
    rng = random.Random(seed)
    rows: list[dict[str, str]] = []
    for threat_type in THREAT_TYPES:
        templates = TEMPLATES[threat_type]
        cut = max(1, len(templates) - holdout) if holdout else len(templates)
        train_tpl = templates[:cut] or templates
        test_tpl = templates[cut:] or templates[-1:]
        for index in range(train_per_class):
            rows.append(
                {
                    "split": "train",
                    "threat_type": threat_type,
                    "event_text": _fill(rng, train_tpl[index % len(train_tpl)]),
                }
            )
        for index in range(test_per_class):
            rows.append(
                {
                    "split": "test",
                    "threat_type": threat_type,
                    "event_text": _fill(rng, test_tpl[index % len(test_tpl)]),
                }
            )
    return rows


def template_catalog() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for threat_type, templates in TEMPLATES.items():
        cut = max(1, len(templates) - 2)
        for index, template in enumerate(templates, start=1):
            rows.append(
                {
                    "threat_type": threat_type,
                    "template_index": str(index),
                    "role": "holdout" if index > cut else "train",
                    "template": template,
                }
            )
    return rows
