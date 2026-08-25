"""Curated Enterprise ATT&CK techniques used for evidence-based inference.

The catalogue is deliberately bounded (not the full ~200+ technique Enterprise
matrix): every entry needs real, checkable MITRE metadata and a genuine
CVE-relevant signal set, and it doubles as the closed vocabulary the LLM
analyser (services/llm_service.py) is allowed to choose from - a technique_id
outside this list is filtered out before it ever reaches the database (see
services/intelligence_service.py), both because the schema enforces a foreign
key against this table and to keep the LLM from inventing a mapping. It must
never present a keyword match, or an LLM's inference, as an official MITRE
ATT&CK mapping - see mapping_type="inferred" throughout the codebase.
"""

ATTACK_CATALOG = (
    {
        "technique_id": "T1190",
        "name": "Exploit Public-Facing Application",
        "description": "Adversaries may exploit a weakness in an Internet-facing application to gain access.",
        "tactics": ["Initial Access"],
        "external_url": "https://attack.mitre.org/techniques/T1190/",
        "signals": ("public-facing", "web application", "web server", "internet-facing", "http server"),
    },
    {
        "technique_id": "T1203",
        "name": "Exploitation for Client Execution",
        "description": "Adversaries may exploit a software vulnerability in a client application to execute code.",
        "tactics": ["Execution"],
        "external_url": "https://attack.mitre.org/techniques/T1203/",
        "signals": ("browser", "client application", "malicious document", "office document", "pdf viewer"),
    },
    {
        "technique_id": "T1210",
        "name": "Exploitation of Remote Services",
        "description": "Adversaries may exploit vulnerable remote services to gain unauthorized access.",
        "tactics": ["Lateral Movement"],
        "external_url": "https://attack.mitre.org/techniques/T1210/",
        "signals": ("remote service", "remote services", "smb", "remote desktop", "rdp service", "ssh service"),
    },
    {
        "technique_id": "T1068",
        "name": "Exploitation for Privilege Escalation",
        "description": "Adversaries may exploit a vulnerability to elevate privileges on a system.",
        "tactics": ["Privilege Escalation"],
        "external_url": "https://attack.mitre.org/techniques/T1068/",
        "signals": ("privilege escalation", "elevate privileges", "elevation of privilege"),
    },
    {
        "technique_id": "T1059",
        "name": "Command and Scripting Interpreter",
        "description": "Adversaries may abuse command or scripting interpreters to execute commands.",
        "tactics": ["Execution"],
        "external_url": "https://attack.mitre.org/techniques/T1059/",
        "signals": ("command injection", "shell command", "arbitrary command", "command execution"),
    },
    {
        "technique_id": "T1055",
        "name": "Process Injection",
        "description": "Adversaries may inject code into another process to evade defenses or elevate privileges.",
        "tactics": ["Defense Evasion", "Privilege Escalation"],
        "external_url": "https://attack.mitre.org/techniques/T1055/",
        "signals": ("process injection", "dll injection", "code injection into", "memory injection"),
    },
    {
        "technique_id": "T1071",
        "name": "Application Layer Protocol",
        "description": "Adversaries may communicate using an application-layer protocol to blend in with normal traffic.",
        "tactics": ["Command and Control"],
        "external_url": "https://attack.mitre.org/techniques/T1071/",
        "signals": ("command and control", "c2 channel", "beaconing", "covert channel"),
    },
    {
        "technique_id": "T1005",
        "name": "Data from Local System",
        "description": "Adversaries may search a local system for sensitive files and information.",
        "tactics": ["Collection"],
        "external_url": "https://attack.mitre.org/techniques/T1005/",
        "signals": ("arbitrary file read", "local file disclosure", "read arbitrary files", "sensitive file"),
    },
    {
        "technique_id": "T1499",
        "name": "Endpoint Denial of Service",
        "description": "Adversaries may exhaust resources or crash a service to deny its availability.",
        "tactics": ["Impact"],
        "external_url": "https://attack.mitre.org/techniques/T1499/",
        "signals": ("denial of service", "crash the service", "resource exhaustion", "cause a crash"),
    },
    {
        "technique_id": "T1552",
        "name": "Unsecured Credentials",
        "description": "Adversaries may search for insecurely stored credentials such as keys, tokens, or passwords.",
        "tactics": ["Credential Access"],
        "external_url": "https://attack.mitre.org/techniques/T1552/",
        "signals": ("hardcoded credential", "hardcoded password", "plaintext password", "exposed api key", "leaked credential"),
    },
    {
        "technique_id": "T1078",
        "name": "Valid Accounts",
        "description": "Adversaries may use compromised or default credentials to gain unauthorized access.",
        "tactics": ["Initial Access", "Persistence"],
        "external_url": "https://attack.mitre.org/techniques/T1078/",
        "signals": ("default credential", "default password", "authentication bypass", "bypass authentication"),
    },
    {
        "technique_id": "T1133",
        "name": "External Remote Services",
        "description": "Adversaries may leverage external-facing remote access services to gain initial access or persist.",
        "tactics": ["Initial Access", "Persistence"],
        "external_url": "https://attack.mitre.org/techniques/T1133/",
        "signals": ("vpn", "remote access service", "external remote", "exposed management interface"),
    },
    {
        "technique_id": "T1046",
        "name": "Network Service Discovery",
        "description": "Adversaries may attempt to discover services running on remote hosts.",
        "tactics": ["Discovery"],
        "external_url": "https://attack.mitre.org/techniques/T1046/",
        "signals": ("network scanning", "service enumeration", "port scan"),
    },
    {
        "technique_id": "T1082",
        "name": "System Information Discovery",
        "description": "Adversaries may gather detailed system and configuration information.",
        "tactics": ["Discovery"],
        "external_url": "https://attack.mitre.org/techniques/T1082/",
        "signals": ("information disclosure", "system information", "configuration disclosure", "version disclosure"),
    },
    {
        "technique_id": "T1567",
        "name": "Exfiltration Over Web Service",
        "description": "Adversaries may exfiltrate data using an existing, legitimate web service.",
        "tactics": ["Exfiltration"],
        "external_url": "https://attack.mitre.org/techniques/T1567/",
        "signals": ("data exfiltration", "exfiltrate data", "unauthorized data transfer"),
    },
    {
        "technique_id": "T1489",
        "name": "Service Stop",
        "description": "Adversaries may stop or disable services to render systems unavailable.",
        "tactics": ["Impact"],
        "external_url": "https://attack.mitre.org/techniques/T1489/",
        "signals": ("service stop", "disable the service", "shut down the service"),
    },
    {
        "technique_id": "T1195",
        "name": "Supply Chain Compromise",
        "description": "Adversaries may compromise a product or its dependencies before it reaches the end consumer.",
        "tactics": ["Initial Access"],
        "external_url": "https://attack.mitre.org/techniques/T1195/",
        "signals": ("supply chain", "malicious package", "compromised dependency", "malicious update"),
    },
    {
        "technique_id": "T1211",
        "name": "Exploitation for Defense Evasion",
        "description": "Adversaries may exploit a vulnerability to bypass a security mechanism or control.",
        "tactics": ["Defense Evasion"],
        "external_url": "https://attack.mitre.org/techniques/T1211/",
        "signals": ("bypass security", "evade detection", "disable security control", "bypass the sandbox"),
    },
    {
        "technique_id": "T1212",
        "name": "Exploitation for Credential Access",
        "description": "Adversaries may exploit a vulnerability to obtain credentials from a system or service.",
        "tactics": ["Credential Access"],
        "external_url": "https://attack.mitre.org/techniques/T1212/",
        "signals": ("credential theft", "steal credentials", "dump credentials", "extract password hashes"),
    },
    {
        "technique_id": "T1611",
        "name": "Escape to Host",
        "description": "Adversaries may break out of a container to gain access to the underlying host.",
        "tactics": ["Privilege Escalation", "Defense Evasion"],
        "external_url": "https://attack.mitre.org/techniques/T1611/",
        "signals": ("container escape", "escape the container", "breakout from the sandboxed"),
    },
)


MITIGATION_BY_TECHNIQUE = {
    "T1190": "Reduce Internet exposure of affected applications and place them behind appropriate access controls.",
    "T1203": "Restrict untrusted files and keep client software patched through managed update processes.",
    "T1210": "Restrict remote-service access to trusted networks and require strong authentication.",
    "T1068": "Apply least privilege and promptly patch local privilege-escalation vulnerabilities.",
    "T1059": "Constrain command execution with least-privilege service accounts and application allowlisting where appropriate.",
    "T1055": "Enable process-injection detection and application control to block untrusted code from loading into other processes.",
    "T1071": "Monitor and restrict outbound application-layer traffic for anomalous or unauthorized command-and-control patterns.",
    "T1005": "Apply strict file-system access controls and validate any user-supplied path before reading local files.",
    "T1499": "Apply rate limiting and resource quotas to reduce the impact of a resource-exhaustion attack.",
    "T1552": "Rotate any potentially exposed credentials and move secrets out of source code or config files into a managed secrets store.",
    "T1078": "Disable default credentials, enforce strong authentication, and monitor for anomalous account use.",
    "T1133": "Restrict external-facing remote access services to trusted networks and require multi-factor authentication.",
    "T1046": "Segment networks and restrict unnecessary service exposure to reduce discoverable attack surface.",
    "T1082": "Minimise verbose error messages and configuration disclosure that could aid reconnaissance.",
    "T1567": "Monitor and restrict outbound data transfers to unauthorized destinations.",
    "T1489": "Ensure service resilience (redundancy, restart policies) and monitor for unauthorized service-control actions.",
    "T1195": "Verify the integrity and provenance of third-party dependencies and updates before deployment.",
    "T1211": "Keep security controls patched and monitor for attempts to disable or bypass them.",
    "T1212": "Protect credential stores and monitor for unauthorized credential-access attempts.",
    "T1611": "Keep container runtimes patched and enforce workload isolation (seccomp, namespaces, no unnecessary privileges).",
}
