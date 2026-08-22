"""Curated Enterprise ATT&CK techniques used for evidence-based inference.

The catalogue is deliberately small: the application only infers a technique
when CVE text contains a concrete behavioural signal.  It must not present a
keyword match as an official MITRE ATT&CK mapping.
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
)


MITIGATION_BY_TECHNIQUE = {
    "T1190": "Reduce Internet exposure of affected applications and place them behind appropriate access controls.",
    "T1203": "Restrict untrusted files and keep client software patched through managed update processes.",
    "T1210": "Restrict remote-service access to trusted networks and require strong authentication.",
    "T1068": "Apply least privilege and promptly patch local privilege-escalation vulnerabilities.",
    "T1059": "Constrain command execution with least-privilege service accounts and application allowlisting where appropriate.",
}
