"""
=============================================================================
 Oktopus — Module Parser (Normalisation des Logs)
=============================================================================
 Fichier : server/parser.py
 Rôle    : Normaliser et parser les logs JSON reçus des agents.
           - Valider la structure JSON
           - Extraire les champs importants
           - Normaliser les niveaux de sévérité
           - Extraire les adresses IP des messages
           - Classifier automatiquement les catégories
 
 Auteur  : Oktopus Team
 Date    : 2026-02-27
 Python  : 3.8+
=============================================================================
"""

import json
import re
from datetime import datetime
from typing import Optional, List, Dict, Any, Tuple


class LogParser:
    """
    Parseur et normaliseur de logs pour le SOC.
    
    Transforme les messages JSON bruts des agents en structures
    normalisées prêtes pour la détection et le stockage.
    """

    # Niveaux de sévérité reconnus (du plus bas au plus haut)
    VALID_LEVELS = ["INFO", "WARNING", "HIGH", "CRITICAL"]

    # Mapping des niveaux alternatifs vers les niveaux standards
    LEVEL_MAPPING = {
        # Niveaux standards
        "info": "INFO",
        "information": "INFO",
        "debug": "INFO",
        "notice": "INFO",
        "low": "INFO",
        # Avertissements
        "warning": "WARNING",
        "warn": "WARNING",
        "medium": "WARNING",
        # Élevé
        "high": "HIGH",
        "error": "HIGH",
        "err": "HIGH",
        "danger": "HIGH",
        # Critique
        "critical": "CRITICAL",
        "crit": "CRITICAL",
        "fatal": "CRITICAL",
        "emergency": "CRITICAL",
        "alert": "CRITICAL",
        "severe": "CRITICAL",
    }

    # Catégories reconnues
    VALID_CATEGORIES = [
        "AUTH", "NETWORK", "SYSTEM", "APPLICATION",
        "SECURITY", "FIREWALL", "WEB", "DATABASE", "OTHER"
    ]

    # Patterns pour extraire des IPs depuis les messages
    IP_PATTERN = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
        r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    )

    # Windows Event IDs connus et leur mapping
    WINDOWS_EVENT_MAPPING = {
        4624: {"level": "INFO", "category": "AUTH", "desc": "Connexion réussie"},
        4625: {"level": "WARNING", "category": "AUTH", "desc": "Échec de connexion"},
        4634: {"level": "INFO", "category": "AUTH", "desc": "Déconnexion"},
        4648: {"level": "WARNING", "category": "AUTH", "desc": "Connexion avec identifiants explicites"},
        4672: {"level": "INFO", "category": "AUTH", "desc": "Privilèges spéciaux assignés"},
        4688: {"level": "INFO", "category": "SYSTEM", "desc": "Nouveau processus créé"},
        4689: {"level": "INFO", "category": "SYSTEM", "desc": "Processus terminé"},
        4697: {"level": "HIGH", "category": "SECURITY", "desc": "Service installé"},
        4698: {"level": "HIGH", "category": "SECURITY", "desc": "Tâche planifiée créée"},
        4719: {"level": "CRITICAL", "category": "SECURITY", "desc": "Politique d'audit modifiée"},
        4720: {"level": "WARNING", "category": "AUTH", "desc": "Compte utilisateur créé"},
        4722: {"level": "WARNING", "category": "AUTH", "desc": "Compte utilisateur activé"},
        4724: {"level": "WARNING", "category": "AUTH", "desc": "Réinitialisation mot de passe"},
        4732: {"level": "WARNING", "category": "AUTH", "desc": "Membre ajouté au groupe local"},
        4756: {"level": "HIGH", "category": "AUTH", "desc": "Membre ajouté au groupe universel"},
        7045: {"level": "HIGH", "category": "SECURITY", "desc": "Nouveau service installé"},
        1102: {"level": "CRITICAL", "category": "SECURITY", "desc": "Journal d'audit effacé"},
    }

    # Patterns pour classification automatique des catégories
    CATEGORY_PATTERNS = {
        "AUTH": [
            r"login|logon|logoff|logout|password|passwd|auth|pam|sudo|su\b|ssh",
            r"credential|account|user.*(?:add|del|creat|modif|lock|unlock)",
            r"kerberos|ntlm|ldap|saml"
        ],
        "NETWORK": [
            r"connect|disconnect|socket|port|tcp|udp|icmp|dns|dhcp",
            r"firewall|iptables|nftables|netfilter|packet|traffic",
            r"interface|ethernet|wifi|network|subnet|route"
        ],
        "WEB": [
            r"http|https|GET|POST|PUT|DELETE|HEAD|OPTIONS",
            r"nginx|apache|iis|tomcat|web.*server",
            r"request|response|status.*code|url|uri|endpoint"
        ],
        "SECURITY": [
            r"malware|virus|trojan|ransomware|exploit|vulnerability",
            r"intrusion|attack|threat|suspicious|anomal",
            r"scan|brute.*force|injection|xss|csrf"
        ],
        "SYSTEM": [
            r"kernel|systemd|init|boot|shutdown|reboot|cron",
            r"disk|memory|cpu|process|service|daemon",
            r"error|warning|critical|fatal|panic"
        ],
        "APPLICATION": [
            r"app|application|module|plugin|extension",
            r"database|mysql|postgres|sqlite|mongodb|redis",
            r"update|upgrade|install|uninstall|config"
        ],
    }

    def __init__(self):
        """Initialise le parseur avec les patterns compilés."""
        # Pré-compiler les patterns de catégories pour la performance
        self._compiled_category_patterns = {}
        for cat, patterns in self.CATEGORY_PATTERNS.items():
            combined = "|".join(patterns)
            self._compiled_category_patterns[cat] = re.compile(combined, re.IGNORECASE)

        print("\033[94m[PARSER]\033[0m Parseur de logs initialisé")

    # =========================================================================
    #  PARSING PRINCIPAL
    # =========================================================================

    def parse_agent_message(self, raw_data: str) -> Optional[Dict[str, Any]]:
        """
        Parse un message brut reçu d'un agent via TCP.
        
        Le message attendu est un JSON avec la structure :
        {
            "agent_id": "...",
            "os": "...",
            "ip": "...",
            "timestamp": "...",
            "logs": [ {...}, ... ]
        }
        
        Args:
            raw_data : Chaîne JSON brute reçue via TCP
        
        Returns:
            Dict normalisé ou None si le parsing échoue
        """
        try:
            data = json.loads(raw_data)
        except json.JSONDecodeError as e:
            print(f"\033[91m[PARSER ERREUR]\033[0m JSON invalide : {e}")
            return None

        # Valider les champs obligatoires
        if not isinstance(data, dict):
            print(f"\033[91m[PARSER ERREUR]\033[0m Message n'est pas un objet JSON")
            return None

        agent_id = data.get("agent_id", "unknown")
        agent_os = data.get("os", data.get("os_type", "unknown"))
        agent_ip = data.get("ip", data.get("ip_address", "0.0.0.0"))
        timestamp = data.get("timestamp", datetime.now().isoformat())
        logs = data.get("logs", [])

        msg_type = data.get("type", "logs")

        # Gérer le cas heartbeat (pas de logs)
        if msg_type == "heartbeat":
            return {
                "type": "heartbeat",
                "agent_id": agent_id,
                "os": agent_os,
                "ip": agent_ip,
                "timestamp": timestamp,
                "logs": []
            }

        # Gérer les types register / ips_response (pas de logs à parser)
        if msg_type in ("register", "ips_response"):
            return {
                "type": msg_type,
                "agent_id": agent_id,
                "os": agent_os,
                "ip": agent_ip,
                "timestamp": timestamp,
                "logs": []
            }

        # Gérer les stats système (type dédié ou champ joint aux logs)
        system_stats = data.get("system_stats")

        if msg_type == "system_stats":
            return {
                "type": "system_stats",
                "agent_id": agent_id,
                "os": agent_os,
                "ip": agent_ip,
                "timestamp": timestamp,
                "system_stats": system_stats,
                "logs": []
            }

        # Normaliser les stats système Android si présentes
        if agent_os == "android" and system_stats:
            system_stats = self.parse_android_system_stats(system_stats)

        # Normaliser chaque log
        normalized_logs = []
        for log_entry in logs:
            # Utiliser le parseur Android si c'est un agent Android
            if agent_os == "android" and log_entry.get("collector") == "android":
                normalized = self.parse_android_log(log_entry, agent_id, agent_ip)
            else:
                normalized = self.normalize_log(log_entry, agent_id, agent_ip, agent_os)
            if normalized:
                normalized_logs.append(normalized)

        result = {
            "type": "logs",
            "agent_id": agent_id,
            "os": agent_os,
            "ip": agent_ip,
            "timestamp": timestamp,
            "logs": normalized_logs,
            "raw": raw_data
        }

        # Joindre les stats système si présentes dans le message de logs
        if system_stats:
            result["system_stats"] = system_stats

        return result

    def normalize_log(self, log_entry: Dict, agent_id: str = "",
                      agent_ip: str = "", agent_os: str = "") -> Optional[Dict]:
        """
        Normalise un log individuel en format standard SOC.
        
        Args:
            log_entry : Dictionnaire du log brut
            agent_id  : ID de l'agent source
            agent_ip  : IP de l'agent
            agent_os  : OS de l'agent
        
        Returns:
            Dict normalisé avec les champs standards
        """
        if not isinstance(log_entry, dict):
            return None

        message = str(log_entry.get("message", "") or log_entry.get("line", ""))
        if not message.strip():
            return None

        # Extraire les champs
        source = log_entry.get("source", "unknown")
        level = log_entry.get("level", "INFO")
        category = log_entry.get("category", "")
        event_id = log_entry.get("event_id", None)
        timestamp = log_entry.get("timestamp", datetime.now().isoformat())

        # Normaliser le niveau de sévérité
        level = self.normalize_level(level)

        # Si c'est un event Windows connu, enrichir le log
        if event_id and int(event_id) in self.WINDOWS_EVENT_MAPPING:
            mapping = self.WINDOWS_EVENT_MAPPING[int(event_id)]
            # Utiliser le niveau le plus élevé entre le mapping et le niveau fourni
            mapped_level = mapping["level"]
            if self.VALID_LEVELS.index(mapped_level) > self.VALID_LEVELS.index(level):
                level = mapped_level
            # Utiliser la catégorie du mapping si pas fournie
            if not category:
                category = mapping["category"]

        # Classification automatique de la catégorie si manquante
        if not category or category == "OTHER":
            category = self.classify_category(message)

        # Extraire les IPs du message
        extracted_ips = self.extract_ips(message)

        # Normaliser le timestamp
        timestamp = self.normalize_timestamp(timestamp)

        return {
            "timestamp": timestamp,
            "agent_id": agent_id,
            "agent_ip": agent_ip,
            "agent_os": agent_os,
            "source": source,
            "level": level,
            "category": category,
            "message": message,
            "event_id": event_id,
            "extracted_ips": extracted_ips,
            "raw_json": json.dumps(log_entry, ensure_ascii=False)
        }

    # =========================================================================
    #  NORMALISATION DES CHAMPS
    # =========================================================================

    def normalize_level(self, level: str) -> str:
        """
        Normalise un niveau de sévérité vers les 4 niveaux standards.
        
        Args:
            level : Niveau brut (peut être en minuscules, variantes, etc.)
        
        Returns:
            str : Niveau normalisé (INFO, WARNING, HIGH, CRITICAL)
        """
        if not level:
            return "INFO"

        level_lower = level.strip().lower()

        # Vérifier dans le mapping
        if level_lower in self.LEVEL_MAPPING:
            return self.LEVEL_MAPPING[level_lower]

        # Si le niveau est déjà standard (en majuscules)
        if level.upper() in self.VALID_LEVELS:
            return level.upper()

        # Par défaut : INFO
        return "INFO"

    def normalize_timestamp(self, timestamp: str) -> str:
        """
        Normalise un timestamp vers le format ISO 8601.
        
        Gère plusieurs formats courants :
        - ISO 8601 : 2024-01-15T10:30:00
        - Syslog   : Jan 15 10:30:00
        - Custom   : 2024/01/15 10:30:00
        
        Args:
            timestamp : Timestamp brut
        
        Returns:
            str : Timestamp ISO 8601 normalisé
        """
        if not timestamp:
            return datetime.now().isoformat()

        # Déjà au format ISO 8601 ?
        try:
            dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00").rstrip("+00:00"))
            return dt.isoformat()
        except (ValueError, AttributeError):
            pass

        # Format syslog : "Jan 15 10:30:00" ou "Feb  5 08:15:33"
        syslog_pattern = re.compile(
            r'^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})'
        )
        match = syslog_pattern.match(timestamp)
        if match:
            try:
                month_str, day, time_str = match.groups()
                year = datetime.now().year
                dt = datetime.strptime(
                    f"{year} {month_str} {day} {time_str}",
                    "%Y %b %d %H:%M:%S"
                )
                return dt.isoformat()
            except ValueError:
                pass

        # Format custom : "2024/01/15 10:30:00"
        try:
            dt = datetime.strptime(timestamp, "%Y/%m/%d %H:%M:%S")
            return dt.isoformat()
        except ValueError:
            pass

        # Format avec tirets : "15-01-2024 10:30:00"
        try:
            dt = datetime.strptime(timestamp, "%d-%m-%Y %H:%M:%S")
            return dt.isoformat()
        except ValueError:
            pass

        # Si aucun format reconnu, retourner maintenant
        return datetime.now().isoformat()

    def classify_category(self, message: str) -> str:
        """
        Classifie automatiquement la catégorie d'un log selon son contenu.
        
        Utilise des patterns regex pour analyser le message et déterminer
        la catégorie la plus probable.
        
        Args:
            message : Contenu du message
        
        Returns:
            str : Catégorie détectée (AUTH, NETWORK, WEB, SECURITY, SYSTEM, APPLICATION, OTHER)
        """
        if not message:
            return "OTHER"

        # Tester chaque catégorie avec les patterns compilés
        best_category = "OTHER"
        best_score = 0

        for cat, pattern in self._compiled_category_patterns.items():
            matches = pattern.findall(message)
            score = len(matches)
            if score > best_score:
                best_score = score
                best_category = cat

        return best_category

    # =========================================================================
    #  EXTRACTION DE DONNÉES
    # =========================================================================

    def extract_ips(self, message: str) -> List[str]:
        """
        Extrait toutes les adresses IPv4 d'un message.
        
        Args:
            message : Texte à analyser
        
        Returns:
            List[str] : Liste d'adresses IP trouvées (sans doublons)
        """
        if not message:
            return []

        ips = self.IP_PATTERN.findall(message)
        # Supprimer les doublons tout en préservant l'ordre
        seen = set()
        unique_ips = []
        for ip in ips:
            if ip not in seen:
                seen.add(ip)
                unique_ips.append(ip)
        return unique_ips

    def extract_username(self, message: str) -> Optional[str]:
        """
        Tente d'extraire un nom d'utilisateur d'un message de log.
        
        Args:
            message : Message à analyser
        
        Returns:
            str ou None : Nom d'utilisateur trouvé
        """
        patterns = [
            r"user[= :]+(\w+)",
            r"for (\w+) from",
            r"account[= :]+(\w+)",
            r"logon.*?user.*?(\w+)",
            r"User Name:\s*(\w+)",
        ]
        for pattern in patterns:
            match = re.search(pattern, message, re.IGNORECASE)
            if match:
                username = match.group(1)
                # Filtrer les faux positifs
                if username.lower() not in ["invalid", "unknown", "none", "null", ""]:
                    return username
        return None

    def extract_port(self, message: str) -> Optional[int]:
        """
        Extrait un numéro de port d'un message de log.
        
        Args:
            message : Message à analyser
        
        Returns:
            int ou None : Numéro de port trouvé
        """
        patterns = [
            r"port[= :]+(\d+)",
            r":(\d{2,5})(?:\s|$|/)",
        ]
        for pattern in patterns:
            match = re.search(pattern, message, re.IGNORECASE)
            if match:
                port = int(match.group(1))
                if 1 <= port <= 65535:
                    return port
        return None

    # =========================================================================
    #  PARSING SPÉCIFIQUE LINUX
    # =========================================================================

    def parse_syslog_line(self, line: str, agent_id: str = "",
                          agent_ip: str = "") -> Optional[Dict]:
        """
        Parse une ligne au format syslog Linux.
        
        Format typique : "Jan 15 10:30:00 hostname service[pid]: message"
        
        Args:
            line     : Ligne de log brute
            agent_id : ID de l'agent
            agent_ip : IP de l'agent
        
        Returns:
            Dict normalisé ou None
        """
        if not line or not line.strip():
            return None

        # Pattern syslog standard
        syslog_re = re.compile(
            r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'  # timestamp
            r'(\S+)\s+'                                       # hostname
            r'(\S+?)(?:\[\d+\])?:\s+'                         # service[pid]
            r'(.+)$'                                           # message
        )

        match = syslog_re.match(line.strip())
        if not match:
            # Si le pattern ne correspond pas, retourner un log basique
            return self.normalize_log({
                "source": "syslog",
                "message": line.strip(),
                "level": "INFO",
            }, agent_id, agent_ip, "linux")

        timestamp_str, hostname, service, message = match.groups()

        # Déterminer le niveau selon le contenu
        level = self._detect_level_from_message(message)

        return self.normalize_log({
            "timestamp": timestamp_str,
            "source": service,
            "message": message,
            "level": level,
        }, agent_id, agent_ip, "linux")

    def parse_auth_log_line(self, line: str, agent_id: str = "",
                            agent_ip: str = "") -> Optional[Dict]:
        """
        Parse une ligne de /var/log/auth.log (tentatives SSH, sudo, etc.)
        
        Args:
            line     : Ligne de log brute
            agent_id : ID de l'agent
            agent_ip : IP de l'agent
        
        Returns:
            Dict normalisé
        """
        parsed = self.parse_syslog_line(line, agent_id, agent_ip)
        if parsed:
            parsed["category"] = "AUTH"

            # Ajuster le niveau pour les événements d'authentification
            msg_lower = parsed["message"].lower()
            if "failed" in msg_lower or "invalid" in msg_lower:
                parsed["level"] = "WARNING"
            if "break-in attempt" in msg_lower:
                parsed["level"] = "HIGH"
            if "accepted" in msg_lower:
                parsed["level"] = "INFO"

        return parsed

    # =========================================================================
    #  PARSING SPÉCIFIQUE WINDOWS
    # =========================================================================

    def parse_windows_event(self, event: Dict, agent_id: str = "",
                            agent_ip: str = "") -> Optional[Dict]:
        """
        Parse un événement Windows Event Log.
        
        Args:
            event    : Dict avec event_id, source, message, etc.
            agent_id : ID de l'agent
            agent_ip : IP de l'agent
        
        Returns:
            Dict normalisé
        """
        event_id = event.get("event_id", 0)
        source = event.get("source", "Windows")
        message = event.get("message", "")
        level = event.get("level", "INFO")

        # Enrichir avec le mapping Windows si disponible
        if event_id in self.WINDOWS_EVENT_MAPPING:
            mapping = self.WINDOWS_EVENT_MAPPING[event_id]
            level = mapping["level"]
            category = mapping["category"]
            if not message:
                message = mapping["desc"]
        else:
            category = self.classify_category(message)

        return self.normalize_log({
            "source": source,
            "event_id": event_id,
            "level": level,
            "category": category,
            "message": message,
        }, agent_id, agent_ip, "windows")

    # =========================================================================
    #  PARSING SPÉCIFIQUE ANDROID
    # =========================================================================

    def parse_android_log(self, log_entry: Dict, agent_id: str = "",
                          agent_ip: str = "") -> Optional[Dict]:
        """
        Parse un log provenant d'un agent Android (Termux).
        
        Sources possibles :
        - BashHistory     : commandes exécutées dans le terminal Termux
        - NetworkMonitor  : connexions réseau détectées
        - TermuxLog       : logs Termux
        
        Args:
            log_entry : Dict du log brut
            agent_id  : ID de l'agent Android
            agent_ip  : IP de l'agent
        
        Returns:
            Dict normalisé ou None
        """
        source = log_entry.get("source", "")
        message = str(log_entry.get("message", "") or log_entry.get("line", ""))
        level = log_entry.get("level", "INFO")

        # Ajuster le niveau pour les commandes suspectes
        if source == "BashHistory" and "suspecte" in message.lower():
            level = "HIGH"

        # Ajuster le niveau pour les connexions réseau suspectes
        if source == "NetworkMonitor" and "SUSPECT" in message.upper():
            level = "HIGH"

        # Détecter la catégorie
        if source == "BashHistory":
            category = "SECURITY"
        elif source == "NetworkMonitor":
            category = "NETWORK"
        else:
            category = self.classify_category(message)

        return self.normalize_log({
            "source": source,
            "level": level,
            "category": category,
            "message": message,
        }, agent_id, agent_ip, "android")

    def parse_android_system_stats(self, stats: Dict) -> Dict:
        """
        Valide et normalise les stats système d'un agent Android.
        
        Spécificités Android :
        - Champ 'battery' présent (percent, charging, plugged)
        - Pas de champ 'swap' ni 'disks'
        
        Args:
            stats : Dict des statistiques système brutes
        
        Returns:
            Dict normalisé (passthrough avec validation)
        """
        if not stats or not isinstance(stats, dict):
            return stats

        # S'assurer que le champ battery existe et est valide
        battery = stats.get("battery", {})
        if not isinstance(battery, dict):
            stats["battery"] = {"percent": -1, "charging": False, "plugged": False}

        return stats

    # =========================================================================
    #  PARSING RÉSEAU
    # =========================================================================

    def parse_network_connection(self, conn_data: Dict, agent_id: str = "",
                                  agent_ip: str = "") -> Optional[Dict]:
        """
        Parse les données de connexion réseau (psutil).
        
        Args:
            conn_data : Dict avec local_addr, remote_addr, status, pid, etc.
            agent_id  : ID de l'agent
            agent_ip  : IP de l'agent
        
        Returns:
            Dict normalisé
        """
        local = conn_data.get("local_addr", "?:?")
        remote = conn_data.get("remote_addr", "?:?")
        status = conn_data.get("status", "UNKNOWN")
        pid = conn_data.get("pid", "?")
        process = conn_data.get("process_name", "unknown")

        message = (
            f"Connexion {status}: {local} → {remote} "
            f"(PID: {pid}, Processus: {process})"
        )

        return self.normalize_log({
            "source": "network",
            "level": "INFO",
            "category": "NETWORK",
            "message": message,
        }, agent_id, agent_ip, "")

    # =========================================================================
    #  UTILITAIRES INTERNES
    # =========================================================================

    def _detect_level_from_message(self, message: str) -> str:
        """
        Détecte le niveau de sévérité d'un log selon son contenu.
        
        Args:
            message : Message à analyser
        
        Returns:
            str : Niveau (INFO, WARNING, HIGH, CRITICAL)
        """
        msg_lower = message.lower()

        # CRITICAL
        if any(word in msg_lower for word in [
            "critical", "emergency", "panic", "fatal",
            "kernel panic", "out of memory", "segfault"
        ]):
            return "CRITICAL"

        # HIGH
        if any(word in msg_lower for word in [
            "error", "failed", "failure", "denied", "refused",
            "unauthorized", "forbidden", "attack", "exploit",
            "malware", "intrusion"
        ]):
            return "HIGH"

        # WARNING
        if any(word in msg_lower for word in [
            "warning", "warn", "timeout", "retry",
            "invalid", "deprecated", "slow", "high load"
        ]):
            return "WARNING"

        # INFO par défaut
        return "INFO"


# =============================================================================
#  POINT D'ENTRÉE — Test standalone
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("  SOC Parser — Test Standalone")
    print("=" * 60)

    parser = LogParser()

    # Test 1 : Parser un message agent complet
    print("\n--- Test 1 : Message agent JSON ---")
    raw = json.dumps({
        "agent_id": "PC-TEST-WIN10",
        "os": "windows",
        "ip": "192.168.1.101",
        "timestamp": "2024-01-15T10:30:00",
        "logs": [
            {
                "source": "Security",
                "event_id": 4625,
                "level": "WARNING",
                "category": "AUTH",
                "message": "Failed login attempt for user admin from 192.168.1.50"
            },
            {
                "source": "System",
                "level": "error",
                "message": "Service Apache crashed with fatal error"
            }
        ]
    })
    result = parser.parse_agent_message(raw)
    if result:
        print(f"  Agent: {result['agent_id']} | OS: {result['os']}")
        for log in result["logs"]:
            print(f"  [{log['level']}] [{log['category']}] {log['message'][:60]}")

    # Test 2 : Normalisation des niveaux
    print("\n--- Test 2 : Normalisation niveaux ---")
    for level in ["error", "warn", "crit", "info", "fatal", "debug", "MEDIUM"]:
        print(f"  {level:10} → {parser.normalize_level(level)}")

    # Test 3 : Extraction IPs
    print("\n--- Test 3 : Extraction IPs ---")
    msg = "Failed login from 192.168.1.50 to server 10.0.0.1 via proxy 172.16.0.1"
    ips = parser.extract_ips(msg)
    print(f"  Message: {msg}")
    print(f"  IPs trouvées: {ips}")

    # Test 4 : Classification catégorie
    print("\n--- Test 4 : Classification ---")
    messages = [
        "Failed password for root from 10.0.0.5 port 22 ssh2",
        "GET /index.html HTTP/1.1 200 OK",
        "kernel: Out of memory: Kill process 1234",
        "iptables: DROP IN=eth0 SRC=10.0.0.5 DST=192.168.1.1",
        "SQL injection detected: SELECT * FROM users WHERE 1=1",
    ]
    for msg in messages:
        cat = parser.classify_category(msg)
        print(f"  [{cat:12}] {msg[:55]}")

    # Test 5 : Parse syslog
    print("\n--- Test 5 : Parse syslog ---")
    syslog_line = "Feb 27 14:30:00 server sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2"
    parsed = parser.parse_syslog_line(syslog_line, "SRV-01", "192.168.1.200")
    if parsed:
        print(f"  [{parsed['level']}] {parsed['source']} — {parsed['message'][:60]}")

    print("\n" + "=" * 60)
    print("  ✅ Tests parser terminés avec succès !")
    print("=" * 60)
