"""
=============================================================================
 Oktopus Agent — Collecteur Réseau
=============================================================================
 Fichier : agent/collectors/network_collector.py
 Rôle    : Surveillance des connexions réseau via psutil
            - Détection de connexions suspectes (ports inhabituels)
            - Détection de nouvelles connexions établies
            - Monitoring des connexions en écoute
=============================================================================
"""

import time
import logging
import platform

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

logger = logging.getLogger("SOC.Collector.Network")


class NetworkCollector:
    """Collecteur de connexions réseau via psutil."""

    # Ports suspects connus
    SUSPICIOUS_PORTS = {
        4444, 5555, 1337, 31337, 6666, 6667, 9001, 8888,
        1234, 12345, 54321, 3127, 27374, 2745, 6129,
        65535, 0
    }

    # Ports connus (pour contexte)
    KNOWN_PORTS = {
        22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
        445: "SMB", 993: "IMAPS", 995: "POP3S", 3306: "MySQL",
        3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
        8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB"
    }

    def __init__(self, suspicious_ports=None):
        """
        Args:
            suspicious_ports (set, optional): Ensemble de ports à considérer suspects
        """
        if not HAS_PSUTIL:
            logger.error("psutil est requis pour le collecteur réseau. Installez avec: pip install psutil")

        self.suspicious_ports = suspicious_ports or self.SUSPICIOUS_PORTS
        self.known_connections = set()  # (local_addr, remote_addr, status)
        self.first_scan = True

    def collect(self):
        """
        Collecter les événements réseau notables.
        
        Returns:
            list[dict]: Liste de logs réseau :
                {
                    "source": "network",
                    "line": str,          # description de la connexion
                    "timestamp": str,
                    "collector": "network",
                    "level": str          # INFO/WARNING/HIGH
                }
        """
        if not HAS_PSUTIL:
            return []

        new_logs = []
        current_connections = set()

        try:
            connections = psutil.net_connections(kind='inet')
        except (psutil.AccessDenied, PermissionError):
            logger.warning("Permission refusée pour lire les connexions réseau (root/admin requis)")
            return []
        except Exception as e:
            logger.error(f"Erreur psutil.net_connections: {e}")
            return []

        for conn in connections:
            # Construire une clé unique pour la connexion
            local = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "?"
            remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "-"
            status = conn.status
            conn_key = (local, remote, status)
            current_connections.add(conn_key)

            # Ne traiter que les nouvelles connexions
            if conn_key in self.known_connections:
                continue

            # Si c'est le premier scan, ne pas tout reporter
            if self.first_scan:
                continue

            # Analyser la connexion
            log_entry = self._analyze_connection(conn, local, remote, status)
            if log_entry:
                new_logs.append(log_entry)

        # Détecter les connexions fermées (optionnel, pour le suivi)
        # closed = self.known_connections - current_connections
        # (pas de génération de log pour les fermetures pour éviter le bruit)

        self.known_connections = current_connections
        self.first_scan = False

        if new_logs:
            logger.debug(f"Collecté {len(new_logs)} événements réseau")

        return new_logs

    def _analyze_connection(self, conn, local, remote, status):
        """
        Analyser une connexion et déterminer si elle est notable.
        
        Returns:
            dict or None: Log entry si la connexion est notable
        """
        if not conn.raddr:
            return None  # Pas de connexion distante (LISTEN, etc.)

        remote_port = conn.raddr.port
        local_port = conn.laddr.port if conn.laddr else 0
        remote_ip = conn.raddr.ip

        # Ignorer les connexions loopback
        if remote_ip in ("127.0.0.1", "::1"):
            return None

        level = "INFO"
        description_parts = []

        # Détecter les ports suspects
        if remote_port in self.suspicious_ports:
            level = "HIGH"
            description_parts.append(f"PORT SUSPECT remote={remote_port}")
        elif local_port in self.suspicious_ports:
            level = "HIGH"
            description_parts.append(f"PORT SUSPECT local={local_port}")

        # Connexions ESTABLISHED vers l'extérieur
        if status == "ESTABLISHED":
            port_name = self.KNOWN_PORTS.get(remote_port, "")
            service = f" ({port_name})" if port_name else ""
            description_parts.append(f"ESTABLISHED {local} → {remote}{service}")

        # Connexions SYN_SENT (tentatives de connexion)
        elif status == "SYN_SENT":
            description_parts.append(f"SYN_SENT {local} → {remote}")
            if level == "INFO":
                level = "INFO"

        # CLOSE_WAIT (connexion en attente de fermeture côté distant)
        elif status == "CLOSE_WAIT":
            description_parts.append(f"CLOSE_WAIT {local} ← {remote}")

        else:
            return None  # Ignorer les autres statuts non intéressants

        if not description_parts:
            return None

        # Info processus
        pid = conn.pid
        proc_name = ""
        if pid:
            try:
                proc = psutil.Process(pid)
                proc_name = proc.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                proc_name = "?"

        line = " | ".join(description_parts)
        if proc_name:
            line += f" [PID={pid} {proc_name}]"

        return {
            "source": "network",
            "line": line,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "collector": "network",
            "level": level,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "pid": pid,
            "process": proc_name
        }

    def get_listening_ports(self):
        """Retourne la liste des ports en écoute sur la machine."""
        if not HAS_PSUTIL:
            return []

        listening = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN' and conn.laddr:
                    pid = conn.pid
                    proc_name = ""
                    if pid:
                        try:
                            proc_name = psutil.Process(pid).name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass

                    listening.append({
                        "port": conn.laddr.port,
                        "ip": conn.laddr.ip,
                        "pid": pid,
                        "process": proc_name
                    })
        except (psutil.AccessDenied, PermissionError):
            pass

        return listening

    def get_connection_stats(self):
        """Retourne des statistiques sur les connexions réseau."""
        if not HAS_PSUTIL:
            return {}

        stats = {
            "ESTABLISHED": 0,
            "LISTEN": 0,
            "TIME_WAIT": 0,
            "CLOSE_WAIT": 0,
            "SYN_SENT": 0,
            "other": 0
        }

        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status in stats:
                    stats[conn.status] += 1
                else:
                    stats["other"] += 1
        except (psutil.AccessDenied, PermissionError):
            pass

        return stats

    def get_status(self):
        """Retourne le statut du collecteur réseau."""
        return {
            "has_psutil": HAS_PSUTIL,
            "tracked_connections": len(self.known_connections),
            "suspicious_ports": sorted(list(self.suspicious_ports))[:10],
            "first_scan": self.first_scan
        }
