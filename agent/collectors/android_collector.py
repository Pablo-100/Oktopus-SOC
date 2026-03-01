"""
=============================================================================
 Oktopus Agent — Collecteurs Android (Termux)
=============================================================================
 Fichier : agent/collectors/android_collector.py
 Rôle    : Collecte les informations système, réseau et logs Termux sur
           un téléphone Android via l'environnement Termux.
           
           Contient 3 classes :
           - AndroidSystemCollector  : CPU, RAM, Batterie, Réseau, OS, Uptime
           - AndroidNetworkCollector : Connexions TCP actives, ports suspects
           - AndroidLogCollector     : Historique bash, commandes suspectes
           
           Limitations Android (sans root) :
           - Pas d'accès à /var/log ni aux Event Logs système
           - psutil.sensors_battery() peut retourner None
           - psutil.net_connections() peut nécessiter des permissions
           
 Dépendances : psutil, platform (stdlib), os, threading
 Python       : 3.8+
=============================================================================
"""

import os
import time
import platform
import threading
import logging
from datetime import datetime, timedelta

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    psutil = None
    HAS_PSUTIL = False
    print("\033[91m[ANDROID_COLLECTOR]\033[0m psutil non installé — "
          "pip install psutil")

logger = logging.getLogger("SOC.Collector.Android")


# =============================================================================
#  AndroidSystemCollector — Stats système (CPU, RAM, Batterie, Réseau, OS)
# =============================================================================

class AndroidSystemCollector:
    """
    Collecteur de statistiques système pour Android / Termux.
    
    Collecte toutes les 30 secondes :
    - CPU       : utilisation %, nombre de cœurs
    - RAM       : total (Go), utilisé (Go), pourcentage
    - Batterie  : pourcentage, en charge ou non
    - Réseau    : octets envoyés/reçus, connexions actives
    - OS        : système, hostname, architecture
    - Uptime    : durée depuis le démarrage
    - Top 5     : processus les plus gourmands en CPU
    """

    def __init__(self, collect_interval: int = 30):
        """
        Initialise le collecteur système Android.
        
        Args:
            collect_interval : Intervalle de collecte en secondes (défaut: 30)
        """
        self.collect_interval = collect_interval
        self._latest_stats = {}
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread = None

    # =========================================================================
    #  DÉMARRAGE / ARRÊT DU THREAD DE COLLECTE
    # =========================================================================

    def start(self, stop_event: threading.Event = None):
        """
        Démarre la collecte en boucle dans un thread séparé.
        
        Args:
            stop_event : Événement d'arrêt externe (optionnel)
        """
        if stop_event:
            self._stop_event = stop_event

        self._thread = threading.Thread(
            target=self._collection_loop, daemon=True,
            name="AndroidSystemCollector"
        )
        self._thread.start()
        logger.info("Collecteur système Android démarré (intervalle: %ds)",
                     self.collect_interval)

    def stop(self):
        """Arrête le thread de collecte."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)

    def _collection_loop(self):
        """Boucle principale — collecte toutes les N secondes."""
        # Première collecte immédiate
        self._do_collect()
        while not self._stop_event.is_set():
            self._stop_event.wait(self.collect_interval)
            if not self._stop_event.is_set():
                self._do_collect()

    def _do_collect(self):
        """Effectue une collecte complète et stocke le résultat."""
        try:
            stats = self.collect()
            with self._lock:
                self._latest_stats = stats
        except Exception as e:
            logger.error("Erreur lors de la collecte système Android : %s", e)

    # =========================================================================
    #  ACCÈS AUX DERNIÈRES STATS
    # =========================================================================

    def get_latest(self) -> dict:
        """
        Retourne les dernières statistiques collectées.
        
        Returns:
            dict : Statistiques système ou {} si aucune collecte
        """
        with self._lock:
            return dict(self._latest_stats)

    # =========================================================================
    #  COLLECTE PRINCIPALE
    # =========================================================================

    def collect(self) -> dict:
        """
        Collecte toutes les statistiques système Android.
        
        Returns:
            dict : {cpu, ram, battery, network, os_info, uptime,
                    top_processes, collected_at}
        """
        if not HAS_PSUTIL:
            return {"error": "psutil non disponible"}

        stats = {
            "cpu": self._collect_cpu(),
            "ram": self._collect_ram(),
            "battery": self._collect_battery(),
            "network": self._collect_network(),
            "os_info": self._collect_os_info(),
            "uptime": self._collect_uptime(),
            "top_processes": self._collect_top_processes(n=5),
            "collected_at": datetime.now().isoformat()
        }
        return stats

    # =========================================================================
    #  CPU — Utilisation, cœurs
    # =========================================================================

    def _collect_cpu(self) -> dict:
        """
        Collecte les informations CPU.
        Sur Android, la fréquence peut ne pas être disponible.
        
        Returns:
            dict : {percent, cores, freq_mhz, per_core}
        """
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            cores = psutil.cpu_count(logical=True) or 0

            # Fréquence CPU — peut échouer sur Android
            freq_mhz = 0
            try:
                freq = psutil.cpu_freq()
                if freq:
                    freq_mhz = round(freq.current, 0)
            except Exception:
                pass

            # Usage par cœur — peut échouer sur certains appareils
            per_core = []
            try:
                per_core = psutil.cpu_percent(interval=0, percpu=True)
            except Exception:
                pass

            return {
                "percent": cpu_percent,
                "cores": cores,
                "freq_mhz": freq_mhz,
                "per_core": per_core
            }
        except Exception as e:
            logger.error("Erreur collecte CPU Android : %s", e)
            return {"percent": 0, "cores": 0, "freq_mhz": 0, "per_core": []}

    # =========================================================================
    #  RAM — Total, utilisé, pourcentage
    # =========================================================================

    def _collect_ram(self) -> dict:
        """
        Collecte les informations mémoire vive (RAM).
        
        Returns:
            dict : {total_gb, used_gb, percent}
        """
        try:
            mem = psutil.virtual_memory()
            return {
                "total_gb": round(mem.total / (1024 ** 3), 2),
                "used_gb": round(mem.used / (1024 ** 3), 2),
                "percent": mem.percent
            }
        except Exception as e:
            logger.error("Erreur collecte RAM Android : %s", e)
            return {"total_gb": 0, "used_gb": 0, "percent": 0}

    # =========================================================================
    #  BATTERIE — Pourcentage, en charge
    # =========================================================================

    def _collect_battery(self) -> dict:
        """
        Collecte les informations batterie via psutil.sensors_battery().
        Peut retourner None sur certains appareils Android.
        
        Returns:
            dict : {percent, charging, plugged} ou {percent: -1, charging: false}
        """
        try:
            battery = psutil.sensors_battery()
            if battery is None:
                # sensors_battery() non disponible sur cet appareil
                logger.debug("sensors_battery() retourne None — batterie non disponible")
                return {"percent": -1, "charging": False, "plugged": False}

            return {
                "percent": round(battery.percent, 1),
                "charging": battery.power_plugged is True,
                "plugged": battery.power_plugged is True
            }
        except Exception as e:
            logger.error("Erreur collecte batterie Android : %s", e)
            return {"percent": -1, "charging": False, "plugged": False}

    # =========================================================================
    #  RÉSEAU — Octets envoyés/reçus, connexions actives
    # =========================================================================

    def _collect_network(self) -> dict:
        """
        Collecte les statistiques réseau.
        
        Returns:
            dict : {bytes_sent_mb, bytes_recv_mb, connections}
        """
        try:
            net = psutil.net_io_counters()
            # Compter les connexions actives (ESTABLISHED)
            connections = 0
            try:
                conns = psutil.net_connections(kind='inet')
                connections = sum(1 for c in conns if c.status == 'ESTABLISHED')
            except (psutil.AccessDenied, PermissionError, OSError):
                connections = -1  # Pas les droits

            return {
                "bytes_sent_mb": round(net.bytes_sent / (1024 ** 2), 2),
                "bytes_recv_mb": round(net.bytes_recv / (1024 ** 2), 2),
                "connections": connections
            }
        except Exception as e:
            logger.error("Erreur collecte réseau Android : %s", e)
            return {"bytes_sent_mb": 0, "bytes_recv_mb": 0, "connections": 0}

    # =========================================================================
    #  OS — Système, hostname, architecture
    # =========================================================================

    def _collect_os_info(self) -> dict:
        """
        Collecte les informations sur le système d'exploitation Android.
        
        Returns:
            dict : {system, hostname, architecture, machine, version}
        """
        try:
            # Tenter de lire la version Android depuis /system/build.prop
            android_version = ""
            try:
                if os.path.exists("/system/build.prop"):
                    with open("/system/build.prop", "r") as f:
                        for line in f:
                            if line.startswith("ro.build.version.release="):
                                android_version = line.split("=", 1)[1].strip()
                                break
            except Exception:
                pass

            # Fallback : version Termux / uname
            if not android_version:
                android_version = platform.version() or platform.release() or "unknown"

            return {
                "system": "Android",
                "hostname": platform.node() or "android-device",
                "architecture": platform.machine() or "aarch64",
                "machine": platform.machine() or "aarch64",
                "version": android_version
            }
        except Exception as e:
            logger.error("Erreur collecte OS Android : %s", e)
            return {
                "system": "Android",
                "hostname": "unknown",
                "architecture": "unknown",
                "machine": "unknown",
                "version": "unknown"
            }

    # =========================================================================
    #  UPTIME — Durée depuis le démarrage
    # =========================================================================

    def _collect_uptime(self) -> dict:
        """
        Calcule l'uptime du téléphone.
        
        Returns:
            dict : {boot_time, uptime_seconds, uptime_human}
        """
        try:
            boot_ts = psutil.boot_time()
            boot_dt = datetime.fromtimestamp(boot_ts)
            uptime_delta = datetime.now() - boot_dt
            total_sec = int(uptime_delta.total_seconds())

            # Format lisible : "2j 5h 32m 10s"
            days = total_sec // 86400
            hours = (total_sec % 86400) // 3600
            minutes = (total_sec % 3600) // 60
            seconds = total_sec % 60

            parts = []
            if days > 0:
                parts.append(f"{days}j")
            if hours > 0:
                parts.append(f"{hours}h")
            parts.append(f"{minutes}m")
            parts.append(f"{seconds}s")
            human = " ".join(parts)

            return {
                "boot_time": boot_dt.isoformat(),
                "uptime_seconds": total_sec,
                "uptime_human": human
            }
        except Exception as e:
            logger.error("Erreur collecte uptime Android : %s", e)
            return {"boot_time": "", "uptime_seconds": 0, "uptime_human": "N/A"}

    # =========================================================================
    #  TOP PROCESSUS — Les N processus les plus gourmands en CPU
    # =========================================================================

    def _collect_top_processes(self, n: int = 5) -> list:
        """
        Retourne les N processus les plus gourmands en CPU.
        Sur Android/Termux, certains processus peuvent ne pas être accessibles.
        
        Args:
            n : Nombre de processus à retourner (défaut: 5)
        
        Returns:
            list[dict] : [{pid, name, cpu_percent, memory_percent}]
        """
        try:
            procs = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent',
                                              'memory_percent']):
                try:
                    info = proc.info
                    if info['name'] and info['cpu_percent'] is not None:
                        procs.append({
                            "pid": info['pid'],
                            "name": info['name'],
                            "cpu_percent": round(info['cpu_percent'], 1),
                            "memory_percent": round(
                                info['memory_percent'] or 0, 1
                            )
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied,
                        psutil.ZombieProcess):
                    continue

            procs.sort(key=lambda p: p['cpu_percent'], reverse=True)
            return procs[:n]

        except Exception as e:
            logger.error("Erreur collecte top processus Android : %s", e)
            return []


# =============================================================================
#  AndroidNetworkCollector — Surveillance des connexions réseau
# =============================================================================

class AndroidNetworkCollector:
    """
    Collecteur de connexions réseau pour Android / Termux.
    
    Surveille les connexions TCP actives via psutil.net_connections()
    et détecte les ports suspects (4444, 1337, 31337, etc.).
    """

    # Ports suspects connus (reverse shells, C2, etc.)
    SUSPICIOUS_PORTS = {
        4444, 5555, 1337, 31337, 6666, 6667, 9001, 8888,
        1234, 12345, 54321, 3127, 27374, 2745, 6129,
        65535, 0
    }

    # Ports connus (pour le contexte)
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
        self.suspicious_ports = suspicious_ports or self.SUSPICIOUS_PORTS
        self.known_connections = set()  # (local_addr, remote_addr, status)
        self.first_scan = True

    def collect(self) -> list:
        """
        Collecter les événements réseau notables.
        
        Returns:
            list[dict] : Liste de logs réseau avec source, line, timestamp,
                         collector, level
        """
        if not HAS_PSUTIL:
            return []

        new_logs = []
        current_connections = set()

        try:
            connections = psutil.net_connections(kind='inet')
        except (psutil.AccessDenied, PermissionError):
            logger.warning("Permission refusée pour lire les connexions réseau "
                           "(normal sur Android sans root)")
            return []
        except OSError as e:
            logger.error("Erreur psutil.net_connections sur Android: %s", e)
            return []
        except Exception as e:
            logger.error("Erreur inattendue net_connections: %s", e)
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

        self.known_connections = current_connections
        self.first_scan = False

        if new_logs:
            logger.debug("Collecté %d événements réseau Android", len(new_logs))

        return new_logs

    def _analyze_connection(self, conn, local, remote, status) -> dict:
        """
        Analyser une connexion et déterminer si elle est notable.
        
        Returns:
            dict ou None : Log entry si la connexion est notable
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

        # CLOSE_WAIT (connexion en attente de fermeture)
        elif status == "CLOSE_WAIT":
            description_parts.append(f"CLOSE_WAIT {local} ← {remote}")

        else:
            return None

        if not description_parts:
            return None

        # Info processus — peut échouer sur Android sans root
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
            "source": "NetworkMonitor",
            "line": line,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "collector": "android",
            "level": level,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "pid": pid,
            "process": proc_name
        }


# =============================================================================
#  AndroidLogCollector — Historique bash et commandes suspectes
# =============================================================================

class AndroidLogCollector:
    """
    Collecteur de logs Termux pour Android.
    
    Surveille :
    - ~/.bash_history : nouvelles commandes exécutées
    - Détecte les outils d'attaque : nmap, hydra, sqlmap, msfconsole, etc.
    - Génère des alertes de niveau HIGH si outil suspect détecté
    
    Technique : suivi de position fichier (même technique que LinuxCollector)
    """

    # Commandes/outils considérés comme suspects
    SUSPICIOUS_COMMANDS = [
        "nmap", "hydra", "sqlmap", "msfconsole", "metasploit",
        "msfvenom", "aircrack", "airmon", "aireplay", "airodump",
        "john", "hashcat", "nikto", "gobuster", "dirb", "dirbuster",
        "enum4linux", "crackmapexec", "responder", "mimikatz",
        "burpsuite", "wpscan", "masscan", "netcat", "nc ",
        "reverse_tcp", "meterpreter", "exploit/", "payload/",
        "beef-xss", "ettercap", "arpspoof", "tcpdump -w",
        "wireshark", "tshark"
    ]

    def __init__(self):
        """Initialise le collecteur de logs Termux."""
        # Chemins des fichiers à surveiller
        home = os.path.expanduser("~")
        self.history_path = os.path.join(home, ".bash_history")
        self.termux_log_path = os.path.join(home, ".termux", "termux.log")

        # Positions de lecture dans les fichiers
        self.file_positions = {}
        self.file_inodes = {}

        # Initialiser les positions (aller à la fin pour ne pas lire l'historique)
        self._init_position(self.history_path)
        self._init_position(self.termux_log_path)

        logger.info("Collecteur logs Android initialisé")
        logger.info("  → Bash history : %s (existe: %s)",
                     self.history_path, os.path.exists(self.history_path))
        logger.info("  → Termux log   : %s (existe: %s)",
                     self.termux_log_path, os.path.exists(self.termux_log_path))

    def _init_position(self, filepath: str):
        """Se positionner à la fin du fichier (ne pas lire l'historique existant)."""
        try:
            if os.path.exists(filepath):
                stat = os.stat(filepath)
                self.file_positions[filepath] = stat.st_size
                self.file_inodes[filepath] = stat.st_ino
                logger.debug("Position initiale : %s @ %d bytes", filepath, stat.st_size)
            else:
                self.file_positions[filepath] = 0
                self.file_inodes[filepath] = None
        except OSError as e:
            logger.warning("Impossible de lire %s : %s", filepath, e)
            self.file_positions[filepath] = 0
            self.file_inodes[filepath] = None

    def collect(self) -> list:
        """
        Collecter les nouvelles lignes des fichiers surveillés.
        Détecte les commandes suspectes dans l'historique bash.
        
        Returns:
            list[dict] : Liste de logs au format standard
        """
        new_logs = []

        # 1. Lire les nouvelles commandes depuis bash_history
        try:
            history_lines = self._read_new_lines(self.history_path)
            for line in history_lines:
                line = line.strip()
                if not line:
                    continue

                # Vérifier si la commande est suspecte
                is_suspicious = self._is_suspicious_command(line)
                level = "HIGH" if is_suspicious else "INFO"
                source = "BashHistory"

                if is_suspicious:
                    log_msg = f"Commande suspecte détectée : {line}"
                    logger.warning("[ANDROID] %s", log_msg)
                else:
                    log_msg = f"Commande exécutée : {line}"

                new_logs.append({
                    "source": source,
                    "line": log_msg,
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "collector": "android",
                    "level": level
                })
        except Exception as e:
            logger.error("Erreur lecture bash_history : %s", e)

        # 2. Lire les nouvelles lignes du log Termux (si disponible)
        try:
            termux_lines = self._read_new_lines(self.termux_log_path)
            for line in termux_lines:
                line = line.strip()
                if not line:
                    continue

                new_logs.append({
                    "source": "TermuxLog",
                    "line": line,
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "collector": "android",
                    "level": "INFO"
                })
        except Exception as e:
            logger.debug("Erreur lecture termux.log (normal si inexistant) : %s", e)

        if new_logs:
            logger.debug("Collecté %d événements depuis les logs Android", len(new_logs))

        return new_logs

    def _read_new_lines(self, filepath: str) -> list:
        """
        Lire les nouvelles lignes d'un fichier (technique tail -f).
        Gère la rotation de fichier et la troncation.
        
        Args:
            filepath : Chemin du fichier à lire
        
        Returns:
            list[str] : Nouvelles lignes lues
        """
        if not os.path.exists(filepath):
            return []

        lines = []
        try:
            stat = os.stat(filepath)
            current_inode = stat.st_ino
            current_size = stat.st_size
            saved_pos = self.file_positions.get(filepath, 0)
            saved_inode = self.file_inodes.get(filepath, None)

            # Détecter la rotation du fichier (inode changé)
            if saved_inode is not None and current_inode != saved_inode:
                logger.info("Rotation détectée : %s (inode changé)", filepath)
                saved_pos = 0

            # Détecter la troncation (fichier plus petit qu'avant)
            if current_size < saved_pos:
                logger.info("Troncation détectée : %s", filepath)
                saved_pos = 0

            # Lire les nouvelles données
            if current_size > saved_pos:
                with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                    f.seek(saved_pos)
                    lines = f.readlines()

                # Mettre à jour la position
                self.file_positions[filepath] = current_size
                self.file_inodes[filepath] = current_inode

        except PermissionError:
            logger.warning("Permission refusée : %s", filepath)
        except OSError as e:
            logger.error("Erreur lecture %s : %s", filepath, e)

        return lines

    def _is_suspicious_command(self, command: str) -> bool:
        """
        Vérifie si une commande est suspecte (outil d'attaque connu).
        
        Args:
            command : La commande à vérifier
        
        Returns:
            bool : True si la commande est suspecte
        """
        cmd_lower = command.lower().strip()
        for suspicious in self.SUSPICIOUS_COMMANDS:
            if suspicious in cmd_lower:
                return True
        return False


# =============================================================================
#  TEST STANDALONE
# =============================================================================

if __name__ == "__main__":
    """Test rapide des collecteurs Android."""
    import json as _json

    print("=" * 60)
    print("  Oktopus — Test Collecteurs Android")
    print("=" * 60)

    # Test SystemCollector
    print("\n--- AndroidSystemCollector ---")
    sys_collector = AndroidSystemCollector()
    stats = sys_collector.collect()
    print(_json.dumps(stats, indent=2, ensure_ascii=False))

    # Test NetworkCollector
    print("\n--- AndroidNetworkCollector ---")
    net_collector = AndroidNetworkCollector()
    logs = net_collector.collect()  # Premier scan — pas de logs
    logs = net_collector.collect()  # Deuxième scan — nouvelles connexions
    print(f"  Logs réseau collectés : {len(logs)}")
    for log in logs[:5]:
        print(f"  [{log['level']}] {log['line'][:70]}")

    # Test LogCollector
    print("\n--- AndroidLogCollector ---")
    log_collector = AndroidLogCollector()
    logs = log_collector.collect()
    print(f"  Logs Termux collectés : {len(logs)}")

    print("\n" + "=" * 60)
    print("  ✅ Tests collecteurs Android terminés !")
    print("=" * 60)
