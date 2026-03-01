"""
=============================================================================
 Oktopus Agent — Collecteur de Statistiques Système
=============================================================================
 Fichier : agent/collectors/system_collector.py
 Rôle    : Collecte les caractéristiques matérielles et logicielles de
           la machine agent (CPU, RAM, SWAP, disque, réseau, OS, uptime,
           top 5 processus) et les envoie au serveur toutes les 30 secondes.
           
           Inspiré du module « System Inventory » de Wazuh / Elastic Agent.
 
 Dépendances : psutil, platform (stdlib)
 Python       : 3.8+
=============================================================================
"""

import platform
import time
import threading
import logging
from datetime import datetime, timedelta

try:
    import psutil
except ImportError:
    psutil = None
    print("\033[91m[SYSTEM_COLLECTOR]\033[0m psutil non installé — "
          "pip install psutil")

logger = logging.getLogger("SOC.SystemCollector")


class SystemCollector:
    """
    Collecteur de statistiques système.
    
    Collecte toutes les 30 secondes :
    - CPU       : utilisation %, nombre de cœurs, threads, fréquence
    - RAM       : total (Go), utilisé (Go), pourcentage
    - SWAP      : total (Go), pourcentage
    - Disques   : utilisation par partition (Go, %)
    - Réseau    : octets envoyés/reçus, connexions actives
    - OS        : système, version, architecture, hostname
    - Uptime    : durée depuis le démarrage
    - Top 5     : processus les plus gourmands en CPU
    """

    def __init__(self, collect_interval: int = 30):
        """
        Initialise le collecteur système.
        
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
            name="SystemCollector"
        )
        self._thread.start()
        logger.info("Collecteur système démarré (intervalle: %ds)",
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
            logger.error("Erreur lors de la collecte système : %s", e)

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
        Collecte toutes les statistiques système.
        
        Returns:
            dict : {cpu, ram, swap, disks, network, os_info, uptime, top_processes,
                    collected_at}
        """
        if psutil is None:
            return {"error": "psutil non disponible"}

        stats = {
            "cpu": self._collect_cpu(),
            "ram": self._collect_ram(),
            "swap": self._collect_swap(),
            "disks": self._collect_disks(),
            "network": self._collect_network(),
            "os_info": self._collect_os_info(),
            "uptime": self._collect_uptime(),
            "top_processes": self._collect_top_processes(n=5),
            "collected_at": datetime.now().isoformat()
        }
        return stats

    # =========================================================================
    #  CPU — Utilisation, cœurs, fréquence
    # =========================================================================

    def _collect_cpu(self) -> dict:
        """
        Collecte les informations CPU.
        
        Returns:
            dict : {percent, cores_physical, cores_logical, freq_current_mhz,
                    freq_max_mhz, per_core_percent}
        """
        try:
            # Pourcentage global (intervalle 1s pour une mesure précise)
            cpu_percent = psutil.cpu_percent(interval=1)
            cores_physical = psutil.cpu_count(logical=False) or 0
            cores_logical = psutil.cpu_count(logical=True) or 0

            # Fréquence CPU
            freq = psutil.cpu_freq()
            freq_current = round(freq.current, 0) if freq else 0
            freq_max = round(freq.max, 0) if freq and freq.max else 0

            # Utilisation par cœur
            per_core = psutil.cpu_percent(interval=0, percpu=True)

            return {
                "percent": cpu_percent,
                "cores_physical": cores_physical,
                "cores_logical": cores_logical,
                "freq_current_mhz": freq_current,
                "freq_max_mhz": freq_max,
                "per_core_percent": per_core
            }
        except Exception as e:
            logger.error("Erreur collecte CPU : %s", e)
            return {"percent": 0, "cores_physical": 0, "cores_logical": 0,
                    "freq_current_mhz": 0, "freq_max_mhz": 0, "per_core_percent": []}

    # =========================================================================
    #  RAM — Total, utilisé, pourcentage
    # =========================================================================

    def _collect_ram(self) -> dict:
        """
        Collecte les informations mémoire vive (RAM).
        
        Returns:
            dict : {total_gb, used_gb, available_gb, percent}
        """
        try:
            mem = psutil.virtual_memory()
            return {
                "total_gb": round(mem.total / (1024 ** 3), 2),
                "used_gb": round(mem.used / (1024 ** 3), 2),
                "available_gb": round(mem.available / (1024 ** 3), 2),
                "percent": mem.percent
            }
        except Exception as e:
            logger.error("Erreur collecte RAM : %s", e)
            return {"total_gb": 0, "used_gb": 0, "available_gb": 0, "percent": 0}

    # =========================================================================
    #  SWAP — Total, pourcentage
    # =========================================================================

    def _collect_swap(self) -> dict:
        """
        Collecte les informations mémoire swap.
        
        Returns:
            dict : {total_gb, used_gb, percent}
        """
        try:
            swap = psutil.swap_memory()
            return {
                "total_gb": round(swap.total / (1024 ** 3), 2),
                "used_gb": round(swap.used / (1024 ** 3), 2),
                "percent": swap.percent
            }
        except Exception as e:
            logger.error("Erreur collecte SWAP : %s", e)
            return {"total_gb": 0, "used_gb": 0, "percent": 0}

    # =========================================================================
    #  DISQUES — Utilisation par partition
    # =========================================================================

    def _collect_disks(self) -> list:
        """
        Collecte l'utilisation de chaque partition montée.
        Fallback sur C:\\ pour Windows si disk_partitions() échoue.
        
        Returns:
            list[dict] : [{device, mountpoint, fstype, total_gb, used_gb,
                           free_gb, percent}]
        """
        disks = []
        try:
            partitions = psutil.disk_partitions(all=False)
            if not partitions:
                # Fallback Windows : C:\\
                partitions = [type("Part", (), {
                    "device": "C:\\", "mountpoint": "C:\\", "fstype": "NTFS"
                })()]

            for part in partitions:
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    disks.append({
                        "device": part.device,
                        "mountpoint": part.mountpoint,
                        "fstype": part.fstype,
                        "total_gb": round(usage.total / (1024 ** 3), 2),
                        "used_gb": round(usage.used / (1024 ** 3), 2),
                        "free_gb": round(usage.free / (1024 ** 3), 2),
                        "percent": usage.percent
                    })
                except (PermissionError, OSError):
                    # Partition non accessible (CD-ROM, etc.)
                    continue

        except Exception as e:
            logger.error("Erreur collecte disques : %s", e)
            # Fallback Windows C:\\
            try:
                usage = psutil.disk_usage("C:\\")
                disks.append({
                    "device": "C:\\",
                    "mountpoint": "C:\\",
                    "fstype": "NTFS",
                    "total_gb": round(usage.total / (1024 ** 3), 2),
                    "used_gb": round(usage.used / (1024 ** 3), 2),
                    "free_gb": round(usage.free / (1024 ** 3), 2),
                    "percent": usage.percent
                })
            except Exception:
                pass

        return disks

    # =========================================================================
    #  RÉSEAU — Octets envoyés/reçus, connexions actives
    # =========================================================================

    def _collect_network(self) -> dict:
        """
        Collecte les statistiques réseau.
        
        Returns:
            dict : {bytes_sent_mb, bytes_recv_mb, packets_sent, packets_recv,
                    active_connections}
        """
        try:
            net = psutil.net_io_counters()
            # Compter les connexions actives (ESTABLISHED uniquement)
            try:
                connections = psutil.net_connections(kind='inet')
                active = sum(1 for c in connections
                             if c.status == 'ESTABLISHED')
            except (psutil.AccessDenied, PermissionError):
                active = -1  # Pas les droits

            return {
                "bytes_sent_mb": round(net.bytes_sent / (1024 ** 2), 2),
                "bytes_recv_mb": round(net.bytes_recv / (1024 ** 2), 2),
                "packets_sent": net.packets_sent,
                "packets_recv": net.packets_recv,
                "active_connections": active
            }
        except Exception as e:
            logger.error("Erreur collecte réseau : %s", e)
            return {"bytes_sent_mb": 0, "bytes_recv_mb": 0,
                    "packets_sent": 0, "packets_recv": 0,
                    "active_connections": 0}

    # =========================================================================
    #  OS — Système, version, architecture, hostname
    # =========================================================================

    def _collect_os_info(self) -> dict:
        """
        Collecte les informations sur le système d'exploitation.
        
        Returns:
            dict : {system, version, release, architecture, hostname, machine}
        """
        try:
            return {
                "system": platform.system(),
                "version": platform.version(),
                "release": platform.release(),
                "architecture": platform.architecture()[0],
                "hostname": platform.node(),
                "machine": platform.machine()
            }
        except Exception as e:
            logger.error("Erreur collecte OS : %s", e)
            return {"system": "unknown", "version": "", "release": "",
                    "architecture": "", "hostname": "", "machine": ""}

    # =========================================================================
    #  UPTIME — Durée depuis le démarrage
    # =========================================================================

    def _collect_uptime(self) -> dict:
        """
        Calcule l'uptime de la machine.
        
        Returns:
            dict : {boot_time, uptime_seconds, uptime_human}
        """
        try:
            boot_ts = psutil.boot_time()
            boot_dt = datetime.fromtimestamp(boot_ts)
            uptime_delta = datetime.now() - boot_dt
            total_sec = int(uptime_delta.total_seconds())

            # Format lisible : "2j 5h 32m"
            days = total_sec // 86400
            hours = (total_sec % 86400) // 3600
            minutes = (total_sec % 3600) // 60

            parts = []
            if days > 0:
                parts.append(f"{days}j")
            if hours > 0:
                parts.append(f"{hours}h")
            parts.append(f"{minutes}m")
            human = " ".join(parts)

            return {
                "boot_time": boot_dt.isoformat(),
                "uptime_seconds": total_sec,
                "uptime_human": human
            }
        except Exception as e:
            logger.error("Erreur collecte uptime : %s", e)
            return {"boot_time": "", "uptime_seconds": 0, "uptime_human": "N/A"}

    # =========================================================================
    #  TOP PROCESSUS — Les N processus les plus gourmands en CPU
    # =========================================================================

    def _collect_top_processes(self, n: int = 5) -> list:
        """
        Retourne les N processus les plus gourmands en CPU.
        
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
                    # Ignorer les processus système sans nom
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

            # Trier par CPU décroissant et prendre les N premiers
            procs.sort(key=lambda p: p['cpu_percent'], reverse=True)
            return procs[:n]

        except Exception as e:
            logger.error("Erreur collecte top processus : %s", e)
            return []


# =============================================================================
#  TEST STANDALONE
# =============================================================================

if __name__ == "__main__":
    """Test rapide du collecteur système."""
    import json as _json

    collector = SystemCollector()
    stats = collector.collect()
    print(_json.dumps(stats, indent=2, ensure_ascii=False))
