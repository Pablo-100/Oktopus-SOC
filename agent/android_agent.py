"""
=============================================================================
 Oktopus — Agent Android (Termux)
=============================================================================
 Fichier : agent/android_agent.py
 Rôle    : Point d'entrée de l'agent Android Termux.
           
           Cet agent est un exécutable séparé de agent.py, conçu pour
           fonctionner dans l'environnement Termux sur un téléphone Android.
           
           Différences avec l'agent standard :
           - Pas de blocker/IPS (pas de root)
           - Détection automatique d'Android (Termux)
           - Batterie dans les stats système
           - Collecte bash_history pour commandes suspectes
           - ID format : ANDROID-{hostname}-{uuid[:6]}
           
 Usage   : python -m agent.android_agent --server <IP> --port 9999
 Python  : 3.8+
=============================================================================
"""

import os
import sys
import time
import uuid
import signal
import logging
import platform
import argparse
import threading
from datetime import datetime

# ============================================================================
#  VÉRIFICATION DE L'ENVIRONNEMENT TERMUX / ANDROID
# ============================================================================

def is_android() -> bool:
    """
    Détecte si on tourne sur Android (Termux).
    
    Vérifie :
    1. Existence du répertoire Termux /data/data/com.termux
    2. /proc/version contient "android"
    3. Présence de TERMUX_VERSION dans les variables d'environnement
    
    Returns:
        bool : True si Android détecté
    """
    # Check 1 : Répertoire Termux
    if os.path.exists("/data/data/com.termux"):
        return True

    # Check 2 : /proc/version
    try:
        with open("/proc/version", "r") as f:
            content = f.read().lower()
            if "android" in content:
                return True
    except (IOError, OSError):
        pass

    # Check 3 : Variable d'environnement Termux
    if os.environ.get("TERMUX_VERSION"):
        return True

    # Check 4 : Architecture ARM typique d'Android
    machine = platform.machine().lower()
    if "aarch64" in machine or "armv" in machine:
        # Vérifier en plus que c'est pas un Raspberry Pi ou autre ARM Linux
        try:
            with open("/proc/version", "r") as f:
                if "linux" in f.read().lower():
                    # Sur ARM Linux — vérifier si Termux
                    if os.path.exists(os.path.expanduser("~/.termux")):
                        return True
        except (IOError, OSError):
            pass

    return False


# ============================================================================
#  IMPORTS CONDITIONNELS
# ============================================================================

try:
    from agent.sender import TCPSender
except ImportError:
    # Si lancé depuis le mauvais répertoire
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from agent.sender import TCPSender

from agent.collectors.android_collector import (
    AndroidSystemCollector,
    AndroidNetworkCollector,
    AndroidLogCollector
)

# ============================================================================
#  CONFIGURATION LOGGING
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="\033[90m%(asctime)s\033[0m [%(name)s] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("SOC.AndroidAgent")


# ============================================================================
#  CLASSE PRINCIPALE — AndroidAgent
# ============================================================================

class AndroidAgent:
    """
    Agent SOC pour Android / Termux.
    
    Collecte système (CPU, RAM, batterie, réseau), connexions réseau,
    et historique bash. Envoie les données au serveur SOC via TCP.
    
    Pas de blocage IPS (nécessiterait root).
    """

    # Bannière ASCII au démarrage
    BANNER = r"""
    ╔══════════════════════════════════════════════════╗
    ║          🐙 Oktopus SOC — Agent Android 🐙       ║
    ║            📱 Termux Edition                      ║
    ╚══════════════════════════════════════════════════╝
    """

    def __init__(self, server_host: str = "127.0.0.1",
                 server_port: int = 9999,
                 collect_interval: int = 5,
                 agent_id: str = None):
        """
        Initialise l'agent Android.
        
        Args:
            server_host      : Adresse IP du serveur SOC
            server_port      : Port TCP du serveur
            collect_interval : Intervalle de collecte des logs (secondes)
            agent_id         : ID de l'agent (auto-généré si None)
        """
        self.server_host = server_host
        self.server_port = server_port
        self.collect_interval = collect_interval
        self.os_type = "android"

        # Événement d'arrêt global
        self._stop_event = threading.Event()

        # Générer ou charger l'ID de l'agent
        self.agent_id = agent_id or self._load_or_generate_agent_id()

        # Détecter l'adresse IP locale
        self.ip_address = self._get_local_ip()

        # Initialiser le sender TCP (réutilise sender.py existant)
        self.sender = TCPSender(
            server_host=self.server_host,
            server_port=self.server_port
        )

        # Initialiser les collecteurs Android
        self.system_collector = AndroidSystemCollector(collect_interval=30)
        self.network_collector = AndroidNetworkCollector()
        self.log_collector = AndroidLogCollector()

        # Liste des collecteurs pour la boucle de collecte
        self.collectors = [self.network_collector, self.log_collector]

        logger.info("Agent Android initialisé")
        logger.info("  Agent ID   : %s", self.agent_id)
        logger.info("  Serveur    : %s:%d", self.server_host, self.server_port)
        logger.info("  Intervalle : %ds", self.collect_interval)
        logger.info("  IP locale  : %s", self.ip_address)

    # =========================================================================
    #  GESTION DE L'IDENTIFIANT AGENT
    # =========================================================================

    def _load_or_generate_agent_id(self) -> str:
        """
        Charge ou génère l'identifiant unique de l'agent.
        
        Format : ANDROID-{hostname}-{uuid[:6]}
        Stocké dans agent_id.txt à la racine du projet.
        
        Returns:
            str : Identifiant de l'agent
        """
        # Chercher le fichier agent_id.txt
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        id_file = os.path.join(base_dir, "agent_id.txt")

        # Si le fichier existe, vérifier s'il contient un ID Android
        if os.path.exists(id_file):
            try:
                existing_id = open(id_file, 'r').read().strip()
                if existing_id.startswith("ANDROID-"):
                    logger.info("ID agent Android chargé : %s", existing_id)
                    return existing_id
                # Si l'ID existant n'est pas Android, on en crée un nouveau
                # (pour ne pas écraser un ID Linux/Windows)
                logger.info("ID existant non-Android (%s), génération d'un nouvel ID Android",
                            existing_id)
            except OSError:
                pass

        # Générer un nouvel ID
        hostname = platform.node() or "android"
        uid = uuid.uuid4().hex[:6]
        agent_id = f"ANDROID-{hostname}-{uid}"

        # Sauvegarder dans un fichier séparé pour Android
        android_id_file = os.path.join(base_dir, "android_agent_id.txt")
        try:
            with open(android_id_file, 'w') as f:
                f.write(agent_id)
            logger.info("Nouvel ID agent Android généré et sauvegardé : %s", agent_id)
        except OSError as e:
            logger.warning("Impossible de sauvegarder l'ID : %s", e)

        return agent_id

    # =========================================================================
    #  DÉTECTION DE L'IP LOCALE
    # =========================================================================

    def _get_local_ip(self) -> str:
        """
        Détecte l'adresse IP locale de l'appareil Android.
        
        Returns:
            str : Adresse IP locale
        """
        import socket
        try:
            # Astuce : ouvrir un socket UDP vers une IP externe
            # sans réellement envoyer de données
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    # =========================================================================
    #  DÉMARRAGE DE L'AGENT
    # =========================================================================

    def start(self):
        """
        Démarrer l'agent Android.
        
        Séquence :
        1. Afficher la bannière
        2. Vérifier l'environnement Android
        3. Connecter au serveur
        4. Démarrer le collecteur système (thread 30s)
        5. Démarrer les threads heartbeat et reconnexion
        6. Entrer dans la boucle de collecte
        """
        print(self.BANNER)
        print(f"  Agent ID   : {self.agent_id}")
        print(f"  OS         : {self.os_type}")
        print(f"  Serveur    : {self.server_host}:{self.server_port}")
        print(f"  IP locale  : {self.ip_address}")
        print(f"  Intervalle : {self.collect_interval}s")
        print(f"  Android    : {'✅ Détecté' if is_android() else '⚠️ Non détecté (mode démo)'}")
        print()

        # Avertissement si pas sur Android
        if not is_android():
            logger.warning("⚠️  Cet agent est conçu pour Android/Termux.")
            logger.warning("    Il peut quand même fonctionner sur Linux pour le test.")
            print()

        # Connexion initiale au serveur
        logger.info("Connexion au serveur %s:%d ...", self.server_host, self.server_port)
        connected = self.sender.connect()
        if connected:
            logger.info("✅ Connecté au serveur SOC")
            # Envoyer un message d'enregistrement
            import platform as _pf
            self.sender.send_registration(
                self.agent_id,
                _pf.node() or "android",
                self.os_type,
                self.ip_address
            )
        else:
            logger.warning("⚠️  Impossible de se connecter — mode buffer activé")

        # Démarrer le collecteur système (thread dédié)
        self.system_collector.start(self._stop_event)

        # Thread de reconnexion automatique
        reconnect_thread = threading.Thread(
            target=self.sender.reconnect_loop,
            args=(self._stop_event, 10),
            daemon=True, name="AndroidReconnect"
        )
        reconnect_thread.start()

        # Thread de heartbeat toutes les 30s
        heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop,
            daemon=True, name="AndroidHeartbeat"
        )
        heartbeat_thread.start()

        # Thread d'envoi de stats système toutes les 60s
        stats_thread = threading.Thread(
            target=self._stats_loop,
            daemon=True, name="AndroidStats"
        )
        stats_thread.start()

        # Boucle de collecte principale
        logger.info("🔄 Démarrage de la boucle de collecte (intervalle: %ds)",
                     self.collect_interval)
        self._collection_loop()

    # =========================================================================
    #  BOUCLE DE COLLECTE PRINCIPALE
    # =========================================================================

    def _collection_loop(self):
        """
        Boucle principale — collecte les logs et les envoie au serveur.
        
        Toutes les N secondes :
        1. Appelle collect() sur chaque collecteur
        2. Récupère les stats système via get_latest()
        3. Construit et envoie le message JSON au serveur
        """
        while not self._stop_event.is_set():
            try:
                all_logs = []

                # Collecter depuis chaque collecteur
                for collector in self.collectors:
                    try:
                        logs = collector.collect()
                        if logs:
                            all_logs.extend(logs)
                    except Exception as e:
                        logger.error("Erreur collecteur %s : %s",
                                     type(collector).__name__, e)

                # Récupérer les stats système
                system_stats = self.system_collector.get_latest()

                # Construire le message
                timestamp = datetime.now().isoformat()

                if all_logs:
                    # Message avec logs + stats
                    message = {
                        "type": "logs",
                        "agent_id": self.agent_id,
                        "os_type": self.os_type,
                        "ip_address": self.ip_address,
                        "timestamp": timestamp,
                        "logs": all_logs
                    }
                    if system_stats:
                        message["system_stats"] = system_stats

                    self.sender.send(message)
                    logger.info("📤 Envoyé %d logs au serveur", len(all_logs))

                elif system_stats:
                    # Pas de logs, mais des stats système disponibles
                    message = {
                        "type": "system_stats",
                        "agent_id": self.agent_id,
                        "os_type": self.os_type,
                        "ip_address": self.ip_address,
                        "timestamp": timestamp,
                        "system_stats": system_stats
                    }
                    self.sender.send(message)

            except Exception as e:
                logger.error("Erreur dans la boucle de collecte : %s", e)

            # Attendre l'intervalle de collecte
            self._stop_event.wait(self.collect_interval)

    # =========================================================================
    #  HEARTBEAT
    # =========================================================================

    def _heartbeat_loop(self):
        """
        Envoie un heartbeat au serveur toutes les 30 secondes.
        Permet au serveur de savoir que l'agent est toujours en vie.
        """
        while not self._stop_event.is_set():
            self._stop_event.wait(30)
            if self._stop_event.is_set():
                break
            try:
                self.sender.send_heartbeat(self.agent_id)
            except Exception as e:
                logger.error("Erreur heartbeat : %s", e)

    # =========================================================================
    #  ENVOI DE STATS SYSTÈME (dédié)
    # =========================================================================

    def _stats_loop(self):
        """
        Envoie les stats système au serveur toutes les 60 secondes
        en tant que message dédié (type: system_stats).
        Ceci est complémentaire aux stats jointes dans les messages de logs.
        """
        while not self._stop_event.is_set():
            self._stop_event.wait(60)
            if self._stop_event.is_set():
                break
            try:
                stats = self.system_collector.get_latest()
                if stats:
                    message = {
                        "type": "system_stats",
                        "agent_id": self.agent_id,
                        "os_type": self.os_type,
                        "ip_address": self.ip_address,
                        "timestamp": datetime.now().isoformat(),
                        "system_stats": stats
                    }
                    self.sender.send(message)
            except Exception as e:
                logger.error("Erreur envoi stats système : %s", e)

    # =========================================================================
    #  ARRÊT PROPRE
    # =========================================================================

    def stop(self):
        """Arrête proprement l'agent Android."""
        logger.info("🛑 Arrêt de l'agent Android...")
        self._stop_event.set()
        self.system_collector.stop()
        self.sender.disconnect()
        logger.info("Agent Android arrêté.")


# ============================================================================
#  POINT D'ENTRÉE — CLI
# ============================================================================

def main():
    """Point d'entrée principal pour l'agent Android Termux."""
    parser = argparse.ArgumentParser(
        description="🐙 Oktopus SOC — Agent Android (Termux)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples :
  python -m agent.android_agent --server 192.168.1.100
  python -m agent.android_agent --server 10.0.0.1 --port 9999 --interval 10
  python -m agent.android_agent --agent-id ANDROID-MonTel-abc123
        """
    )

    parser.add_argument(
        "--server", default="127.0.0.1",
        help="Adresse IP du serveur SOC (défaut: 127.0.0.1)"
    )
    parser.add_argument(
        "--port", type=int, default=9999,
        help="Port TCP du serveur (défaut: 9999)"
    )
    parser.add_argument(
        "--interval", type=int, default=5,
        help="Intervalle de collecte en secondes (défaut: 5)"
    )
    parser.add_argument(
        "--agent-id", default=None,
        help="ID de l'agent (défaut: auto — ANDROID-hostname-uuid)"
    )

    args = parser.parse_args()

    # Créer et démarrer l'agent
    agent = AndroidAgent(
        server_host=args.server,
        server_port=args.port,
        collect_interval=args.interval,
        agent_id=args.agent_id
    )

    # Gestion du signal Ctrl+C pour arrêt propre
    def signal_handler(sig, frame):
        print("\n")
        agent.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    try:
        signal.signal(signal.SIGTERM, signal_handler)
    except (OSError, AttributeError):
        pass  # SIGTERM pas disponible sur tous les OS

    # Démarrer
    try:
        agent.start()
    except KeyboardInterrupt:
        agent.stop()


if __name__ == "__main__":
    main()
