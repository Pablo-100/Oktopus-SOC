"""
=============================================================================
 Oktopus Agent — Agent Principal (Orchestrateur)
=============================================================================
 Fichier : agent/agent.py
 Rôle    : Point d'entrée de l'agent Oktopus
            - Détection automatique de l'OS
            - Chargement des collecteurs appropriés
            - Boucle de collecte → envoi au serveur via TCP
            - Heartbeat périodique
            - Buffer intelligent (max 1000 logs)
            - CLI args : --server, --port, --interval, --agent-id
=============================================================================
"""

import os
import sys
import time
import json
import uuid
import select
import socket
import signal
import logging
import argparse
import platform
import threading

# Ajouter le répertoire parent au PYTHONPATH
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.sender import TCPSender
from agent.blocker import IPBlocker
from agent.collectors.linux_collector import LinuxCollector
from agent.collectors.windows_collector import WindowsCollector
from agent.collectors.network_collector import NetworkCollector
from agent.collectors.system_collector import SystemCollector

# --- Logging ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("SOC.Agent")


# --- Bannière ASCII ---
BANNER = r"""
╔══════════════════════════════════════════════════════════════╗
║        🐙 OKTOPUS AGENT — Rise from the deep                ║
║           Collecteur de logs & Envoi temps réel              ║
╚══════════════════════════════════════════════════════════════╝
"""


class SOCAgent:
    """Agent SOC — collecte des logs et les envoie au serveur."""

    def __init__(self, server_host="127.0.0.1", server_port=9999,
                 collect_interval=5, agent_id=None, config_path=None):
        """
        Args:
            server_host (str): Adresse du serveur SOC
            server_port (int): Port TCP du serveur
            collect_interval (int): Intervalle de collecte en secondes
            agent_id (str): Identifiant unique de l'agent (auto-généré si None)
            config_path (str): Chemin vers le fichier de configuration
        """
        # Config
        self.config = self._load_config(config_path)
        self.server_host = server_host or self.config.get("agent", {}).get("default_server", "127.0.0.1")
        self.server_port = server_port or self.config.get("agent", {}).get("port", 9999)
        self.collect_interval = collect_interval or self.config.get("agent", {}).get("collect_interval", 5)
        self.buffer_max = self.config.get("agent", {}).get("buffer_max", 1000)

        # Identité de l'agent
        self.hostname = socket.gethostname()
        self.os_type = platform.system().lower()  # linux / windows / darwin
        self.ip_address = self._get_local_ip()
        self.agent_id = agent_id or self._load_or_generate_agent_id()

        # Composants
        self.sender = TCPSender(
            server_host=self.server_host,
            server_port=self.server_port,
            buffer_max=self.buffer_max
        )
        self.blocker = IPBlocker()
        self.collectors = []
        self.stop_event = threading.Event()

        # Stats
        self.total_collected = 0
        self.start_time = None

        # Collecteur de statistiques système (CPU, RAM, Disque, etc.)
        self.system_collector = SystemCollector(collect_interval=30)

        # Setup collecteurs selon l'OS
        self._setup_collectors()

    def _load_config(self, config_path):
        """Charger la configuration depuis un fichier JSON."""
        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                logger.info(f"Configuration chargée: {config_path}")
                return config
            except Exception as e:
                logger.warning(f"Erreur chargement config: {e}")
        return {}

    def _get_local_ip(self):
        """Obtenir l'adresse IP locale de la machine."""
        try:
            # Astuce : se connecter à un serveur externe pour déterminer l'IP locale
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def _load_or_generate_agent_id(self):
        """
        Charge l'agent_id depuis un fichier local (agent_id.txt).
        S'il n'existe pas, en génère un nouveau et le persiste.
        Garantit un identifiant stable entre les redémarrages.
        """
        # Fichier stocké à côté du script agent
        id_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "agent_id.txt")
        id_file = os.path.normpath(id_file)

        # Tenter de lire un ID existant
        try:
            if os.path.isfile(id_file):
                with open(id_file, "r", encoding="utf-8") as f:
                    saved_id = f.read().strip()
                if saved_id:
                    logger.info(f"Agent ID chargé depuis {id_file}: {saved_id}")
                    return saved_id
        except Exception as e:
            logger.warning(f"Impossible de lire {id_file}: {e}")

        # Générer un nouvel ID et le sauvegarder
        new_id = f"{self.hostname}-{self.os_type}-{uuid.uuid4().hex[:6]}"
        try:
            with open(id_file, "w", encoding="utf-8") as f:
                f.write(new_id)
            logger.info(f"Nouvel Agent ID généré et sauvegardé: {new_id}")
        except Exception as e:
            logger.warning(f"Impossible de sauvegarder l'Agent ID dans {id_file}: {e}")

        return new_id

    def _setup_collectors(self):
        """Initialiser les collecteurs selon l'OS détecté."""
        logger.info(f"OS détecté: {self.os_type}")

        # Collecteur réseau (universel)
        net_collector = NetworkCollector(
            suspicious_ports=set(self.config.get("detection", {}).get("suspicious_ports", []))
                            or None
        )
        self.collectors.append(("network", net_collector))
        logger.info("✓ Collecteur réseau initialisé")

        if self.os_type == "linux" or self.os_type == "darwin":
            # Collecteur Linux
            linux_collector = LinuxCollector()
            self.collectors.append(("linux", linux_collector))
            logger.info("✓ Collecteur Linux initialisé")

            # Log des fichiers surveillés
            status = linux_collector.get_status()
            for src, info in status.items():
                mark = "✓" if info["readable"] else "✗"
                logger.info(f"  {mark} {src}: {info['path']}")

        elif self.os_type == "windows":
            # Collecteur Windows
            win_collector = WindowsCollector()
            self.collectors.append(("windows", win_collector))
            logger.info("✓ Collecteur Windows initialisé")

        else:
            logger.warning(f"OS non reconnu ({self.os_type}) — collecteurs limités")

    def start(self):
        """Démarrer l'agent SOC."""
        print(BANNER)
        self.start_time = time.time()

        logger.info(f"Agent ID    : {self.agent_id}")
        logger.info(f"Hostname    : {self.hostname}")
        logger.info(f"OS          : {self.os_type}")
        logger.info(f"IP          : {self.ip_address}")
        logger.info(f"Serveur     : {self.server_host}:{self.server_port}")
        logger.info(f"Intervalle  : {self.collect_interval}s")

        # Afficher l'état IPS / Blocker
        if self.blocker.has_admin:
            logger.info(f"IPS Status  : ✓ OPÉRATIONNEL (droits admin confirmés)")
        else:
            logger.warning(f"IPS Status  : ✗ NON OPÉRATIONNEL (pas de droits admin)")
            logger.warning(f"              → Relancez l'agent en tant qu'Administrateur pour activer l'IPS")
        logger.info(f"Blocker     : {self.blocker.get_stats()['os_type']} | Admin: {self.blocker.has_admin}")
        logger.info("=" * 60)

        # Connexion au serveur
        logger.info("Connexion au serveur SOC...")
        if not self.sender.connect():
            logger.warning("Connexion initiale échouée — les logs seront bufferisés")

        # Enregistrement de l'agent
        self.sender.send_registration(
            agent_id=self.agent_id,
            hostname=self.hostname,
            os_type=self.os_type,
            ip_address=self.ip_address
        )

        # Démarrer le thread de reconnexion
        reconnect_thread = threading.Thread(
            target=self.sender.reconnect_loop,
            args=(self.stop_event, 10),
            daemon=True,
            name="Reconnect"
        )
        reconnect_thread.start()

        # Démarrer le thread de heartbeat
        heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop,
            daemon=True,
            name="Heartbeat"
        )
        heartbeat_thread.start()

        # Démarrer le thread des stats
        stats_thread = threading.Thread(
            target=self._stats_loop,
            daemon=True,
            name="Stats"
        )
        stats_thread.start()

        # Démarrer le thread d'écoute des commandes serveur (IPS)
        command_thread = threading.Thread(
            target=self._command_listener_loop,
            daemon=True,
            name="CommandListener"
        )
        command_thread.start()

        # Démarrer le collecteur de statistiques système (30s)
        self.system_collector.start(self.stop_event)
        logger.info("✓ Collecteur système démarré (intervalle: 30s)")

        # Boucle principale de collecte
        logger.info("Démarrage de la collecte...")
        self._collection_loop()

    def _collection_loop(self):
        """Boucle principale : collecte → envoi."""
        while not self.stop_event.is_set():
            try:
                all_logs = []

                # Collecter depuis tous les collecteurs
                for name, collector in self.collectors:
                    try:
                        logs = collector.collect()
                        if logs:
                            all_logs.extend(logs)
                    except Exception as e:
                        logger.error(f"Erreur collecteur {name}: {e}")

                # Récupérer les dernières statistiques système
                system_stats = self.system_collector.get_latest()

                # Envoyer les logs collectés (avec stats système si disponibles)
                if all_logs:
                    self.total_collected += len(all_logs)
                    msg = {
                        "type": "logs",
                        "agent_id": self.agent_id,
                        "os_type": self.os_type,
                        "ip_address": self.ip_address,
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "logs": all_logs
                    }
                    # Joindre les stats système au message de logs
                    if system_stats:
                        msg["system_stats"] = system_stats
                    self.sender.send(msg)
                    logger.debug(f"Envoyé {len(all_logs)} logs (total: {self.total_collected})")
                elif system_stats:
                    # Pas de logs mais des stats système → envoyer quand même
                    msg = {
                        "type": "system_stats",
                        "agent_id": self.agent_id,
                        "os_type": self.os_type,
                        "ip_address": self.ip_address,
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "system_stats": system_stats
                    }
                    self.sender.send(msg)

                # Attendre l'intervalle
                self.stop_event.wait(self.collect_interval)

            except Exception as e:
                logger.error(f"Erreur boucle de collecte: {e}")
                self.stop_event.wait(self.collect_interval)

    def _heartbeat_loop(self):
        """Envoyer un heartbeat régulier au serveur."""
        while not self.stop_event.is_set():
            self.stop_event.wait(30)  # Heartbeat toutes les 30 secondes
            if not self.stop_event.is_set():
                self.sender.send_heartbeat(self.agent_id)

    def _stats_loop(self):
        """Afficher les statistiques périodiquement."""
        while not self.stop_event.is_set():
            self.stop_event.wait(60)  # Stats toutes les 60 secondes
            if not self.stop_event.is_set():
                uptime = int(time.time() - self.start_time)
                sender_stats = self.sender.get_stats()
                blocker_stats = self.blocker.get_stats()
                logger.info(
                    f"[STATS] Uptime: {uptime}s | "
                    f"Collectés: {self.total_collected} | "
                    f"Envoyés: {sender_stats['total_sent']} | "
                    f"Buffer: {sender_stats['buffered']} | "
                    f"Bloquées: {blocker_stats['active_blocks']} | "
                    f"Connecté: {'Oui' if sender_stats['connected'] else 'Non'}"
                )

    def _command_listener_loop(self):
        """
        Écoute les commandes envoyées par le serveur via le socket TCP existant.
        Le serveur peut envoyer des commandes JSON de type block_ip / unblock_ip.
        Utilise select() pour ne PAS modifier le timeout du socket sender.
        """
        logger.info("[CMD] Thread d'écoute des commandes serveur démarré")
        buffer = ""

        while not self.stop_event.is_set():
            try:
                # Utiliser le socket du sender
                sock = self.sender.socket
                if not sock or not self.sender.connected:
                    self.stop_event.wait(2)
                    buffer = ""  # reset buffer on reconnect
                    continue

                # Utiliser select pour savoir si des données sont disponibles
                # SANS modifier le timeout du socket (évite conflit avec sender)
                try:
                    ready, _, _ = select.select([sock], [], [], 1.0)
                except (ValueError, OSError):
                    # Socket fermé pendant le select
                    self.stop_event.wait(2)
                    buffer = ""
                    continue

                if not ready:
                    continue  # Pas de données, on reboucle

                try:
                    data = sock.recv(4096)
                    if not data:
                        self.stop_event.wait(1)
                        continue

                    buffer += data.decode("utf-8", errors="replace")

                    # Traiter les messages complets
                    while "\n" in buffer:
                        line, buffer = buffer.split("\n", 1)
                        line = line.strip()
                        if not line:
                            continue
                        self._handle_server_command(line)

                except socket.timeout:
                    continue
                except (ConnectionResetError, ConnectionAbortedError, OSError):
                    self.stop_event.wait(2)
                    buffer = ""
                    continue

            except Exception as e:
                logger.error(f"[CMD] Erreur listener commandes : {e}")
                self.stop_event.wait(5)

    def _handle_server_command(self, raw_message: str):
        """
        Traite une commande JSON reçue du serveur.
        
        Commandes supportées :
        - block_ip   : Bloquer une IP dans le firewall
        - unblock_ip : Débloquer une IP
        - ips_status : Retourner l'état du blocker IPS
        """
        try:
            command = json.loads(raw_message)
            action = command.get("action", "")

            if action == "block_ip":
                ip = command.get("ip")
                reason = command.get("reason", "")
                severity = command.get("severity", "")
                duration = command.get("duration_minutes", 0)

                if ip:
                    logger.info(f"[CMD] Commande BLOCK reçue : {ip} ({reason})")
                    result = self.blocker.block_ip(
                        ip=ip,
                        reason=reason,
                        severity=severity,
                        duration_minutes=duration
                    )
                    # Envoyer la confirmation au serveur
                    self.sender.send({
                        "type": "ips_response",
                        "agent_id": self.agent_id,
                        "action": "block_ip",
                        "ip": ip,
                        "success": result.get("success", False),
                        "message": result.get("message", ""),
                        "has_admin": self.blocker.has_admin
                    })

            elif action == "unblock_ip":
                ip = command.get("ip")
                reason = command.get("reason", "")

                if ip:
                    logger.info(f"[CMD] Commande UNBLOCK reçue : {ip} ({reason})")
                    result = self.blocker.unblock_ip(ip=ip, reason=reason)
                    # Envoyer la confirmation au serveur
                    self.sender.send({
                        "type": "ips_response",
                        "agent_id": self.agent_id,
                        "action": "unblock_ip",
                        "ip": ip,
                        "success": result.get("success", False),
                        "message": result.get("message", ""),
                        "has_admin": self.blocker.has_admin
                    })

            elif action == "ips_status":
                # Retourner l'état complet du blocker
                stats = self.blocker.get_stats()
                self.sender.send({
                    "type": "ips_response",
                    "agent_id": self.agent_id,
                    "action": "ips_status",
                    "stats": stats,
                    "has_admin": self.blocker.has_admin
                })

            else:
                logger.warning(f"[CMD] Commande inconnue : {action}")

        except json.JSONDecodeError:
            # Pas un JSON — ignorer (peut être un autre protocole)
            pass
        except Exception as e:
            logger.error(f"[CMD] Erreur traitement commande : {e}")

    def stop(self):
        """Arrêter l'agent proprement."""
        logger.info("Arrêt de l'agent SOC...")
        self.stop_event.set()

        # Nettoyer les règles firewall créées par l'IPS
        logger.info("Nettoyage des règles IPS...")
        self.blocker.cleanup_all()

        # Vider le buffer restant
        logger.info("Envoi des logs restants en buffer...")
        self.sender._flush_buffer()

        # Déconnexion
        self.sender.disconnect()

        uptime = int(time.time() - self.start_time) if self.start_time else 0
        logger.info(f"Agent arrêté. Uptime: {uptime}s | Logs collectés: {self.total_collected}")


def parse_args():
    """Parser les arguments CLI."""
    parser = argparse.ArgumentParser(
        description="Oktopus Agent — Collecteur de logs sécurité",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  python -m agent.agent
  python -m agent.agent --server 192.168.1.100 --port 9999
  python -m agent.agent --interval 10 --agent-id "serveur-web-01"
  python -m agent.agent --config config/rules.json
        """
    )
    parser.add_argument("--server", default="127.0.0.1",
                        help="Adresse du serveur Oktopus (défaut: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=9999,
                        help="Port TCP du serveur (défaut: 9999)")
    parser.add_argument("--interval", type=int, default=5,
                        help="Intervalle de collecte en secondes (défaut: 5)")
    parser.add_argument("--agent-id",
                        help="Identifiant de l'agent (auto-généré si non spécifié)")
    parser.add_argument("--config", default=None,
                        help="Chemin vers le fichier de configuration JSON")
    return parser.parse_args()


def main():
    """Point d'entrée principal de l'agent."""
    args = parse_args()

    # Chercher le config par défaut
    config_path = args.config
    if not config_path:
        default_configs = [
            os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "rules.json"),
            "config/rules.json",
            "../config/rules.json"
        ]
        for path in default_configs:
            if os.path.exists(path):
                config_path = path
                break

    agent = SOCAgent(
        server_host=args.server,
        server_port=args.port,
        collect_interval=args.interval,
        agent_id=args.agent_id,
        config_path=config_path
    )

    # Signal handler pour arrêt propre
    def signal_handler(sig, frame):
        print()
        agent.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, signal_handler)

    # Démarrer
    try:
        agent.start()
    except KeyboardInterrupt:
        agent.stop()


if __name__ == "__main__":
    main()
