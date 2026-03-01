"""
=============================================================================
 Oktopus — Serveur TCP Principal (Orchestrateur)
=============================================================================
 Fichier : server/server.py
 Rôle    : Serveur TCP qui orchestre l'ensemble du SOC :
           - Écoute sur 0.0.0.0:9999, accepte les connexions agents
           - Pour chaque message : parse → détecte → stocke → broadcast
           - Gère le heartbeat et la détection d'agents déconnectés
           - Lance le serveur WebSocket en parallèle
 
 Auteur  : Oktopus Team
 Date    : 2026-02-27
 Python  : 3.8+
=============================================================================
"""

import socket
import threading
import json
import os
import sys
import time
import signal
from datetime import datetime
from typing import Dict, Optional

# Ajouter le dossier parent au path pour les imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server.database import SOCDatabase
from server.parser import LogParser
from server.detector import ThreatDetector
from server.ws_server import WebSocketServer
from server.ips_engine import IPSEngine
from server.geo_ip import GeoIPLookup


class SOCServer:
    """
    Serveur principal du SOC — orchestre tous les composants.
    
    Architecture :
    - Thread principal      : Serveur TCP (accepte les agents)
    - Thread par agent      : Réception des logs en continu
    - Thread WebSocket      : Broadcast vers les dashboards
    - Thread heartbeat      : Vérification des agents actifs
    - Thread stats          : Mise à jour périodique des stats
    
    Attributs :
        host       : Adresse d'écoute TCP
        port       : Port TCP (défaut: 9999)
        ws_port    : Port WebSocket (défaut: 8765)
        db         : Instance SOCDatabase
        parser     : Instance LogParser
        detector   : Instance ThreatDetector
        ws_server  : Instance WebSocketServer
        clients    : Dict des agents connectés {agent_id: socket}
    """

    def __init__(self, config_path: str = None):
        """
        Initialise le serveur SOC avec tous ses composants.
        
        Args:
            config_path : Chemin vers le fichier de configuration
        """
        # --- Charger la configuration ---
        self.config = self._load_config(config_path)
        
        self.host = "0.0.0.0"
        self.port = self.config.get("server", {}).get("tcp_port", 9999)
        self.ws_port = self.config.get("server", {}).get("ws_port", 8765)
        db_path = self.config.get("server", {}).get("db_path", "soc.db")

        # --- Initialiser les composants ---
        self._print_banner()
        
        self.db = SOCDatabase(db_path)
        self.parser = LogParser()
        self.detector = ThreatDetector(config_path)
        self.geo_ip = GeoIPLookup()
        self.ws_server = WebSocketServer(
            host=self.host, 
            port=self.ws_port, 
            database=self.db
        )

        # --- État du serveur ---
        self.running = False
        self.server_socket: Optional[socket.socket] = None
        self.clients: Dict[str, Dict] = {}  # {agent_id: {socket, ip, os, last_seen}}
        self.clients_lock = threading.Lock()

        # --- Moteur IPS ---
        self.ips_engine = IPSEngine(
            database=self.db,
            ws_server=self.ws_server,
            clients=self.clients,
            clients_lock=self.clients_lock,
            config=self.config
        )
        # Donner la référence IPS au ws_server pour les commandes dashboard
        self.ws_server.ips_engine = self.ips_engine

        # Compteurs
        self.total_logs_received = 0
        self.total_alerts_generated = 0

        # --- Suivi des connexions avec données malformées ---
        self._parse_failures: Dict[str, list] = {}   # {ip: [timestamps]}
        self._parse_failure_lock = threading.Lock()
        self._parse_failure_alerted: Dict[str, float] = {}  # anti-spam {ip: last_alert_ts}

    def _load_config(self, config_path: str = None) -> Dict:
        """
        Charge le fichier de configuration.
        
        Args:
            config_path : Chemin vers rules.json
        
        Returns:
            Dict : Configuration
        """
        if not config_path:
            # Chercher dans les emplacements standards
            possible_paths = [
                os.path.join(os.path.dirname(__file__), "..", "config", "rules.json"),
                os.path.join(os.path.dirname(__file__), "config", "rules.json"),
                "config/rules.json",
            ]
            for path in possible_paths:
                if os.path.exists(path):
                    config_path = path
                    break

        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                print(f"\033[91m[SERVER ERREUR]\033[0m Config invalide : {e}")
        
        # Config par défaut
        return {
            "server": {"tcp_port": 9999, "ws_port": 8765, "db_path": "soc.db"},
            "detection": {"brute_force_threshold": 5, "brute_force_window_seconds": 60}
        }

    def _print_banner(self):
        """Affiche la bannière ASCII d'Oktopus au démarrage."""
        banner = """
\033[96m
  ██████╗ ██╗  ██╗████████╗ ██████╗ ██████╗ ██╗   ██╗███████╗
 ██╔═══██╗██║ ██╔╝╚══██╔══╝██╔═══██╗██╔══██╗██║   ██║██╔════╝
 ██║   ██║█████╔╝    ██║   ██║   ██║██████╔╝██║   ██║███████╗
 ██║   ██║██╔═██╗    ██║   ██║   ██║██╔═══╝ ██║   ██║╚════██║
 ╚██████╔╝██║  ██╗   ██║   ╚██████╔╝██║     ╚██████╔╝███████║
  ╚═════╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝      ╚═════╝ ╚══════╝
\033[0m
\033[93m  🐙 Rise from the deep. Crush every threat.\033[0m
\033[90m  ─────────────────────────────────────────────────────────\033[0m
"""
        print(banner)

    # =========================================================================
    #  DÉMARRAGE DU SERVEUR
    # =========================================================================

    def start(self):
        """
        Démarre le serveur SOC complet :
        1. Serveur WebSocket (thread séparé)
        2. Thread heartbeat (vérification agents)
        3. Thread stats (broadcast périodique)
        4. Serveur TCP (thread principal — bloquant)
        """
        self.running = True

        # Gérer Ctrl+C proprement
        signal.signal(signal.SIGINT, self._signal_handler)

        # 1. Démarrer le serveur WebSocket
        self.ws_server.start()
        # Attendre que la boucle asyncio du WS soit réellement prête
        if not self.ws_server._loop_ready.wait(timeout=5):
            print("\033[93m[SERVER]\033[0m Attention : la boucle WebSocket n'est pas encore prête")

        # 2. Démarrer le thread heartbeat
        heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop, daemon=True
        )
        heartbeat_thread.start()

        # 3. Démarrer le thread de broadcast stats
        stats_thread = threading.Thread(
            target=self._stats_broadcast_loop, daemon=True
        )
        stats_thread.start()

        # 4. Démarrer le thread de nettoyage périodique
        cleanup_thread = threading.Thread(
            target=self._cleanup_loop, daemon=True
        )
        cleanup_thread.start()

        # 5. Démarrer le thread IPS auto-unblock
        self.stop_event = threading.Event()
        self.ips_engine.start_auto_unblock(self.stop_event)

        # 6. Serveur TCP (bloquant)
        self._start_tcp_server()

    def _start_tcp_server(self):
        """
        Démarre le serveur TCP et accepte les connexions des agents.
        Chaque agent est géré dans un thread séparé.
        """
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.settimeout(1.0)  # Timeout pour pouvoir vérifier self.running
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(50)  # Max 50 connexions en attente

            print(f"\033[92m[SERVER]\033[0m Serveur TCP démarré sur {self.host}:{self.port}")
            print(f"\033[92m[SERVER]\033[0m En attente de connexions agents...")
            print(f"\033[90m[SERVER]\033[0m Dashboard : ouvrir dashboard/index.html dans le navigateur")
            print(f"\033[90m[SERVER]\033[0m Ctrl+C pour arrêter\n")

            while self.running:
                try:
                    client_socket, address = self.server_socket.accept()
                    client_ip = address[0]

                    # === REJET TCP — refuser les connexions des IPs bloquées ===
                    if self.ips_engine and self.ips_engine.is_ip_locally_blocked(client_ip):
                        print(f"\033[91m[SERVER IPS]\033[0m 🚫 Connexion REFUSÉE "
                              f"de {client_ip}:{address[1]} (IP bloquée)")
                        try:
                            client_socket.close()
                        except Exception:
                            pass
                        continue
                    
                    print(f"\033[92m[SERVER]\033[0m Nouvelle connexion depuis {client_ip}:{address[1]}")

                    # Lancer un thread pour ce client
                    client_thread = threading.Thread(
                        target=self._handle_agent,
                        args=(client_socket, address),
                        daemon=True
                    )
                    client_thread.start()

                except socket.timeout:
                    continue  # Timeout normal, on continue la boucle
                except OSError:
                    if self.running:
                        raise
                    break

        except Exception as e:
            print(f"\033[91m[SERVER ERREUR]\033[0m Erreur TCP : {e}")
        finally:
            self.stop()

    # =========================================================================
    #  GESTION DES AGENTS
    # =========================================================================

    def _handle_agent(self, client_socket: socket.socket, address: tuple):
        """
        Gère la communication avec un agent connecté.
        
        Protocole :
        - L'agent envoie des messages JSON terminés par \\n
        - Chaque message est parsé, analysé, stocké et broadcasté
        - La connexion reste ouverte en continu
        
        Args:
            client_socket : Socket du client
            address       : Tuple (ip, port)
        """
        client_ip = address[0]
        agent_id = None
        buffer = ""

        try:
            client_socket.settimeout(120)  # Timeout 2 min (heartbeat toutes les 30s)

            while self.running:
                try:
                    data = client_socket.recv(65536)
                    if not data:
                        break  # Client déconnecté

                    # Vérifier si l'IP a été bloquée pendant la connexion
                    if self.ips_engine and self.ips_engine.is_ip_locally_blocked(client_ip):
                        print(f"\033[91m[SERVER IPS]\033[0m 🔌 Connexion existante de "
                              f"{client_ip} fermée (IP bloquée)")
                        break

                    buffer += data.decode("utf-8", errors="replace")

                    # Traiter tous les messages complets (séparés par \n)
                    while "\n" in buffer:
                        message, buffer = buffer.split("\n", 1)
                        message = message.strip()
                        if not message:
                            continue

                        # Traiter le message
                        agent_id = self._process_message(message, client_ip, client_socket)

                except socket.timeout:
                    # Vérifier si l'agent est toujours là
                    if agent_id:
                        print(f"\033[93m[SERVER]\033[0m Timeout agent {agent_id} — en attente...")
                    continue

                except ConnectionResetError:
                    break
                except UnicodeDecodeError:
                    continue

        except Exception as e:
            print(f"\033[91m[SERVER ERREUR]\033[0m Erreur avec {client_ip} : {e}")
        finally:
            # Déconnexion de l'agent
            client_socket.close()
            if agent_id:
                with self.clients_lock:
                    if agent_id in self.clients:
                        del self.clients[agent_id]
                self.db.update_agent_status(agent_id, "inactive")
                print(f"\033[91m[SERVER]\033[0m Agent déconnecté : {agent_id} ({client_ip})")
                
                # Notifier les dashboards
                agents = self.db.get_all_agents()
                self.ws_server.broadcast_agent_update(agents)

    def _process_message(self, raw_message: str, client_ip: str,
                         client_socket: socket.socket) -> Optional[str]:
        """
        Traite un message JSON reçu d'un agent.
        
        Pipeline :
        1. Parser (normaliser les logs)
        2. Détecter (chercher des menaces)
        3. Stocker (sauvegarder en DB)
        4. Broadcaster (envoyer au dashboard)
        
        Args:
            raw_message   : Message JSON brut
            client_ip     : IP de l'agent
            client_socket : Socket de l'agent
        
        Returns:
            str : agent_id si identifié, None sinon
        """
        # --- 1. PARSING ---
        parsed = self.parser.parse_agent_message(raw_message)
        if not parsed:
            # ── DÉTECTION : données malformées (scan, fuzzing, attaque) ──
            self._track_parse_failure(client_ip, raw_message)
            return None

        agent_id = parsed.get("agent_id", "unknown")
        agent_os = parsed.get("os", "unknown")
        agent_ip = parsed.get("ip", client_ip)

        # --- Enregistrer/mettre à jour l'agent ---
        # Ne pas écraser les bonnes valeurs avec des valeurs par défaut
        if agent_os not in ("unknown", "") or agent_ip not in ("0.0.0.0", ""):
            self.db.register_agent(agent_id, agent_ip, agent_os)
        else:
            # Heartbeat ou message sans info OS/IP → juste mettre à jour last_seen
            self.db.update_agent_heartbeat(agent_id)
        
        with self.clients_lock:
            self.clients[agent_id] = {
                "socket": client_socket,
                "ip": agent_ip,
                "os": agent_os,
                "last_seen": datetime.now()
            }

        # --- Heartbeat : pas de logs à traiter ---
        if parsed.get("type") == "heartbeat":
            self.db.update_agent_heartbeat(agent_id)
            return agent_id

        # --- Register / IPS Response : pas de logs à traiter ---
        if parsed.get("type") in ("register", "ips_response"):
            return agent_id

        # --- Statistiques système de l'agent ---
        system_stats = parsed.get("system_stats")
        if system_stats:
            self._process_system_stats(agent_id, system_stats)

        # --- Message dédié aux stats système (sans logs) ---
        if parsed.get("type") == "system_stats":
            return agent_id

        # --- 2-3-4. Traiter chaque log ---
        for log in parsed.get("logs", []):
            self._process_single_log(log, agent_id, agent_ip, agent_os, raw_message)

        # Mettre à jour les stats pour le dashboard
        if parsed.get("logs"):
            stats = self.db.get_stats()
            self.ws_server.broadcast_stats(stats)

        return agent_id

    def _process_single_log(self, log: Dict, agent_id: str, agent_ip: str,
                            agent_os: str, raw_message: str):
        """
        Traite un log individuel : stockage → détection → broadcast.
        
        Args:
            log         : Log normalisé
            agent_id    : ID de l'agent
            agent_ip    : IP de l'agent
            agent_os    : OS de l'agent
            raw_message : Message brut complet
        """
        # --- STOCKER dans SQLite ---
        log_id = self.db.insert_log(
            timestamp=log.get("timestamp", datetime.now().isoformat()),
            agent_id=agent_id,
            agent_ip=agent_ip,
            agent_os=agent_os,
            source=log.get("source", ""),
            level=log.get("level", "INFO"),
            category=log.get("category", ""),
            message=log.get("message", ""),
            raw_json=log.get("raw_json", raw_message[:500])
        )

        self.total_logs_received += 1

        # Afficher dans le terminal du serveur
        level = log.get("level", "INFO")
        level_colors = {
            "INFO": "\033[37m",      # Gris
            "WARNING": "\033[33m",   # Orange
            "HIGH": "\033[91m",      # Rouge
            "CRITICAL": "\033[91;1m" # Rouge gras
        }
        color = level_colors.get(level, "\033[37m")
        
        print(f"{color}[LOG {level:8}]\033[0m "
              f"\033[94m{agent_id:20}\033[0m "
              f"{log.get('message', '')[:80]}")

        # --- BROADCAST vers le dashboard ---
        log_data = {
            "id": log_id,
            "timestamp": log.get("timestamp", ""),
            "agent_id": agent_id,
            "agent_ip": agent_ip,
            "agent_os": agent_os,
            "source": log.get("source", ""),
            "level": level,
            "category": log.get("category", ""),
            "message": log.get("message", "")
        }
        self.ws_server.broadcast_log(log_data)

        # --- DÉTECTION des menaces ---
        alerts = self.detector.analyze(log)
        
        for alert in alerts:
            alert_id = self.db.insert_alert(
                timestamp=alert.get("timestamp", datetime.now().isoformat()),
                agent_id=agent_id,
                rule_name=alert.get("rule_name", "UNKNOWN"),
                severity=alert.get("severity", "MEDIUM"),
                message=alert.get("message", ""),
                log_id=log_id,
                alert_type=alert.get("type", ""),
                mitre_tactic=alert.get("mitre_tactic", ""),
                mitre_technique_id=alert.get("mitre_technique_id", ""),
                mitre_technique_name=alert.get("mitre_technique_name", "")
            )
            self.total_alerts_generated += 1

            # Broadcast l'alerte
            alert_data = {
                "id": alert_id,
                "timestamp": alert.get("timestamp", ""),
                "agent_id": agent_id,
                "rule_name": alert.get("rule_name", ""),
                "severity": alert.get("severity", ""),
                "type": alert.get("type", ""),
                "message": alert.get("message", ""),
                "log_id": log_id,
                "resolved": 0,
                "mitre_tactic": alert.get("mitre_tactic", ""),
                "mitre_technique_id": alert.get("mitre_technique_id", ""),
                "mitre_technique_name": alert.get("mitre_technique_name", "")
            }
            self.ws_server.broadcast_alert(alert_data)

            # --- GEO-IP : géolocaliser l'IP attaquante ---
            try:
                ip = self.geo_ip.extract_ip_from_alert(alert)
                if ip:
                    geo = self.geo_ip.lookup(ip)
                    if geo:
                        geo_event = {
                            "timestamp": alert.get("timestamp", datetime.now().isoformat()),
                            "ip": ip,
                            "country": geo["country"],
                            "country_code": geo["country_code"],
                            "city": geo["city"],
                            "lat": geo["lat"],
                            "lon": geo["lon"],
                            "flag": geo.get("flag", ""),
                            "alert_type": alert.get("type", ""),
                            "severity": alert.get("severity", ""),
                            "agent_id": agent_id,
                            "rule_name": alert.get("rule_name", "")
                        }
                        self.db.insert_geo_event(
                            timestamp=geo_event["timestamp"],
                            ip=ip,
                            country=geo["country"],
                            country_code=geo["country_code"],
                            city=geo["city"],
                            lat=geo["lat"],
                            lon=geo["lon"],
                            alert_type=geo_event["alert_type"],
                            severity=geo_event["severity"],
                            agent_id=agent_id
                        )
                        self.ws_server.broadcast_geo_event(geo_event)
            except Exception as geo_err:
                print(f"\033[93m[GEO-IP WARN]\033[0m {geo_err}")

            # --- IPS : décider de bloquer ou non ---
            try:
                self.ips_engine.process_alert(alert, agent_id, alert_id)
            except Exception as ips_err:
                print(f"\033[91m[IPS ERREUR]\033[0m process_alert : {ips_err}")

    # =========================================================================
    #  TRAITEMENT DES STATISTIQUES SYSTÈME (CPU, RAM, Disque, etc.)
    # =========================================================================

    def _process_system_stats(self, agent_id: str, stats: Dict):
        """
        Traite les statistiques système envoyées par un agent.
        
        Pipeline :
        1. Sauvegarder dans la table agent_stats
        2. Broadcaster aux dashboards via WebSocket
        
        Args:
            agent_id : Identifiant de l'agent
            stats    : Dictionnaire des statistiques système
        """
        try:
            # Sauvegarder en base de données
            self.db.insert_agent_stats(agent_id, stats)

            # Broadcaster aux dashboards connectés
            self.ws_server.broadcast_agent_stats({
                "agent_id": agent_id,
                "stats": stats
            })

            # Log discret dans le terminal serveur
            cpu = stats.get("cpu", {}).get("percent", "?")
            ram = stats.get("ram", {}).get("percent", "?")
            print(f"\033[96m[SYSTEM STATS]\033[0m "
                  f"\033[94m{agent_id:20}\033[0m "
                  f"CPU: {cpu}% | RAM: {ram}%")

        except Exception as e:
            print(f"\033[91m[SERVER ERREUR]\033[0m Traitement stats système : {e}")

    # =========================================================================
    #  DÉTECTION DES CONNEXIONS MALFORMÉES (SCAN / FUZZING / ATTAQUE)
    # =========================================================================

    def _track_parse_failure(self, client_ip: str, raw_message: str):
        """
        Suit les échecs de parsing JSON par IP source.
        
        Si une IP envoie trop de données malformées en peu de temps,
        c'est un signe de scan, fuzzing ou tentative d'attaque.
        
        Seuils :
        - 5 échecs en 60 secondes → alerte CRITICAL
        - Anti-spam : max 1 alerte par IP toutes les 120 secondes
        
        Args:
            client_ip   : IP source de la connexion
            raw_message : Données brutes reçues (pour l'analyse)
        """
        now = time.time()
        window = 60       # Fenêtre de détection : 60 secondes
        threshold = 5     # Nombre d'échecs pour déclencher l'alerte
        cooldown = 120    # Anti-spam : 1 alerte par IP toutes les 2 minutes

        with self._parse_failure_lock:
            # Initialiser le suivi pour cette IP
            if client_ip not in self._parse_failures:
                self._parse_failures[client_ip] = []

            # Ajouter l'échec courant
            self._parse_failures[client_ip].append(now)

            # Nettoyer les entrées hors fenêtre
            self._parse_failures[client_ip] = [
                t for t in self._parse_failures[client_ip] if now - t < window
            ]

            count = len(self._parse_failures[client_ip])

            # Vérifier anti-spam
            last_alert = self._parse_failure_alerted.get(client_ip, 0)
            if count >= threshold and (now - last_alert) > cooldown:
                self._parse_failure_alerted[client_ip] = now
                # Générer l'alerte en dehors du lock
                self._generate_malformed_flood_alert(client_ip, count, raw_message)

    def _generate_malformed_flood_alert(self, client_ip: str, count: int,
                                         sample: str):
        """
        Génère une alerte MALFORMED_DATA_FLOOD + log + broadcast + IPS.
        
        Détecte les IP qui envoient des données non-JSON en masse,
        signe typique de :
        - Scanner de ports (nmap, masscan)
        - Fuzzing (essayer des payloads aléatoires)
        - Tentative d'exploitation (buffer overflow, etc.)
        - Reconnaissance réseau
        
        Args:
            client_ip : IP source
            count     : Nombre d'échecs dans la fenêtre
            sample    : Échantillon des données malformées
        """
        timestamp = datetime.now().isoformat()
        safe_sample = sample[:200].replace('\n', ' ').replace('\r', '')

        print(f"\033[91;1m[🚨 ALERTE CRITIQUE]\033[0m "
              f"MALFORMED_DATA_FLOOD depuis \033[93m{client_ip}\033[0m "
              f"— {count} données invalides en 60s")

        # 1. Stocker un log synthétique
        log_id = self.db.insert_log(
            timestamp=timestamp,
            agent_id="SERVER-IDS",
            agent_ip=client_ip,
            agent_os="unknown",
            source="TCP-LISTENER",
            level="CRITICAL",
            category="SECURITY",
            message=(f"Flood de données malformées depuis {client_ip} "
                     f"— {count} tentatives en 60s. "
                     f"Échantillon : {safe_sample}"),
            raw_json=sample[:500]
        )

        # 2. Broadcast le log au dashboard
        log_data = {
            "id": log_id,
            "timestamp": timestamp,
            "agent_id": "SERVER-IDS",
            "agent_ip": client_ip,
            "agent_os": "unknown",
            "source": "TCP-LISTENER",
            "level": "CRITICAL",
            "category": "SECURITY",
            "message": (f"Flood de données malformées depuis {client_ip} "
                        f"— {count} tentatives en 60s")
        }
        self.ws_server.broadcast_log(log_data)
        self.total_logs_received += 1

        # 3. Créer l'alerte
        alert_msg = (f"[INTRUSION] {client_ip} envoie des données non-JSON "
                     f"en masse ({count} en 60s). "
                     f"Possible scan/fuzzing/attaque. "
                     f"Données : {safe_sample}")

        alert_id = self.db.insert_alert(
            timestamp=timestamp,
            agent_id="SERVER-IDS",
            rule_name="MALFORMED_DATA_FLOOD",
            severity="CRITICAL",
            message=alert_msg,
            log_id=log_id,
            alert_type="MALFORMED_DATA_FLOOD",
            mitre_tactic="Impact",
            mitre_technique_id="T1498",
            mitre_technique_name="Network Denial of Service"
        )
        self.total_alerts_generated += 1

        # 4. Broadcast l'alerte au dashboard
        alert_data = {
            "id": alert_id,
            "timestamp": timestamp,
            "agent_id": "SERVER-IDS",
            "rule_name": "MALFORMED_DATA_FLOOD",
            "severity": "CRITICAL",
            "type": "MALFORMED_DATA_FLOOD",
            "message": alert_msg,
            "log_id": log_id,
            "resolved": 0,
            "mitre_tactic": "Impact",
            "mitre_technique_id": "T1498",
            "mitre_technique_name": "Network Denial of Service"
        }
        self.ws_server.broadcast_alert(alert_data)

        # Geo-IP pour MALFORMED_DATA_FLOOD
        try:
            geo_result = self.geo_ip.lookup(client_ip)
            if geo_result:
                self.db.insert_geo_event(
                    timestamp=timestamp,
                    ip=client_ip,
                    country=geo_result.get('country', ''),
                    country_code=geo_result.get('country_code', ''),
                    city=geo_result.get('city', ''),
                    lat=geo_result.get('lat', 0),
                    lon=geo_result.get('lon', 0),
                    alert_type='MALFORMED_DATA_FLOOD',
                    severity='CRITICAL',
                    agent_id='SERVER-IDS'
                )
                geo_event = {
                    'timestamp': timestamp,
                    'ip': client_ip,
                    'country': geo_result.get('country', ''),
                    'country_code': geo_result.get('country_code', ''),
                    'city': geo_result.get('city', ''),
                    'lat': geo_result.get('lat', 0),
                    'lon': geo_result.get('lon', 0),
                    'flag': geo_result.get('flag', ''),
                    'alert_type': 'MALFORMED_DATA_FLOOD',
                    'severity': 'CRITICAL',
                    'agent_id': 'SERVER-IDS'
                }
                self.ws_server.broadcast_geo_event(geo_event)
        except Exception as e:
            print(f"\033[93m[GEO-IP]\033[0m Erreur geo MALFORMED: {e}")

        # 5. IPS — tenter de bloquer l'IP
        ips_alert = {
            "timestamp": timestamp,
            "agent_id": "SERVER-IDS",
            "rule_name": "MALFORMED_DATA_FLOOD",
            "severity": "CRITICAL",
            "type": "MALFORMED_DATA_FLOOD",
            "message": (f"Flood de données malformées depuis {client_ip} "
                        f"({count} tentatives). Source IP: {client_ip}"),
            "source_ip": client_ip
        }
        try:
            self.ips_engine.process_alert(ips_alert, "SERVER-IDS", alert_id)
        except Exception as e:
            print(f"\033[91m[IPS ERREUR]\033[0m process_alert "
                  f"MALFORMED_DATA_FLOOD : {e}")

        # 6. Mettre à jour les stats
        stats = self.db.get_stats()
        self.ws_server.broadcast_stats(stats)

    # =========================================================================
    #  THREADS DE MAINTENANCE
    # =========================================================================

    def _heartbeat_loop(self):
        """
        Vérifie périodiquement (toutes les 30s) les agents actifs.
        Marque comme inactifs ceux qui n'ont pas envoyé de heartbeat.
        """
        while self.running:
            time.sleep(30)
            try:
                # Marquer les agents inactifs (pas de signe de vie > 90s)
                count = self.db.mark_inactive_agents(timeout_seconds=90)
                
                if count > 0:
                    # Notifier les dashboards
                    agents = self.db.get_all_agents()
                    self.ws_server.broadcast_agent_update(agents)
                
            except Exception as e:
                print(f"\033[91m[HEARTBEAT ERREUR]\033[0m {e}")

    def _stats_broadcast_loop(self):
        """
        Broadcast les statistiques toutes les 10 secondes.
        Permet au dashboard de rester à jour même sans nouveaux logs.
        """
        while self.running:
            time.sleep(10)
            try:
                stats = self.db.get_stats()
                stats["ws_clients"] = self.ws_server.get_client_count()
                stats["connected_agents"] = len(self.clients)
                stats["total_logs_received"] = self.total_logs_received
                stats["total_alerts_generated"] = self.total_alerts_generated
                # Ajouter les stats IPS
                stats["ips"] = self.ips_engine.get_stats()
                self.ws_server.broadcast_stats(stats)
            except Exception as e:
                print(f"\033[91m[STATS ERREUR]\033[0m {e}")

    def _cleanup_loop(self):
        """
        Nettoyage périodique (toutes les 5 minutes).
        - Nettoie les compteurs du détecteur
        - Purge les vieux logs si nécessaire
        """
        while self.running:
            time.sleep(300)  # 5 minutes
            try:
                self.detector.cleanup_old_entries()
                # Purger les stats système de plus de 48h
                self.db.cleanup_old_agent_stats(hours=48)
                # Nettoyer le cache Geo-IP
                self.geo_ip.cleanup_cache()
                print(f"\033[90m[CLEANUP]\033[0m Nettoyage périodique effectué "
                      f"(DB: {self.db.get_database_size()})")
            except Exception as e:
                print(f"\033[91m[CLEANUP ERREUR]\033[0m {e}")

    # =========================================================================
    #  ARRÊT DU SERVEUR
    # =========================================================================

    def stop(self):
        """Arrête proprement le serveur et tous ses composants."""
        if not self.running:
            return

        self.running = False
        print(f"\n\033[93m[SERVER]\033[0m Arrêt du serveur en cours...")

        # Arrêter le thread IPS
        if hasattr(self, 'stop_event'):
            self.stop_event.set()

        # Fermer le socket TCP
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass

        # Fermer toutes les connexions agents
        with self.clients_lock:
            for agent_id, info in self.clients.items():
                try:
                    info["socket"].close()
                except Exception:
                    pass
            self.clients.clear()

        # Arrêter le serveur WebSocket
        self.ws_server.stop()

        print(f"\033[92m[SERVER]\033[0m Serveur SOC arrêté proprement")
        print(f"\033[90m[SERVER]\033[0m Statistiques finales :")
        print(f"\033[90m         Logs reçus    : {self.total_logs_received}\033[0m")
        print(f"\033[90m         Alertes       : {self.total_alerts_generated}\033[0m")
        print(f"\033[90m         Taille DB     : {self.db.get_database_size()}\033[0m")

    def _signal_handler(self, signum, frame):
        """Gestionnaire de signal pour Ctrl+C."""
        print(f"\n\033[93m[SERVER]\033[0m Signal d'arrêt reçu (Ctrl+C)")
        self.stop()
        sys.exit(0)


# =============================================================================
#  POINT D'ENTRÉE
# =============================================================================

if __name__ == "__main__":
    import argparse

    # Arguments en ligne de commande
    arg_parser = argparse.ArgumentParser(description="SOC Server — Security Operations Center")
    arg_parser.add_argument(
        "--config", "-c",
        default=None,
        help="Chemin vers le fichier de configuration (rules.json)"
    )
    arg_parser.add_argument(
        "--port", "-p",
        type=int,
        default=None,
        help="Port TCP d'écoute (défaut: 9999)"
    )
    arg_parser.add_argument(
        "--ws-port", "-w",
        type=int,
        default=None,
        help="Port WebSocket (défaut: 8765)"
    )

    args = arg_parser.parse_args()

    # Trouver le fichier de config
    config_path = args.config
    if not config_path:
        # Chercher automatiquement
        script_dir = os.path.dirname(os.path.abspath(__file__))
        possible = [
            os.path.join(script_dir, "..", "config", "rules.json"),
            os.path.join(script_dir, "config", "rules.json"),
            "config/rules.json",
        ]
        for p in possible:
            if os.path.exists(p):
                config_path = p
                break

    # Créer et démarrer le serveur
    server = SOCServer(config_path=config_path)
    
    # Override des ports si spécifiés en CLI
    if args.port:
        server.port = args.port
    if args.ws_port:
        server.ws_port = args.ws_port

    server.start()
