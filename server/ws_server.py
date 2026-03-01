"""
=============================================================================
 Oktopus — WebSocket Server (Broadcaster vers Dashboard)
=============================================================================
 Fichier : server/ws_server.py
 Rôle    : Serveur WebSocket qui push les logs et alertes en temps réel
           vers tous les dashboards (navigateurs) connectés.
           - Écoute sur 0.0.0.0:8765
           - Gère les connexions/déconnexions des clients
           - Broadcast des logs, alertes et stats
           - Gère les commandes du dashboard (résoudre alerte, etc.)
 
 Auteur  : Oktopus Team
 Date    : 2026-02-27
 Python  : 3.8+
=============================================================================
"""

import asyncio
import json
import threading
import websockets
from datetime import datetime
from typing import Set, Dict, Any, Optional


class WebSocketServer:
    """
    Serveur WebSocket pour le broadcast en temps réel vers les dashboards.
    
    Fonctionne dans un thread séparé avec sa propre boucle asyncio
    pour ne pas bloquer le serveur TCP principal.
    
    Attributs :
        host       : Adresse d'écoute (défaut: 0.0.0.0)
        port       : Port WebSocket (défaut: 8765)
        clients    : Ensemble des clients WebSocket connectés
        loop       : Boucle asyncio dédiée
        db         : Référence vers la base de données (optionnel)
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 8765, database=None):
        """
        Initialise le serveur WebSocket.
        
        Args:
            host     : Adresse d'écoute
            port     : Port d'écoute
            database : Instance SOCDatabase (pour les requêtes du dashboard)
        """
        self.host = host
        self.port = port
        self.clients: Set = set()
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.db = database
        self.ips_engine = None  # Sera défini par server.py après init
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._loop_ready = threading.Event()  # Signalé quand la boucle asyncio est prête

        print(f"\033[96m[WEBSOCKET]\033[0m Serveur WebSocket configuré sur {host}:{port}")

    # =========================================================================
    #  DÉMARRAGE / ARRÊT
    # =========================================================================

    def start(self):
        """
        Démarre le serveur WebSocket dans un thread séparé.
        Le serveur tourne en arrière-plan et n'est pas bloquant.
        """
        self._running = True
        self._thread = threading.Thread(target=self._run_server, daemon=True)
        self._thread.start()
        print(f"\033[96m[WEBSOCKET]\033[0m Serveur démarré sur ws://{self.host}:{self.port}")

    def _run_server(self):
        """
        Boucle principale du serveur WebSocket (exécutée dans un thread).
        Crée une nouvelle boucle asyncio dédiée.
        """
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

        try:
            self.loop.run_until_complete(self._serve())
        except Exception as e:
            print(f"\033[91m[WEBSOCKET ERREUR]\033[0m Erreur serveur : {e}")
        finally:
            self.loop.close()

    async def _serve(self):
        """
        Coroutine principale : démarre le serveur WebSocket et attend.
        """
        try:
            async with websockets.serve(
                self._handler, 
                self.host, 
                self.port,
                ping_interval=30,
                ping_timeout=10,
            ):
                # Signaler que la boucle est prête pour les broadcasts
                self._loop_ready.set()
                print(f"\033[96m[WEBSOCKET]\033[0m Boucle asyncio prête — broadcasts activés")
                # Boucle infinie tant que le serveur tourne
                while self._running:
                    await asyncio.sleep(1)
        except Exception as e:
            print(f"\033[91m[WEBSOCKET ERREUR]\033[0m Erreur serve : {e}")
            self._loop_ready.set()  # Débloquer les threads en attente même en cas d'erreur

    def stop(self):
        """Arrête le serveur WebSocket proprement."""
        self._running = False
        if self.loop and self.loop.is_running():
            self.loop.call_soon_threadsafe(self.loop.stop)
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        print(f"\033[96m[WEBSOCKET]\033[0m Serveur arrêté")

    # =========================================================================
    #  GESTION DES CLIENTS
    # =========================================================================

    async def _handler(self, websocket):
        """
        Handler pour chaque client WebSocket connecté.
        
        - Ajoute le client à l'ensemble
        - Envoie les données initiales (stats, logs récents, alertes)
        - Écoute les messages du client (commandes du dashboard)
        - Retire le client à la déconnexion
        
        Args:
            websocket : Connexion WebSocket du client
        """
        # Enregistrer le nouveau client
        self.clients.add(websocket)
        client_ip = websocket.remote_address[0] if websocket.remote_address else "unknown"
        print(f"\033[96m[WEBSOCKET]\033[0m Client connecté : {client_ip} "
              f"({len(self.clients)} client(s) actif(s))")

        try:
            # Envoyer les données initiales au nouveau client
            await self._send_initial_data(websocket)

            # Écouter les messages du client
            async for message in websocket:
                await self._handle_client_message(websocket, message)

        except websockets.exceptions.ConnectionClosed:
            pass
        except Exception as e:
            print(f"\033[91m[WEBSOCKET ERREUR]\033[0m Erreur avec client {client_ip} : {e}")
        finally:
            # Retirer le client
            self.clients.discard(websocket)
            print(f"\033[96m[WEBSOCKET]\033[0m Client déconnecté : {client_ip} "
                  f"({len(self.clients)} client(s) actif(s))")

    async def _send_initial_data(self, websocket):
        """
        Envoie les données initiales à un nouveau client dashboard.
        Inclut : stats, logs récents, alertes actives, liste agents.
        
        Args:
            websocket : Client WebSocket
        """
        if not self.db:
            return

        try:
            # Envoyer les stats globales
            stats = self.db.get_stats()
            await websocket.send(json.dumps({
                "type": "stats",
                "data": stats
            }, ensure_ascii=False))

            # Envoyer les logs récents (50 derniers)
            logs = self.db.get_recent_logs(limit=50)
            await websocket.send(json.dumps({
                "type": "initial_logs",
                "data": logs
            }, ensure_ascii=False))

            # Envoyer toutes les alertes (y compris résolues, pour le filtre dashboard)
            alerts = self.db.get_all_alerts(limit=200)
            await websocket.send(json.dumps({
                "type": "initial_alerts",
                "data": alerts
            }, ensure_ascii=False))

            # Envoyer la liste des agents
            agents = self.db.get_all_agents()
            await websocket.send(json.dumps({
                "type": "agents",
                "data": agents
            }, ensure_ascii=False))

            # Envoyer les données du graphe timeline
            hourly = self.db.get_hourly_log_counts(24)
            await websocket.send(json.dumps({
                "type": "timeline",
                "data": hourly
            }, ensure_ascii=False))

            # Envoyer les données IPS initiales
            try:
                blocked_ips = self.db.get_blocked_ips()
                ips_history = self.db.get_ips_history(limit=100)
                ips_stats = self.db.get_ips_stats()
                await websocket.send(json.dumps({
                    "type": "initial_ips",
                    "data": {
                        "blocked_ips": blocked_ips,
                        "history": ips_history,
                        "stats": ips_stats,
                        "whitelist": self.ips_engine.get_whitelist() if self.ips_engine else [],
                        "enabled": self.ips_engine.enabled if self.ips_engine else False
                    }
                }, ensure_ascii=False))
            except Exception as e:
                print(f"\033[91m[WEBSOCKET ERREUR]\033[0m Envoi données IPS initiales échoué : {e}")

            # Envoyer les dernières statistiques système des agents
            try:
                agent_stats = self.db.get_latest_agent_stats()
                if agent_stats:
                    await websocket.send(json.dumps({
                        "type": "initial_agent_stats",
                        "data": agent_stats
                    }, ensure_ascii=False))
            except Exception as e:
                print(f"\033[91m[WEBSOCKET ERREUR]\033[0m Envoi stats agents initiales échoué : {e}")

            # Envoyer les événements Geo-IP récents
            try:
                geo_events = self.db.get_recent_geo_events(limit=100)
                if geo_events:
                    await websocket.send(json.dumps({
                        "type": "initial_geo",
                        "data": geo_events
                    }, ensure_ascii=False))
            except Exception as e:
                print(f"\033[91m[WEBSOCKET ERREUR]\033[0m Envoi geo events initiales échoué : {e}")

        except Exception as e:
            print(f"\033[91m[WEBSOCKET ERREUR]\033[0m Envoi données initiales échoué : {e}")

    async def _handle_client_message(self, websocket, message: str):
        """
        Traite un message reçu d'un client dashboard.
        
        Commandes supportées :
        - resolve_alert : Résoudre une alerte
        - get_stats     : Demander les stats actuelles
        - get_logs      : Demander des logs filtrés
        - get_agents    : Demander la liste des agents
        
        Args:
            websocket : Client WebSocket
            message   : Message JSON reçu
        """
        try:
            data = json.loads(message)
            command = data.get("command", "")

            if command == "resolve_alert" and self.db:
                alert_id = data.get("alert_id")
                if alert_id:
                    success = self.db.resolve_alert(int(alert_id))
                    # Notifier tous les clients
                    await self._broadcast({
                        "type": "alert_resolved",
                        "data": {"alert_id": alert_id, "success": success}
                    })
                    # Envoyer les stats mises à jour
                    stats = self.db.get_stats()
                    await self._broadcast({
                        "type": "stats",
                        "data": stats
                    })

            elif command == "get_stats" and self.db:
                stats = self.db.get_stats()
                await websocket.send(json.dumps({
                    "type": "stats",
                    "data": stats
                }, ensure_ascii=False))

            elif command == "get_logs" and self.db:
                limit = data.get("limit", 100)
                level = data.get("level", None)
                agent_id = data.get("agent_id", None)
                logs = self.db.get_recent_logs(limit=limit, level=level, agent_id=agent_id)
                await websocket.send(json.dumps({
                    "type": "filtered_logs",
                    "data": logs
                }, ensure_ascii=False))

            elif command == "get_agents" and self.db:
                agents = self.db.get_all_agents()
                await websocket.send(json.dumps({
                    "type": "agents",
                    "data": agents
                }, ensure_ascii=False))

            elif command == "get_timeline" and self.db:
                hourly = self.db.get_hourly_log_counts(24)
                await websocket.send(json.dumps({
                    "type": "timeline",
                    "data": hourly
                }, ensure_ascii=False))

            # --- Commandes IPS ---
            elif command == "unblock_ip" and self.ips_engine:
                action_id = data.get("action_id")
                reason = data.get("reason", "manual_dashboard")
                if action_id:
                    success = self.ips_engine.unblock_ip(int(action_id), reason)
                    await websocket.send(json.dumps({
                        "type": "ips_unblock_result",
                        "data": {"action_id": action_id, "success": success}
                    }, ensure_ascii=False))

            elif command == "toggle_ips" and self.ips_engine:
                enabled = data.get("enabled", True)
                self.ips_engine.set_enabled(enabled)
                # Broadcast le nouvel état à tous les clients
                self.broadcast_ips_event({
                    "event": "ips_toggled",
                    "enabled": self.ips_engine.enabled
                })

            elif command == "get_ips_data" and self.db:
                blocked_ips = self.db.get_blocked_ips()
                ips_history = self.db.get_ips_history(limit=100)
                ips_stats = self.db.get_ips_stats()
                await websocket.send(json.dumps({
                    "type": "ips_data",
                    "data": {
                        "blocked_ips": blocked_ips,
                        "history": ips_history,
                        "stats": ips_stats,
                        "whitelist": self.ips_engine.get_whitelist() if self.ips_engine else [],
                        "enabled": self.ips_engine.enabled if self.ips_engine else False
                    }
                }, ensure_ascii=False))

            elif command == "add_whitelist" and self.ips_engine:
                ip = data.get("ip")
                if ip:
                    self.ips_engine.add_to_whitelist(ip)
                    self.broadcast_ips_event({
                        "event": "whitelist_updated",
                        "whitelist": self.ips_engine.get_whitelist()
                    })

            elif command == "remove_whitelist" and self.ips_engine:
                ip = data.get("ip")
                if ip:
                    self.ips_engine.remove_from_whitelist(ip)
                    self.broadcast_ips_event({
                        "event": "whitelist_updated",
                        "whitelist": self.ips_engine.get_whitelist()
                    })

            # --- Commande : stats système des agents ---
            elif command == "get_agent_stats" and self.db:
                agent_id = data.get("agent_id", None)
                agent_stats = self.db.get_latest_agent_stats(agent_id)
                await websocket.send(json.dumps({
                    "type": "initial_agent_stats",
                    "data": agent_stats
                }, ensure_ascii=False))

            # --- Commande : événements Geo-IP ---
            elif command == "get_geo_events" and self.db:
                geo_events = self.db.get_recent_geo_events(limit=100)
                await websocket.send(json.dumps({
                    "type": "initial_geo",
                    "data": geo_events
                }, ensure_ascii=False))

        except json.JSONDecodeError:
            print(f"\033[91m[WEBSOCKET ERREUR]\033[0m Message client invalide : {message[:50]}")
        except Exception as e:
            print(f"\033[91m[WEBSOCKET ERREUR]\033[0m Erreur traitement commande : {e}")

    # =========================================================================
    #  BROADCAST — Envoi de données à TOUS les clients
    # =========================================================================

    async def _broadcast(self, data: Dict):
        """
        Envoie un message à tous les clients connectés (async).
        
        Args:
            data : Dictionnaire à envoyer (sera sérialisé en JSON)
        """
        if not self.clients:
            return

        message = json.dumps(data, ensure_ascii=False)
        
        # Créer une copie pour éviter les problèmes de modification pendant l'itération
        clients_copy = self.clients.copy()
        disconnected = set()

        for client in clients_copy:
            try:
                await client.send(message)
            except websockets.exceptions.ConnectionClosed:
                disconnected.add(client)
            except Exception as e:
                print(f"\033[91m[WEBSOCKET ERREUR]\033[0m Broadcast échoué pour un client : {e}")
                disconnected.add(client)

        # Nettoyer les clients déconnectés
        for client in disconnected:
            self.clients.discard(client)

    def broadcast_log(self, log_data: Dict):
        """
        Broadcast un nouveau log à tous les clients (appelé depuis le thread principal).
        Thread-safe : utilise call_soon_threadsafe pour planifier dans la boucle asyncio.
        
        Args:
            log_data : Données du log normalisé
        """
        if not self.loop or not self._running or not self.loop.is_running():
            return

        message = {
            "type": "log",
            "data": log_data
        }

        try:
            asyncio.run_coroutine_threadsafe(
                self._broadcast(message),
                self.loop
            )
        except Exception as e:
            print(f"\033[91m[WEBSOCKET ERREUR]\033[0m Broadcast log échoué : {e}")

    def broadcast_alert(self, alert_data: Dict):
        """
        Broadcast une nouvelle alerte à tous les clients (thread-safe).
        
        Args:
            alert_data : Données de l'alerte
        """
        if not self.loop or not self._running or not self.loop.is_running():
            return

        message = {
            "type": "alert",
            "data": alert_data
        }

        try:
            asyncio.run_coroutine_threadsafe(
                self._broadcast(message),
                self.loop
            )
        except Exception as e:
            print(f"\033[91m[WEBSOCKET ERREUR]\033[0m Broadcast alerte échoué : {e}")

    def broadcast_stats(self, stats: Dict):
        """
        Broadcast les statistiques mises à jour (thread-safe).
        
        Args:
            stats : Données statistiques
        """
        if not self.loop or not self._running or not self.loop.is_running():
            return

        message = {
            "type": "stats",
            "data": stats
        }

        try:
            asyncio.run_coroutine_threadsafe(
                self._broadcast(message),
                self.loop
            )
        except Exception as e:
            print(f"\033[91m[WEBSOCKET ERREUR]\033[0m Broadcast stats échoué : {e}")

    def broadcast_agent_update(self, agents: list):
        """
        Broadcast la mise à jour de la liste des agents (thread-safe).
        
        Args:
            agents : Liste des agents
        """
        if not self.loop or not self._running or not self.loop.is_running():
            return

        message = {
            "type": "agents",
            "data": agents
        }

        try:
            asyncio.run_coroutine_threadsafe(
                self._broadcast(message),
                self.loop
            )
        except Exception as e:
            print(f"\033[91m[WEBSOCKET ERREUR]\033[0m Broadcast agents échoué : {e}")

    def broadcast_ips_event(self, event_data: dict):
        """
        Broadcast un événement IPS à tous les clients dashboard (thread-safe).
        
        Args:
            event_data : Données de l'événement IPS
        """
        if not self.loop or not self._running or not self.loop.is_running():
            return

        message = {
            "type": "ips_event",
            "data": event_data
        }

        try:
            asyncio.run_coroutine_threadsafe(
                self._broadcast(message),
                self.loop
            )
        except Exception as e:
            print(f"\033[91m[WEBSOCKET ERREUR]\033[0m Broadcast IPS échoué : {e}")

    def broadcast_agent_stats(self, stats_data: dict):
        """
        Broadcast les statistiques système d'un agent (thread-safe).
        Envoyé à chaque réception de stats depuis un agent.
        
        Args:
            stats_data : {agent_id, stats}
        """
        if not self.loop or not self._running or not self.loop.is_running():
            return

        message = {
            "type": "agent_stats",
            "data": stats_data
        }

        try:
            asyncio.run_coroutine_threadsafe(
                self._broadcast(message),
                self.loop
            )
        except Exception as e:
            print(f"\033[91m[WEBSOCKET ERREUR]\033[0m Broadcast agent stats échoué : {e}")

    def broadcast_geo_event(self, geo_data: dict):
        """
        Broadcast un événement Geo-IP aux dashboards (thread-safe).
        
        Args:
            geo_data : {ip, country, country_code, city, lat, lon, flag,
                        alert_type, severity, agent_id, rule_name, timestamp}
        """
        if not self.loop or not self._running or not self.loop.is_running():
            return

        message = {
            "type": "geo_event",
            "data": geo_data
        }

        try:
            asyncio.run_coroutine_threadsafe(
                self._broadcast(message),
                self.loop
            )
        except Exception as e:
            print(f"\033[91m[WEBSOCKET ERREUR]\033[0m Broadcast geo event échoué : {e}")

    def get_client_count(self) -> int:
        """Retourne le nombre de clients dashboard connectés."""
        return len(self.clients)


# =============================================================================
#  POINT D'ENTRÉE — Test standalone
# =============================================================================

if __name__ == "__main__":
    import time

    print("=" * 60)
    print("  SOC WebSocket Server — Test Standalone")
    print("=" * 60)
    print()
    print("  Le serveur WebSocket écoute sur ws://0.0.0.0:8765")
    print("  Ouvrez un navigateur et connectez-vous pour tester.")
    print("  Ctrl+C pour arrêter.")
    print()

    ws_server = WebSocketServer(port=8765)
    ws_server.start()

    try:
        while True:
            time.sleep(5)
            print(f"\033[96m[WEBSOCKET]\033[0m "
                  f"Clients connectés : {ws_server.get_client_count()}")
            
            # Simuler un broadcast de test
            ws_server.broadcast_log({
                "timestamp": datetime.now().isoformat(),
                "agent_id": "TEST-AGENT",
                "level": "INFO",
                "message": "Test log depuis le serveur WebSocket",
                "source": "test",
                "category": "SYSTEM"
            })

    except KeyboardInterrupt:
        print("\n\033[96m[WEBSOCKET]\033[0m Arrêt du serveur...")
        ws_server.stop()
        print("  ✅ Serveur WebSocket arrêté proprement.")
