"""
=============================================================================
 Oktopus Agent — TCP Sender (Client)
=============================================================================
 Fichier : agent/sender.py
 Rôle    : Envoi des logs au serveur Oktopus via TCP
            - Connexion TCP persistante avec reconnexion automatique
            - Buffer local (max 1000 logs) si serveur indisponible
            - Protocole : JSON + \\n par message
            - Thread-safe (Lock)
=============================================================================
"""

import socket
import json
import time
import threading
import logging

logger = logging.getLogger("SOC.Sender")


class TCPSender:
    """Client TCP pour l'envoi des logs au serveur SOC."""

    def __init__(self, server_host="127.0.0.1", server_port=9999, buffer_max=1000):
        self.server_host = server_host
        self.server_port = server_port
        self.buffer_max = buffer_max

        self.socket = None
        self.connected = False
        self.lock = threading.Lock()

        # Buffer pour les logs en attente (quand le serveur est indisponible)
        self.buffer = []
        self.buffer_lock = threading.Lock()

        # Stats
        self.total_sent = 0
        self.total_failed = 0
        self.total_buffered = 0

        # Retry config
        self.retry_delay = 2       # secondes
        self.max_retry_delay = 30  # secondes
        self.current_retry = self.retry_delay

    def connect(self):
        """Établir la connexion TCP au serveur SOC."""
        with self.lock:
            if self.connected:
                return True

            try:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.settimeout(10)
                self.socket.connect((self.server_host, self.server_port))
                self.connected = True
                self.current_retry = self.retry_delay
                logger.info(f"Connecté au serveur SOC {self.server_host}:{self.server_port}")

                # Vider le buffer après reconnexion
                self._flush_buffer()
                return True

            except (socket.error, OSError) as e:
                logger.warning(f"Connexion échouée ({self.server_host}:{self.server_port}): {e}")
                self.connected = False
                self._close_socket()
                return False

    def disconnect(self):
        """Fermer la connexion TCP."""
        with self.lock:
            self._close_socket()
            self.connected = False
            logger.info("Déconnecté du serveur SOC")

    def _close_socket(self):
        """Fermer le socket proprement."""
        if self.socket:
            try:
                self.socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self.socket.close()
            except OSError:
                pass
            self.socket = None

    def send(self, message):
        """
        Envoyer un message (dict) au serveur.
        Si la connexion est perdue, le message est bufferisé.

        Args:
            message (dict): Le message à envoyer (sera sérialisé en JSON)
        
        Returns:
            bool: True si envoyé, False si bufferisé
        """
        if not isinstance(message, dict):
            logger.error("Le message doit être un dictionnaire")
            return False

        # Tenter l'envoi
        if self.connected:
            success = self._send_raw(message)
            if success:
                self.total_sent += 1
                return True

        # Bufferiser si l'envoi échoue
        self._add_to_buffer(message)
        return False

    def send_batch(self, messages):
        """
        Envoyer un lot de messages.

        Args:
            messages (list[dict]): Liste de messages à envoyer
        
        Returns:
            int: Nombre de messages envoyés avec succès
        """
        sent = 0
        for msg in messages:
            if self.send(msg):
                sent += 1
        return sent

    def _send_raw(self, message):
        """Envoyer un message brut via le socket TCP."""
        with self.lock:
            if not self.connected or not self.socket:
                return False

            try:
                data = json.dumps(message, ensure_ascii=False) + "\n"
                self.socket.sendall(data.encode("utf-8"))
                return True

            except (socket.error, OSError, BrokenPipeError) as e:
                logger.warning(f"Erreur d'envoi: {e}")
                self.connected = False
                self._close_socket()
                return False

    def _add_to_buffer(self, message):
        """Ajouter un message au buffer local."""
        with self.buffer_lock:
            if len(self.buffer) >= self.buffer_max:
                # Supprimer les plus anciens (FIFO)
                dropped = len(self.buffer) - self.buffer_max + 1
                self.buffer = self.buffer[dropped:]
                logger.warning(f"Buffer plein — {dropped} ancien(s) log(s) supprimé(s)")

            self.buffer.append(message)
            self.total_buffered += 1

    def _flush_buffer(self):
        """Envoyer tous les messages en attente dans le buffer."""
        with self.buffer_lock:
            if not self.buffer:
                return

            logger.info(f"Vidage du buffer ({len(self.buffer)} messages)...")
            remaining = []

            for msg in self.buffer:
                if not self._send_raw(msg):
                    remaining.append(msg)
                else:
                    self.total_sent += 1

            self.buffer = remaining

            if remaining:
                logger.warning(f"{len(remaining)} messages n'ont pas pu être envoyés")
            else:
                logger.info("Buffer vidé avec succès")

    def send_registration(self, agent_id, hostname, os_type, ip_address):
        """
        Envoyer le message d'enregistrement de l'agent.

        Args:
            agent_id (str): Identifiant unique de l'agent
            hostname (str): Nom de la machine
            os_type (str): Type d'OS (linux / windows)
            ip_address (str): Adresse IP de l'agent
        
        Returns:
            bool: True si envoyé
        """
        msg = {
            "type": "register",
            "agent_id": agent_id,
            "hostname": hostname,
            "os_type": os_type,
            "ip_address": ip_address,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        return self.send(msg)

    def send_heartbeat(self, agent_id):
        """
        Envoyer un heartbeat au serveur.

        Args:
            agent_id (str): Identifiant de l'agent
        
        Returns:
            bool: True si envoyé
        """
        msg = {
            "type": "heartbeat",
            "agent_id": agent_id,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        return self.send(msg)

    def send_logs(self, agent_id, logs, os_type="", ip_address=""):
        """
        Envoyer un batch de lignes de logs.

        Args:
            agent_id (str): Identifiant de l'agent
            logs (list[dict]): Liste de logs à envoyer
                Chaque log : {"source": str, "line": str, "timestamp": str}
            os_type (str): Système d'exploitation
            ip_address (str): Adresse IP de l'agent
        
        Returns:
            bool: True si envoyé
        """
        msg = {
            "type": "logs",
            "agent_id": agent_id,
            "os_type": os_type,
            "ip_address": ip_address,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "logs": logs
        }
        return self.send(msg)

    def reconnect_loop(self, stop_event, interval=5):
        """
        Boucle de reconnexion automatique (à exécuter dans un thread).

        Args:
            stop_event (threading.Event): Événement pour arrêter la boucle
            interval (int): Intervalle entre les tentatives (secondes)
        """
        while not stop_event.is_set():
            if not self.connected:
                logger.info("Tentative de reconnexion...")
                if self.connect():
                    logger.info("Reconnexion réussie")
                else:
                    time.sleep(min(self.current_retry, self.max_retry_delay))
                    self.current_retry = min(self.current_retry * 2, self.max_retry_delay)
            else:
                stop_event.wait(interval)

    def get_stats(self):
        """Retourne les statistiques de l'envoyeur."""
        with self.buffer_lock:
            buffered = len(self.buffer)
        return {
            "connected": self.connected,
            "total_sent": self.total_sent,
            "total_failed": self.total_failed,
            "buffered": buffered,
            "server": f"{self.server_host}:{self.server_port}"
        }
