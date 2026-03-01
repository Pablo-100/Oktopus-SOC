"""
=============================================================================
 Oktopus Agent — Collecteur Linux
=============================================================================
 Fichier : agent/collectors/linux_collector.py
 Rôle    : Collecte des logs Linux en temps réel
            - /var/log/auth.log  (authentification SSH, sudo, etc.)
            - /var/log/syslog    (événements système)
            - Logs nginx (/var/log/nginx/access.log, error.log)
            - Technique tail -f (suivi en temps réel)
=============================================================================
"""

import os
import time
import logging

logger = logging.getLogger("SOC.Collector.Linux")


class LinuxCollector:
    """Collecteur de logs pour systèmes Linux."""

    # Fichiers de logs à surveiller
    DEFAULT_LOG_FILES = {
        "auth": "/var/log/auth.log",
        "syslog": "/var/log/syslog",
        "nginx_access": "/var/log/nginx/access.log",
        "nginx_error": "/var/log/nginx/error.log",
        "kern": "/var/log/kern.log",
        "daemon": "/var/log/daemon.log",
    }

    def __init__(self, log_files=None):
        """
        Args:
            log_files (dict, optional): 
                Dictionnaire {nom_source: chemin_fichier}
                Si None, utilise les fichiers par défaut
        """
        self.log_files = log_files or self.DEFAULT_LOG_FILES
        self.file_positions = {}  # {chemin: position_actuelle}
        self.file_inodes = {}    # {chemin: inode} pour détecter la rotation

        # Initialiser les positions (aller à la fin de chaque fichier)
        for source, path in self.log_files.items():
            self._init_position(path)

    def _init_position(self, filepath):
        """Se positionner à la fin du fichier (ne pas lire l'historique)."""
        try:
            if os.path.exists(filepath):
                stat = os.stat(filepath)
                self.file_positions[filepath] = stat.st_size
                self.file_inodes[filepath] = stat.st_ino
                logger.debug(f"Position initiale: {filepath} @ {stat.st_size} bytes")
            else:
                self.file_positions[filepath] = 0
                self.file_inodes[filepath] = None
                logger.debug(f"Fichier inexistant: {filepath}")
        except OSError as e:
            logger.warning(f"Impossible de lire {filepath}: {e}")
            self.file_positions[filepath] = 0
            self.file_inodes[filepath] = None

    def collect(self):
        """
        Collecter les nouvelles lignes de tous les fichiers surveillés.
        
        Returns:
            list[dict]: Liste de logs au format:
                {
                    "source": str,       # nom du source (auth, syslog, etc.)
                    "line": str,         # contenu brut de la ligne
                    "timestamp": str,    # horodatage de collecte
                    "collector": "linux"
                }
        """
        new_logs = []

        for source, filepath in self.log_files.items():
            try:
                lines = self._read_new_lines(filepath)
                for line in lines:
                    line = line.strip()
                    if line:
                        new_logs.append({
                            "source": source,
                            "line": line,
                            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                            "collector": "linux"
                        })
            except Exception as e:
                logger.error(f"Erreur collecte {source} ({filepath}): {e}")

        if new_logs:
            logger.debug(f"Collecté {len(new_logs)} lignes depuis les logs Linux")

        return new_logs

    def _read_new_lines(self, filepath):
        """
        Lire les nouvelles lignes d'un fichier (technique tail -f).
        Gère la rotation de logs (détecte le changement d'inode ou la troncation).
        
        Args:
            filepath (str): Chemin du fichier
        
        Returns:
            list[str]: Nouvelles lignes lues
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

            # Détecter la rotation du fichier
            if saved_inode is not None and current_inode != saved_inode:
                logger.info(f"Rotation détectée: {filepath} (inode changé)")
                saved_pos = 0

            # Détecter la troncation
            if current_size < saved_pos:
                logger.info(f"Troncation détectée: {filepath}")
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
            logger.warning(f"Permission refusée: {filepath}")
        except OSError as e:
            logger.error(f"Erreur lecture {filepath}: {e}")

        return lines

    def get_status(self):
        """Retourne le statut de chaque source surveillée."""
        status = {}
        for source, path in self.log_files.items():
            exists = os.path.exists(path)
            readable = os.access(path, os.R_OK) if exists else False
            status[source] = {
                "path": path,
                "exists": exists,
                "readable": readable,
                "position": self.file_positions.get(path, 0)
            }
        return status

    def add_log_file(self, source_name, filepath):
        """Ajouter un fichier de log à surveiller."""
        self.log_files[source_name] = filepath
        self._init_position(filepath)
        logger.info(f"Nouveau fichier ajouté: {source_name} → {filepath}")

    def remove_log_file(self, source_name):
        """Retirer un fichier de log de la surveillance."""
        if source_name in self.log_files:
            path = self.log_files[source_name]
            del self.log_files[source_name]
            self.file_positions.pop(path, None)
            self.file_inodes.pop(path, None)
            logger.info(f"Fichier retiré: {source_name}")
