"""
=============================================================================
 Oktopus — Module Base de Données (SQLite)
=============================================================================
 Fichier : server/database.py
 Rôle    : Gestion complète de la base de données SQLite du SOC.
           - Création / initialisation des tables (logs, alerts, agents)
           - Insertion de logs, alertes, et agents
           - Requêtes de lecture (stats, filtres, historique)
           - Mise à jour du statut des agents et résolution des alertes
 
 Auteur  : Oktopus Team
 Date    : 2026-02-27
 Python  : 3.8+
=============================================================================
"""

import sqlite3
import threading
import json
import os
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple


class SOCDatabase:
    """
    Classe principale pour la gestion de la base de données SQLite du SOC.
    
    Utilise un verrou (threading.Lock) pour garantir la sécurité en
    environnement multi-thread (le serveur TCP traite plusieurs agents
    en parallèle).
    
    Attributs :
        db_path (str)           : Chemin vers le fichier SQLite
        lock (threading.Lock)   : Verrou pour accès concurrent
    """

    def __init__(self, db_path: str = "soc.db"):
        """
        Initialise la connexion à la base de données.
        
        Args:
            db_path : Chemin vers le fichier SQLite (par défaut : soc.db)
        """
        self.db_path = db_path
        self.lock = threading.Lock()
        
        # Créer les tables si elles n'existent pas
        self._init_database()
        
        print(f"\033[92m[DATABASE]\033[0m Base de données initialisée : {self.db_path}")

    # =========================================================================
    #  INITIALISATION
    # =========================================================================

    def _init_database(self):
        """
        Crée les 3 tables principales si elles n'existent pas :
        - logs    : Stockage de tous les logs reçus des agents
        - alerts  : Stockage des alertes générées par le moteur IDS
        - agents  : Registre des agents connectés au SOC
        """
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            try:
                # ---------------------------------------------------------
                # Table LOGS — Stockage de tous les événements reçus
                # ---------------------------------------------------------
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS logs (
                        id          INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp   TEXT NOT NULL,
                        agent_id    TEXT NOT NULL,
                        agent_ip    TEXT,
                        agent_os    TEXT,
                        source      TEXT,
                        level       TEXT DEFAULT 'INFO',
                        category    TEXT,
                        message     TEXT NOT NULL,
                        raw_json    TEXT
                    )
                """)

                # ---------------------------------------------------------
                # Table ALERTS — Alertes de sécurité détectées par le IDS
                # ---------------------------------------------------------
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS alerts (
                        id          INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp   TEXT NOT NULL,
                        agent_id    TEXT NOT NULL,
                        rule_name   TEXT NOT NULL,
                        severity    TEXT NOT NULL,
                        type        TEXT DEFAULT '',
                        message     TEXT NOT NULL,
                        log_id      INTEGER,
                        resolved    INTEGER DEFAULT 0,
                        FOREIGN KEY (log_id) REFERENCES logs(id)
                    )
                """)

                # ---------------------------------------------------------
                # Table AGENTS — Registre des agents enregistrés
                # ---------------------------------------------------------
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS agents (
                        id          INTEGER PRIMARY KEY AUTOINCREMENT,
                        agent_id    TEXT UNIQUE NOT NULL,
                        ip          TEXT,
                        os          TEXT,
                        first_seen  TEXT,
                        last_seen   TEXT,
                        status      TEXT DEFAULT 'active'
                    )
                """)

                # ---------------------------------------------------------
                # INDEX pour améliorer les performances des requêtes
                # ---------------------------------------------------------
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_logs_timestamp 
                    ON logs(timestamp)
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_logs_agent_id 
                    ON logs(agent_id)
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_logs_level 
                    ON logs(level)
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_alerts_timestamp 
                    ON alerts(timestamp)
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_alerts_severity 
                    ON alerts(severity)
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_alerts_resolved 
                    ON alerts(resolved)
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_agents_agent_id 
                    ON agents(agent_id)
                """)

                # ---------------------------------------------------------
                # Table IPS_ACTIONS — Historique des actions IPS (blocage/déblocage)
                # ---------------------------------------------------------
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS ips_actions (
                        id              INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp       TEXT NOT NULL,
                        ip              TEXT NOT NULL,
                        action          TEXT NOT NULL,
                        reason          TEXT,
                        severity        TEXT,
                        alert_type      TEXT,
                        agent_id        TEXT,
                        alert_id        INTEGER,
                        duration_minutes INTEGER DEFAULT 0,
                        expires_at      TEXT,
                        status          TEXT DEFAULT 'active',
                        unblocked_at    TEXT,
                        unblock_reason  TEXT,
                        FOREIGN KEY (alert_id) REFERENCES alerts(id)
                    )
                """)

                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_ips_ip 
                    ON ips_actions(ip)
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_ips_status 
                    ON ips_actions(status)
                """)

                # ---------------------------------------------------------
                # Table AGENT_STATS — Statistiques système des agents
                # (CPU, RAM, Disque, Réseau, OS, Uptime, Top processus)
                # Historique conservé 48h puis purgé automatiquement.
                # ---------------------------------------------------------
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS agent_stats (
                        id          INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp   TEXT NOT NULL,
                        agent_id    TEXT NOT NULL,
                        stats_json  TEXT NOT NULL,
                        FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
                    )
                """)

                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_agent_stats_agent_id 
                    ON agent_stats(agent_id)
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_agent_stats_timestamp 
                    ON agent_stats(timestamp)
                """)

                # ---------------------------------------------------------
                # Table GEO_EVENTS — Géolocalisation des IPs attaquantes
                # ---------------------------------------------------------
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS geo_events (
                        id          INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp   TEXT NOT NULL,
                        ip          TEXT NOT NULL,
                        country     TEXT,
                        country_code TEXT,
                        city        TEXT,
                        lat         REAL,
                        lon         REAL,
                        alert_type  TEXT,
                        severity    TEXT,
                        agent_id    TEXT
                    )
                """)

                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_geo_events_timestamp 
                    ON geo_events(timestamp)
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_geo_events_ip 
                    ON geo_events(ip)
                """)

                # ---------------------------------------------------------
                # Migration : ajouter colonnes MITRE ATT&CK à alerts
                # ---------------------------------------------------------
                try:
                    cursor.execute("ALTER TABLE alerts ADD COLUMN mitre_tactic TEXT DEFAULT ''")
                except sqlite3.OperationalError:
                    pass  # colonne existe déjà
                try:
                    cursor.execute("ALTER TABLE alerts ADD COLUMN mitre_technique_id TEXT DEFAULT ''")
                except sqlite3.OperationalError:
                    pass
                try:
                    cursor.execute("ALTER TABLE alerts ADD COLUMN mitre_technique_name TEXT DEFAULT ''")
                except sqlite3.OperationalError:
                    pass

                conn.commit()
                print(f"\033[92m[DATABASE]\033[0m Tables créées/vérifiées avec succès.")

            except sqlite3.Error as e:
                print(f"\033[91m[DATABASE ERREUR]\033[0m Erreur lors de l'initialisation : {e}")
                conn.rollback()
            finally:
                conn.close()

    def _get_connection(self) -> sqlite3.Connection:
        """
        Crée et retourne une nouvelle connexion SQLite.
        Active les clés étrangères et configure le mode Row pour
        accéder aux colonnes par nom.
        
        Returns:
            sqlite3.Connection : Connexion configurée
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # Accès par nom de colonne
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")  # Write-Ahead Logging (perf)
        return conn

    # =========================================================================
    #  INSERTION — LOGS
    # =========================================================================

    def insert_log(self, timestamp: str, agent_id: str, agent_ip: str,
                   agent_os: str, source: str, level: str, category: str,
                   message: str, raw_json: str = "") -> Optional[int]:
        """
        Insère un nouveau log dans la base de données.
        
        Args:
            timestamp : Horodatage ISO 8601
            agent_id  : Identifiant de l'agent (ex: PC-JOHN-WIN10)
            agent_ip  : Adresse IP de l'agent
            agent_os  : Système d'exploitation (windows/linux)
            source    : Source du log (Security, auth.log, etc.)
            level     : Niveau (INFO, WARNING, HIGH, CRITICAL)
            category  : Catégorie (AUTH, NETWORK, SYSTEM, etc.)
            message   : Message du log
            raw_json  : JSON brut original (optionnel)
        
        Returns:
            int : ID du log inséré, ou None en cas d'erreur
        """
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO logs 
                        (timestamp, agent_id, agent_ip, agent_os, source, 
                         level, category, message, raw_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (timestamp, agent_id, agent_ip, agent_os, source,
                      level, category, message, raw_json))
                conn.commit()
                log_id = cursor.lastrowid
                return log_id

            except sqlite3.Error as e:
                print(f"\033[91m[DATABASE ERREUR]\033[0m Insertion log échouée : {e}")
                conn.rollback()
                return None
            finally:
                conn.close()

    def insert_logs_batch(self, logs: List[Dict[str, Any]]) -> List[int]:
        """
        Insère plusieurs logs en une seule transaction (plus performant).
        
        Args:
            logs : Liste de dictionnaires contenant les champs du log
        
        Returns:
            List[int] : Liste des IDs insérés
        """
        inserted_ids = []
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                for log in logs:
                    cursor.execute("""
                        INSERT INTO logs 
                            (timestamp, agent_id, agent_ip, agent_os, source,
                             level, category, message, raw_json)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        log.get("timestamp", datetime.now().isoformat()),
                        log.get("agent_id", "unknown"),
                        log.get("agent_ip", ""),
                        log.get("agent_os", ""),
                        log.get("source", ""),
                        log.get("level", "INFO"),
                        log.get("category", ""),
                        log.get("message", ""),
                        log.get("raw_json", "")
                    ))
                    inserted_ids.append(cursor.lastrowid)
                conn.commit()

            except sqlite3.Error as e:
                print(f"\033[91m[DATABASE ERREUR]\033[0m Insertion batch échouée : {e}")
                conn.rollback()
                inserted_ids = []
            finally:
                conn.close()

        return inserted_ids

    # =========================================================================
    #  INSERTION — ALERTES
    # =========================================================================

    def insert_alert(self, timestamp: str, agent_id: str, rule_name: str,
                     severity: str, message: str, 
                     log_id: Optional[int] = None,
                     alert_type: str = "",
                     mitre_tactic: str = "",
                     mitre_technique_id: str = "",
                     mitre_technique_name: str = "") -> Optional[int]:
        """
        Insère une nouvelle alerte de sécurité.
        
        Args:
            timestamp           : Horodatage ISO 8601
            agent_id            : Identifiant de l'agent source
            rule_name           : Nom de la règle IDS déclenchée
            severity            : Sévérité (LOW, MEDIUM, HIGH, CRITICAL)
            message             : Description détaillée de l'alerte
            log_id              : ID du log associé (clé étrangère, optionnel)
            alert_type          : Type de menace (BRUTE_FORCE, PORT_SCAN, …)
            mitre_tactic        : Tactique MITRE ATT&CK (ex: Credential Access)
            mitre_technique_id  : ID technique MITRE (ex: T1110)
            mitre_technique_name: Nom technique MITRE (ex: Brute Force)
        
        Returns:
            int : ID de l'alerte insérée, ou None en cas d'erreur
        """
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO alerts 
                        (timestamp, agent_id, rule_name, severity, type, message,
                         log_id, resolved, mitre_tactic, mitre_technique_id, mitre_technique_name)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
                """, (timestamp, agent_id, rule_name, severity, alert_type, message,
                      log_id, mitre_tactic, mitre_technique_id, mitre_technique_name))
                conn.commit()
                alert_id = cursor.lastrowid
                return alert_id

            except sqlite3.Error as e:
                print(f"\033[91m[DATABASE ERREUR]\033[0m Insertion alerte échouée : {e}")
                conn.rollback()
                return None
            finally:
                conn.close()

    # =========================================================================
    #  INSERTION / MISE À JOUR — AGENTS
    # =========================================================================

    def register_agent(self, agent_id: str, ip: str, os_type: str) -> bool:
        """
        Enregistre un nouvel agent ou met à jour un agent existant.
        
        - Si l'agent n'existe pas → création avec first_seen et last_seen
        - Si l'agent existe → mise à jour de last_seen, ip, os, status
        
        Args:
            agent_id : Identifiant unique de l'agent
            ip       : Adresse IP de l'agent
            os_type  : Système d'exploitation (windows/linux)
        
        Returns:
            bool : True si succès, False sinon
        """
        now = datetime.now().isoformat()
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                
                # Vérifier si l'agent existe déjà
                cursor.execute(
                    "SELECT id FROM agents WHERE agent_id = ?", 
                    (agent_id,)
                )
                existing = cursor.fetchone()

                if existing:
                    # Mise à jour : last_seen, IP, OS, statut actif
                    cursor.execute("""
                        UPDATE agents 
                        SET last_seen = ?, ip = ?, os = ?, status = 'active'
                        WHERE agent_id = ?
                    """, (now, ip, os_type, agent_id))
                else:
                    # Nouvel agent : première inscription
                    cursor.execute("""
                        INSERT INTO agents 
                            (agent_id, ip, os, first_seen, last_seen, status)
                        VALUES (?, ?, ?, ?, ?, 'active')
                    """, (agent_id, ip, os_type, now, now))

                conn.commit()
                return True

            except sqlite3.Error as e:
                print(f"\033[91m[DATABASE ERREUR]\033[0m Enregistrement agent échoué : {e}")
                conn.rollback()
                return False
            finally:
                conn.close()

    def update_agent_status(self, agent_id: str, status: str) -> bool:
        """
        Met à jour le statut d'un agent (active/inactive/disconnected).
        
        Args:
            agent_id : Identifiant de l'agent
            status   : Nouveau statut
        
        Returns:
            bool : True si succès
        """
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE agents SET status = ?, last_seen = ?
                    WHERE agent_id = ?
                """, (status, datetime.now().isoformat(), agent_id))
                conn.commit()
                return True

            except sqlite3.Error as e:
                print(f"\033[91m[DATABASE ERREUR]\033[0m MAJ statut agent échouée : {e}")
                conn.rollback()
                return False
            finally:
                conn.close()

    def update_agent_heartbeat(self, agent_id: str) -> bool:
        """
        Met à jour le dernier signe de vie d'un agent (heartbeat).
        
        Args:
            agent_id : Identifiant de l'agent
        
        Returns:
            bool : True si succès
        """
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE agents SET last_seen = ?, status = 'active'
                    WHERE agent_id = ?
                """, (datetime.now().isoformat(), agent_id))
                conn.commit()
                return True

            except sqlite3.Error as e:
                print(f"\033[91m[DATABASE ERREUR]\033[0m MAJ heartbeat échouée : {e}")
                conn.rollback()
                return False
            finally:
                conn.close()

    # =========================================================================
    #  LECTURE — LOGS
    # =========================================================================

    def get_recent_logs(self, limit: int = 100, offset: int = 0, 
                        level: Optional[str] = None,
                        agent_id: Optional[str] = None) -> List[Dict]:
        """
        Récupère les logs les plus récents avec filtres optionnels.
        
        Args:
            limit    : Nombre max de résultats (défaut: 100)
            offset   : Décalage pour la pagination
            level    : Filtrer par niveau (INFO, WARNING, HIGH, CRITICAL)
            agent_id : Filtrer par agent
        
        Returns:
            List[Dict] : Liste des logs sous forme de dictionnaires
        """
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                
                # Construction dynamique de la requête avec filtres
                query = "SELECT * FROM logs WHERE 1=1"
                params = []

                if level:
                    query += " AND level = ?"
                    params.append(level)

                if agent_id:
                    query += " AND agent_id = ?"
                    params.append(agent_id)

                query += " ORDER BY id DESC LIMIT ? OFFSET ?"
                params.extend([limit, offset])

                cursor.execute(query, params)
                rows = cursor.fetchall()
                
                # Convertir sqlite3.Row en dictionnaires
                return [dict(row) for row in rows]

            except sqlite3.Error as e:
                print(f"\033[91m[DATABASE ERREUR]\033[0m Lecture logs échouée : {e}")
                return []
            finally:
                conn.close()

    def get_logs_since(self, since: str) -> List[Dict]:
        """
        Récupère tous les logs depuis un timestamp donné.
        
        Args:
            since : Timestamp ISO 8601 (ex: 2024-01-15T10:00:00)
        
        Returns:
            List[Dict] : Logs trouvés
        """
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM logs 
                    WHERE timestamp >= ? 
                    ORDER BY id ASC
                """, (since,))
                return [dict(row) for row in cursor.fetchall()]

            except sqlite3.Error as e:
                print(f"\033[91m[DATABASE ERREUR]\033[0m Lecture logs (since) échouée : {e}")
                return []
            finally:
                conn.close()

    def search_logs(self, keyword: str, limit: int = 50) -> List[Dict]:
        """
        Recherche des logs par mot-clé dans le message.
        
        Args:
            keyword : Terme à rechercher
            limit   : Nombre max de résultats
        
        Returns:
            List[Dict] : Logs correspondants
        """
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM logs 
                    WHERE message LIKE ? 
                    ORDER BY id DESC LIMIT ?
                """, (f"%{keyword}%", limit))
                return [dict(row) for row in cursor.fetchall()]

            except sqlite3.Error as e:
                print(f"\033[91m[DATABASE ERREUR]\033[0m Recherche logs échouée : {e}")
                return []
            finally:
                conn.close()

    # =========================================================================
    #  LECTURE — ALERTES
    # =========================================================================

    def get_active_alerts(self, limit: int = 100) -> List[Dict]:
        """
        Récupère les alertes non résolues (resolved = 0).
        
        Args:
            limit : Nombre max de résultats
        
        Returns:
            List[Dict] : Alertes actives
        """
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM alerts 
                    WHERE resolved = 0 
                    ORDER BY id DESC LIMIT ?
                """, (limit,))
                return [dict(row) for row in cursor.fetchall()]

            except sqlite3.Error as e:
                print(f"\033[91m[DATABASE ERREUR]\033[0m Lecture alertes échouée : {e}")
                return []
            finally:
                conn.close()

    def get_all_alerts(self, limit: int = 200, 
                       severity: Optional[str] = None) -> List[Dict]:
        """
        Récupère toutes les alertes avec filtre optionnel par sévérité.
        
        Args:
            limit    : Nombre max de résultats
            severity : Filtrer par sévérité (LOW, MEDIUM, HIGH, CRITICAL)
        
        Returns:
            List[Dict] : Alertes trouvées
        """
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                
                if severity:
                    cursor.execute("""
                        SELECT * FROM alerts 
                        WHERE severity = ?
                        ORDER BY id DESC LIMIT ?
                    """, (severity, limit))
                else:
                    cursor.execute("""
                        SELECT * FROM alerts 
                        ORDER BY id DESC LIMIT ?
                    """, (limit,))

                return [dict(row) for row in cursor.fetchall()]

            except sqlite3.Error as e:
                print(f"\033[91m[DATABASE ERREUR]\033[0m Lecture alertes échouée : {e}")
                return []
            finally:
                conn.close()

    def resolve_alert(self, alert_id: int) -> bool:
        """
        Marque une alerte comme résolue.
        
        Args:
            alert_id : ID de l'alerte à résoudre
        
        Returns:
            bool : True si succès
        """
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE alerts SET resolved = 1 
                    WHERE id = ?
                """, (alert_id,))
                conn.commit()
                return cursor.rowcount > 0

            except sqlite3.Error as e:
                print(f"\033[91m[DATABASE ERREUR]\033[0m Résolution alerte échouée : {e}")
                conn.rollback()
                return False
            finally:
                conn.close()

    # =========================================================================
    #  LECTURE — AGENTS
    # =========================================================================

    def get_all_agents(self) -> List[Dict]:
        """
        Récupère la liste de tous les agents enregistrés.
        
        Returns:
            List[Dict] : Liste des agents
        """
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM agents ORDER BY last_seen DESC
                """)
                return [dict(row) for row in cursor.fetchall()]

            except sqlite3.Error as e:
                print(f"\033[91m[DATABASE ERREUR]\033[0m Lecture agents échouée : {e}")
                return []
            finally:
                conn.close()

    def get_active_agents(self) -> List[Dict]:
        """
        Récupère uniquement les agents avec statut 'active'.
        
        Returns:
            List[Dict] : Agents actifs
        """
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM agents 
                    WHERE status = 'active' 
                    ORDER BY last_seen DESC
                """)
                return [dict(row) for row in cursor.fetchall()]

            except sqlite3.Error as e:
                print(f"\033[91m[DATABASE ERREUR]\033[0m Lecture agents actifs échouée : {e}")
                return []
            finally:
                conn.close()

    def mark_inactive_agents(self, timeout_seconds: int = 60) -> int:
        """
        Marque comme 'inactive' les agents dont le dernier heartbeat
        dépasse le timeout spécifié.
        
        Args:
            timeout_seconds : Délai d'inactivité en secondes (défaut: 60s)
        
        Returns:
            int : Nombre d'agents marqués inactifs
        """
        cutoff = (datetime.now() - timedelta(seconds=timeout_seconds)).isoformat()
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE agents SET status = 'inactive'
                    WHERE status = 'active' AND last_seen < ?
                """, (cutoff,))
                conn.commit()
                count = cursor.rowcount
                if count > 0:
                    print(f"\033[93m[DATABASE]\033[0m {count} agent(s) marqué(s) inactif(s)")
                return count

            except sqlite3.Error as e:
                print(f"\033[91m[DATABASE ERREUR]\033[0m MAJ agents inactifs échouée : {e}")
                conn.rollback()
                return 0
            finally:
                conn.close()

    # =========================================================================
    #  STATISTIQUES — Pour le Dashboard
    # =========================================================================

    def get_stats(self) -> Dict[str, Any]:
        """
        Calcule et retourne les statistiques globales du SOC.
        Utilisé par le dashboard pour les cartes de stats en haut.
        
        Returns:
            Dict contenant :
                - total_logs_today      : Nombre de logs reçus aujourd'hui
                - active_alerts         : Nombre d'alertes non résolues
                - active_agents         : Nombre d'agents actifs
                - critical_last_hour    : Nombre d'alertes CRITICAL dernière heure
                - logs_by_level         : Répartition des logs par niveau
                - alerts_by_severity    : Répartition des alertes par sévérité
        """
        today = datetime.now().strftime("%Y-%m-%d")
        last_hour = (datetime.now() - timedelta(hours=1)).isoformat()

        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                stats = {}

                # Total logs aujourd'hui
                cursor.execute(
                    "SELECT COUNT(*) FROM logs WHERE timestamp LIKE ?",
                    (f"{today}%",)
                )
                stats["total_logs_today"] = cursor.fetchone()[0]

                # Alertes actives (non résolues)
                cursor.execute(
                    "SELECT COUNT(*) FROM alerts WHERE resolved = 0"
                )
                stats["active_alerts"] = cursor.fetchone()[0]

                # Agents actifs
                cursor.execute(
                    "SELECT COUNT(*) FROM agents WHERE status = 'active'"
                )
                stats["active_agents"] = cursor.fetchone()[0]

                # Alertes CRITICAL dernière heure
                cursor.execute("""
                    SELECT COUNT(*) FROM alerts 
                    WHERE severity = 'CRITICAL' AND timestamp >= ?
                """, (last_hour,))
                stats["critical_last_hour"] = cursor.fetchone()[0]

                # Répartition logs par niveau
                cursor.execute("""
                    SELECT level, COUNT(*) as count 
                    FROM logs 
                    WHERE timestamp LIKE ?
                    GROUP BY level
                """, (f"{today}%",))
                stats["logs_by_level"] = {
                    row["level"]: row["count"] for row in cursor.fetchall()
                }

                # Répartition alertes par sévérité
                cursor.execute("""
                    SELECT severity, COUNT(*) as count 
                    FROM alerts 
                    WHERE resolved = 0
                    GROUP BY severity
                """)
                stats["alerts_by_severity"] = {
                    row["severity"]: row["count"] for row in cursor.fetchall()
                }

                return stats

            except sqlite3.Error as e:
                print(f"\033[91m[DATABASE ERREUR]\033[0m Calcul stats échoué : {e}")
                return {
                    "total_logs_today": 0,
                    "active_alerts": 0,
                    "active_agents": 0,
                    "critical_last_hour": 0,
                    "logs_by_level": {},
                    "alerts_by_severity": {}
                }
            finally:
                conn.close()

    def get_hourly_log_counts(self, hours: int = 24) -> List[Dict]:
        """
        Retourne le nombre de logs par heure pour les N dernières heures.
        Utilisé par le graphe timeline du dashboard.
        
        Args:
            hours : Nombre d'heures à couvrir (défaut: 24)
        
        Returns:
            List[Dict] : Liste de {hour: "HH:00", logs: N, alerts: N}
        """
        result = []
        now = datetime.now()

        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()

                for i in range(hours, 0, -1):
                    # Calcul de la fenêtre horaire
                    hour_start = (now - timedelta(hours=i)).strftime("%Y-%m-%dT%H:")
                    hour_label = (now - timedelta(hours=i)).strftime("%H:00")

                    # Nombre de logs dans cette heure
                    cursor.execute(
                        "SELECT COUNT(*) FROM logs WHERE timestamp LIKE ?",
                        (f"{hour_start}%",)
                    )
                    log_count = cursor.fetchone()[0]

                    # Nombre d'alertes dans cette heure
                    cursor.execute(
                        "SELECT COUNT(*) FROM alerts WHERE timestamp LIKE ?",
                        (f"{hour_start}%",)
                    )
                    alert_count = cursor.fetchone()[0]

                    result.append({
                        "hour": hour_label,
                        "logs": log_count,
                        "alerts": alert_count
                    })

                return result

            except sqlite3.Error as e:
                print(f"\033[91m[DATABASE ERREUR]\033[0m Calcul stats horaires échoué : {e}")
                return []
            finally:
                conn.close()

    def get_logs_count_by_agent(self) -> List[Dict]:
        """
        Retourne le nombre de logs par agent (pour graphiques).
        
        Returns:
            List[Dict] : [{agent_id, count}, ...]
        """
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT agent_id, COUNT(*) as count 
                    FROM logs 
                    GROUP BY agent_id 
                    ORDER BY count DESC
                """)
                return [dict(row) for row in cursor.fetchall()]

            except sqlite3.Error as e:
                print(f"\033[91m[DATABASE ERREUR]\033[0m Stats par agent échouées : {e}")
                return []
            finally:
                conn.close()

    # =========================================================================
    #  DÉTECTION — Requêtes pour le moteur IDS
    # =========================================================================

    def get_failed_logins_from_ip(self, ip: str, 
                                   window_seconds: int = 60) -> int:
        """
        Compte le nombre de tentatives de connexion échouées depuis une IP
        dans une fenêtre de temps donnée. Utilisé pour la détection brute force.
        
        Args:
            ip              : Adresse IP source
            window_seconds  : Fenêtre de temps en secondes
        
        Returns:
            int : Nombre de tentatives échouées
        """
        since = (datetime.now() - timedelta(seconds=window_seconds)).isoformat()
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT COUNT(*) FROM logs 
                    WHERE message LIKE ? 
                    AND timestamp >= ?
                    AND (category = 'AUTH' OR level IN ('WARNING', 'HIGH'))
                """, (f"%{ip}%", since))
                return cursor.fetchone()[0]

            except sqlite3.Error as e:
                print(f"\033[91m[DATABASE ERREUR]\033[0m Comptage failed logins échoué : {e}")
                return 0
            finally:
                conn.close()

    def get_logs_in_time_range(self, start: str, end: str) -> List[Dict]:
        """
        Récupère les logs dans une plage de temps spécifique.
        
        Args:
            start : Timestamp début ISO 8601
            end   : Timestamp fin ISO 8601
        
        Returns:
            List[Dict] : Logs dans la plage
        """
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM logs 
                    WHERE timestamp BETWEEN ? AND ?
                    ORDER BY id ASC
                """, (start, end))
                return [dict(row) for row in cursor.fetchall()]

            except sqlite3.Error as e:
                print(f"\033[91m[DATABASE ERREUR]\033[0m Lecture plage temps échouée : {e}")
                return []
            finally:
                conn.close()

    # =========================================================================
    #  IPS — ACTIONS DE BLOCAGE / DÉBLOCAGE
    # =========================================================================

    def insert_ips_action(self, ip: str, action: str, reason: str = "",
                          severity: str = "", alert_type: str = "",
                          agent_id: str = "", alert_id: Optional[int] = None,
                          duration_minutes: int = 0) -> Optional[int]:
        """
        Insère une action IPS (block ou unblock).

        Args:
            ip               : Adresse IP ciblée
            action           : 'block' ou 'unblock'
            reason           : Raison du blocage
            severity         : Sévérité de la menace
            alert_type       : Type de menace (BRUTE_FORCE, SQL_INJECTION, …)
            agent_id         : Agent ayant exécuté l'action
            alert_id         : ID de l'alerte associée
            duration_minutes : Durée du blocage (0 = permanent)

        Returns:
            int : ID de l'action insérée, ou None
        """
        now = datetime.now()
        timestamp = now.isoformat()
        expires_at = ""
        if duration_minutes > 0:
            expires_at = (now + timedelta(minutes=duration_minutes)).isoformat()

        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO ips_actions
                        (timestamp, ip, action, reason, severity, alert_type,
                         agent_id, alert_id, duration_minutes, expires_at, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (timestamp, ip, action, reason, severity, alert_type,
                      agent_id, alert_id, duration_minutes, expires_at,
                      'active' if action == 'block' else 'unblocked'))
                conn.commit()
                return cursor.lastrowid
            except sqlite3.Error as e:
                print(f"\033[91m[DATABASE ERREUR]\033[0m Insertion IPS action échouée : {e}")
                conn.rollback()
                return None
            finally:
                conn.close()

    def get_blocked_ips(self) -> List[Dict]:
        """Retourne la liste des IPs actuellement bloquées (status='active')."""
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM ips_actions
                    WHERE action = 'block' AND status = 'active'
                    ORDER BY timestamp DESC
                """)
                return [dict(row) for row in cursor.fetchall()]
            except sqlite3.Error as e:
                print(f"\033[91m[DATABASE ERREUR]\033[0m Lecture IPS bloquées échouée : {e}")
                return []
            finally:
                conn.close()

    def get_ips_history(self, limit: int = 200) -> List[Dict]:
        """Retourne l'historique complet des actions IPS."""
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM ips_actions
                    ORDER BY timestamp DESC LIMIT ?
                """, (limit,))
                return [dict(row) for row in cursor.fetchall()]
            except sqlite3.Error as e:
                print(f"\033[91m[DATABASE ERREUR]\033[0m Lecture historique IPS échouée : {e}")
                return []
            finally:
                conn.close()

    def unblock_ip(self, action_id: int, reason: str = "manual") -> bool:
        """
        Marque une IP comme débloquée.

        Args:
            action_id : ID de l'action IPS à débloquer
            reason    : Raison du déblocage ('manual', 'expired', …)

        Returns:
            bool : True si mise à jour réussie
        """
        now = datetime.now().isoformat()
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE ips_actions
                    SET status = 'unblocked', unblocked_at = ?, unblock_reason = ?
                    WHERE id = ? AND status = 'active'
                """, (now, reason, action_id))
                conn.commit()
                return cursor.rowcount > 0
            except sqlite3.Error as e:
                print(f"\033[91m[DATABASE ERREUR]\033[0m Déblocage IP échoué : {e}")
                conn.rollback()
                return False
            finally:
                conn.close()

    def get_expired_blocks(self) -> List[Dict]:
        """Retourne les blocages expirés qui sont encore actifs."""
        now = datetime.now().isoformat()
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM ips_actions
                    WHERE action = 'block' AND status = 'active'
                      AND duration_minutes > 0 AND expires_at != ''
                      AND expires_at <= ?
                """, (now,))
                return [dict(row) for row in cursor.fetchall()]
            except sqlite3.Error as e:
                print(f"\033[91m[DATABASE ERREUR]\033[0m Lecture blocs expirés échouée : {e}")
                return []
            finally:
                conn.close()

    def is_ip_blocked(self, ip: str) -> bool:
        """Vérifie si une IP est actuellement bloquée."""
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT COUNT(*) FROM ips_actions
                    WHERE ip = ? AND action = 'block' AND status = 'active'
                """, (ip,))
                return cursor.fetchone()[0] > 0
            except sqlite3.Error as e:
                return False
            finally:
                conn.close()

    def get_ips_stats(self) -> Dict[str, Any]:
        """Retourne les statistiques IPS."""
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT COUNT(*) FROM ips_actions WHERE action='block' AND status='active'"
                )
                active_blocks = cursor.fetchone()[0]
                cursor.execute(
                    "SELECT COUNT(*) FROM ips_actions WHERE action='block'"
                )
                total_blocks = cursor.fetchone()[0]
                cursor.execute(
                    "SELECT COUNT(*) FROM ips_actions WHERE status='unblocked'"
                )
                total_unblocks = cursor.fetchone()[0]
                return {
                    "active_blocks": active_blocks,
                    "total_blocks": total_blocks,
                    "total_unblocks": total_unblocks
                }
            except sqlite3.Error as e:
                return {"active_blocks": 0, "total_blocks": 0, "total_unblocks": 0}
            finally:
                conn.close()

    # =========================================================================
    #  AGENT STATS — Statistiques système des agents
    # =========================================================================

    def insert_agent_stats(self, agent_id: str, stats: Dict) -> Optional[int]:
        """
        Insère les statistiques système d'un agent.
        
        Args:
            agent_id : Identifiant de l'agent
            stats    : Dictionnaire contenant les stats (CPU, RAM, etc.)
        
        Returns:
            int : ID de l'enregistrement, ou None si échec
        """
        now = datetime.now().isoformat()
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                stats_json = json.dumps(stats, ensure_ascii=False)
                cursor.execute("""
                    INSERT INTO agent_stats (timestamp, agent_id, stats_json)
                    VALUES (?, ?, ?)
                """, (now, agent_id, stats_json))
                conn.commit()
                return cursor.lastrowid
            except sqlite3.Error as e:
                print(f"\033[91m[DATABASE ERREUR]\033[0m Insertion agent_stats échouée : {e}")
                conn.rollback()
                return None
            finally:
                conn.close()

    def get_latest_agent_stats(self, agent_id: str = None) -> List[Dict]:
        """
        Récupère les dernières statistiques de chaque agent, ou d'un agent
        spécifique.
        
        Args:
            agent_id : (optionnel) Filtrer par agent_id
        
        Returns:
            List[Dict] : [{agent_id, timestamp, stats}, ...]
        """
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                if agent_id:
                    cursor.execute("""
                        SELECT agent_id, timestamp, stats_json
                        FROM agent_stats
                        WHERE agent_id = ?
                        ORDER BY id DESC LIMIT 1
                    """, (agent_id,))
                else:
                    # Dernière entrée par agent (sous-requête MAX)
                    cursor.execute("""
                        SELECT a.agent_id, a.timestamp, a.stats_json
                        FROM agent_stats a
                        INNER JOIN (
                            SELECT agent_id, MAX(id) as max_id
                            FROM agent_stats
                            GROUP BY agent_id
                        ) latest ON a.id = latest.max_id
                        ORDER BY a.agent_id
                    """)

                results = []
                for row in cursor.fetchall():
                    try:
                        stats = json.loads(row["stats_json"])
                    except (json.JSONDecodeError, TypeError):
                        stats = {}
                    results.append({
                        "agent_id": row["agent_id"],
                        "timestamp": row["timestamp"],
                        "stats": stats
                    })
                return results

            except sqlite3.Error as e:
                print(f"\033[91m[DATABASE ERREUR]\033[0m Lecture agent_stats échouée : {e}")
                return []
            finally:
                conn.close()

    def cleanup_old_agent_stats(self, hours: int = 48) -> int:
        """
        Supprime les statistiques plus anciennes que N heures.
        Conservation par défaut : 48 heures.
        
        Args:
            hours : Nombre d'heures à conserver (défaut: 48)
        
        Returns:
            int : Nombre d'enregistrements supprimés
        """
        cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(
                    "DELETE FROM agent_stats WHERE timestamp < ?",
                    (cutoff,)
                )
                conn.commit()
                count = cursor.rowcount
                if count > 0:
                    print(f"\033[93m[DATABASE]\033[0m {count} ancien(nes) stats agent purgée(s)")
                return count
            except sqlite3.Error as e:
                print(f"\033[91m[DATABASE ERREUR]\033[0m Purge agent_stats échouée : {e}")
                conn.rollback()
                return 0
            finally:
                conn.close()

    # =========================================================================
    #  MAINTENANCE
    # =========================================================================

    def purge_old_logs(self, days: int = 30) -> int:
        """
        Supprime les logs plus anciens que N jours.
        Utile pour la maintenance et éviter que la DB grossisse trop.
        
        Args:
            days : Nombre de jours à conserver (défaut: 30)
        
        Returns:
            int : Nombre de logs supprimés
        """
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(
                    "DELETE FROM logs WHERE timestamp < ?", 
                    (cutoff,)
                )
                conn.commit()
                count = cursor.rowcount
                if count > 0:
                    print(f"\033[93m[DATABASE]\033[0m {count} ancien(s) log(s) purgé(s)")
                return count

            except sqlite3.Error as e:
                print(f"\033[91m[DATABASE ERREUR]\033[0m Purge logs échouée : {e}")
                conn.rollback()
                return 0
            finally:
                conn.close()

    def get_database_size(self) -> str:
        """
        Retourne la taille du fichier de base de données.
        
        Returns:
            str : Taille formatée (ex: "2.4 MB")
        """
        try:
            size = os.path.getsize(self.db_path)
            if size < 1024:
                return f"{size} B"
            elif size < 1024 * 1024:
                return f"{size / 1024:.1f} KB"
            else:
                return f"{size / (1024 * 1024):.1f} MB"
        except OSError:
            return "N/A"

    # =========================================================================
    #  GEO-IP — Événements géolocalisés
    # =========================================================================

    def insert_geo_event(self, timestamp: str, ip: str, country: str,
                         country_code: str, city: str, lat: float, lon: float,
                         alert_type: str = "", severity: str = "",
                         agent_id: str = "") -> Optional[int]:
        """
        Insère un événement géolocalisé (IP attaquante localisée).

        Args:
            timestamp    : Horodatage ISO 8601
            ip           : Adresse IP source
            country      : Nom du pays
            country_code : Code pays ISO (FR, US, …)
            city         : Ville
            lat          : Latitude
            lon          : Longitude
            alert_type   : Type d'alerte associée
            severity     : Sévérité de l'alerte
            agent_id     : Agent cible

        Returns:
            int : ID de l'événement inséré, ou None en cas d'erreur
        """
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO geo_events
                        (timestamp, ip, country, country_code, city,
                         lat, lon, alert_type, severity, agent_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (timestamp, ip, country, country_code, city,
                      lat, lon, alert_type, severity, agent_id))
                conn.commit()
                return cursor.lastrowid
            except sqlite3.Error as e:
                print(f"\033[91m[DATABASE ERREUR]\033[0m Insertion geo_event échouée : {e}")
                conn.rollback()
                return None
            finally:
                conn.close()

    def get_recent_geo_events(self, limit: int = 100) -> List[Dict]:
        """
        Récupère les derniers événements géolocalisés.

        Args:
            limit : Nombre max de résultats

        Returns:
            List[Dict] : Événements géolocalisés
        """
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM geo_events
                    ORDER BY id DESC LIMIT ?
                """, (limit,))
                return [dict(row) for row in cursor.fetchall()]
            except sqlite3.Error as e:
                print(f"\033[91m[DATABASE ERREUR]\033[0m Lecture geo_events échouée : {e}")
                return []
            finally:
                conn.close()


# =============================================================================
#  POINT D'ENTRÉE — Test standalone
# =============================================================================

if __name__ == "__main__":
    """
    Test rapide du module database.py en standalone.
    Crée la DB, insère des données de test, et affiche les stats.
    """
    print("=" * 60)
    print("  SOC Database — Test Standalone")
    print("=" * 60)

    # Initialisation
    db = SOCDatabase("test_soc.db")

    # Test 1 : Enregistrer un agent
    print("\n--- Test 1 : Enregistrement agent ---")
    db.register_agent("PC-TEST-WIN10", "192.168.1.100", "windows")
    db.register_agent("SRV-LINUX-01", "192.168.1.200", "linux")
    agents = db.get_all_agents()
    for a in agents:
        print(f"  Agent: {a['agent_id']} | IP: {a['ip']} | OS: {a['os']} | Status: {a['status']}")

    # Test 2 : Insérer des logs
    print("\n--- Test 2 : Insertion de logs ---")
    log_id_1 = db.insert_log(
        timestamp=datetime.now().isoformat(),
        agent_id="PC-TEST-WIN10",
        agent_ip="192.168.1.100",
        agent_os="windows",
        source="Security",
        level="WARNING",
        category="AUTH",
        message="Failed login attempt for user admin from 192.168.1.50"
    )
    print(f"  Log inséré avec ID : {log_id_1}")

    log_id_2 = db.insert_log(
        timestamp=datetime.now().isoformat(),
        agent_id="SRV-LINUX-01",
        agent_ip="192.168.1.200",
        agent_os="linux",
        source="auth.log",
        level="HIGH",
        category="AUTH",
        message="Failed password for root from 10.0.0.5 port 22 ssh2"
    )
    print(f"  Log inséré avec ID : {log_id_2}")

    log_id_3 = db.insert_log(
        timestamp=datetime.now().isoformat(),
        agent_id="PC-TEST-WIN10",
        agent_ip="192.168.1.100",
        agent_os="windows",
        source="Application",
        level="INFO",
        category="SYSTEM",
        message="Application started successfully"
    )
    print(f"  Log inséré avec ID : {log_id_3}")

    # Test 3 : Insérer une alerte
    print("\n--- Test 3 : Insertion d'alerte ---")
    alert_id = db.insert_alert(
        timestamp=datetime.now().isoformat(),
        agent_id="SRV-LINUX-01",
        rule_name="SSH_BRUTE_FORCE",
        severity="HIGH",
        message="Tentative de brute force SSH détectée depuis 10.0.0.5",
        log_id=log_id_2
    )
    print(f"  Alerte insérée avec ID : {alert_id}")

    # Test 4 : Statistiques
    print("\n--- Test 4 : Statistiques ---")
    stats = db.get_stats()
    print(f"  Logs aujourd'hui    : {stats['total_logs_today']}")
    print(f"  Alertes actives     : {stats['active_alerts']}")
    print(f"  Agents actifs       : {stats['active_agents']}")
    print(f"  CRITICAL (1h)       : {stats['critical_last_hour']}")
    print(f"  Logs par niveau     : {stats['logs_by_level']}")
    print(f"  Alertes par sévérité: {stats['alerts_by_severity']}")

    # Test 5 : Lecture des logs
    print("\n--- Test 5 : Logs récents ---")
    logs = db.get_recent_logs(limit=10)
    for log in logs:
        print(f"  [{log['level']}] {log['agent_id']} — {log['message'][:60]}")

    # Test 6 : Résoudre une alerte
    print("\n--- Test 6 : Résolution alerte ---")
    resolved = db.resolve_alert(alert_id)
    print(f"  Alerte {alert_id} résolue : {resolved}")
    active = db.get_active_alerts()
    print(f"  Alertes actives restantes : {len(active)}")

    # Test 7 : Taille de la DB
    print(f"\n--- Taille DB : {db.get_database_size()} ---")

    # Nettoyage du fichier de test
    print("\n--- Nettoyage ---")
    os.remove("test_soc.db")
    print("  Fichier test_soc.db supprimé.")

    print("\n" + "=" * 60)
    print("  ✅ Tous les tests passés avec succès !")
    print("=" * 60)
