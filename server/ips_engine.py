"""
=============================================================================
 Oktopus — Moteur IPS (Intrusion Prevention System)
=============================================================================
 Fichier : server/ips_engine.py
 Rôle    : Moteur de prévention d'intrusion
           - Reçoit les alertes du detector.py
           - Décide automatiquement de bloquer ou non selon la sévérité
           - Envoie les commandes de blocage aux agents via TCP
           - Gère la whitelist (IPs à ne jamais bloquer)
           - Auto-déblocage après expiration (thread dédié)
           - Historique complet en SQLite

 Architecture :
   detector.py → ips_engine.py → agent/blocker.py
                      ↕
                  database.py (ips_actions table)
                      ↕
                  ws_server.py → dashboard

 Auteur  : Oktopus Team
 Date    : 2026-02-27
 Python  : 3.8+
=============================================================================
"""

import re
import json
import time
import socket
import threading
import subprocess
import platform
from datetime import datetime
from typing import Dict, List, Optional, Set


class IPSEngine:
    """
    Moteur IPS — analyse les alertes et déclenche les blocages automatiques.

    Attributs :
        db          : Instance SOCDatabase
        ws_server   : Instance WebSocketServer (pour broadcast au dashboard)
        clients     : Référence aux clients TCP connectés {agent_id: {socket, …}}
        clients_lock: Lock pour accès concurrent aux clients
        whitelist   : Set d'IPs à ne jamais bloquer
        rules       : Règles de blocage par type/sévérité
        enabled     : IPS activé ou non
    """

    # =========================================================================
    #  WHITELIST — IPs à ne jamais bloquer
    # =========================================================================
    DEFAULT_WHITELIST = {
        "127.0.0.1",
        "0.0.0.0",
        "::1",
        "localhost",
    }

    # =========================================================================
    #  RÈGLES DE BLOCAGE AUTOMATIQUE
    # =========================================================================
    # Format : { "type_pattern": { "severity": (action, duration_minutes) } }
    # duration_minutes = 0 → blocage permanent
    BLOCKING_RULES = {
        "BRUTE_FORCE": {
            "CRITICAL": ("block", 60),
            "HIGH":     ("block", 30),
            "MEDIUM":   ("log_only", 0),
        },
        "SQL_INJECTION": {
            "CRITICAL": ("block", 0),      # Permanent
            "HIGH":     ("block", 120),
            "MEDIUM":   ("block", 60),
        },
        "PORT_SCAN": {
            "CRITICAL": ("block", 60),
            "HIGH":     ("block", 30),
            "MEDIUM":   ("log_only", 0),
        },
        "XSS": {
            "CRITICAL": ("block", 60),
            "HIGH":     ("block", 15),
            "MEDIUM":   ("log_only", 0),
        },
        "MALWARE": {
            "CRITICAL": ("block", 0),      # Permanent
            "HIGH":     ("block", 120),
            "MEDIUM":   ("block", 60),
        },
        "PATH_TRAVERSAL": {
            "CRITICAL": ("block", 120),
            "HIGH":     ("block", 60),
            "MEDIUM":   ("log_only", 0),
        },
        "PRIV_ESC": {
            "CRITICAL": ("block", 0),      # Permanent
            "HIGH":     ("block", 60),
        },
        "EXFILTRATION": {
            "CRITICAL": ("block", 0),      # Permanent
            "HIGH":     ("block", 120),
        },
        "RECON": {
            "HIGH":     ("block", 30),
            "MEDIUM":   ("log_only", 0),
        },
        "SUSPICIOUS_CONNECTION": {
            "HIGH":     ("block", 15),
            "MEDIUM":   ("log_only", 0),
        },
        "LOG_TAMPERING": {
            "CRITICAL": ("block", 0),      # Permanent
            "HIGH":     ("block", 60),
        },
        # ---- Nouvelles règles inspirées de l'IDS engine ----
        "DDOS": {
            "CRITICAL": ("block", 30),
            "HIGH":     ("block", 15),
            "MEDIUM":   ("log_only", 0),
        },
        "SMB_EXPLOIT": {
            "CRITICAL": ("block", 0),      # Permanent — EternalBlue
            "HIGH":     ("block", 120),
        },
        "DNS_TUNNEL": {
            "CRITICAL": ("block", 0),      # Permanent
            "HIGH":     ("block", 60),
        },
        "C2": {
            "CRITICAL": ("block", 0),      # Permanent
            "HIGH":     ("block", 120),
        },
        "ANOMALY": {
            "HIGH":     ("block", 15),
            "MEDIUM":   ("log_only", 0),
        },
        # ---- Nouvelles règles IDS ----
        "COMMAND_INJECTION": {
            "CRITICAL": ("block", 0),      # Permanent
            "HIGH":     ("block", 120),
            "MEDIUM":   ("block", 60),
        },
        "LDAP_INJECTION": {
            "CRITICAL": ("block", 0),      # Permanent
            "HIGH":     ("block", 120),
        },
        "XXE": {
            "CRITICAL": ("block", 0),      # Permanent
            "HIGH":     ("block", 120),
        },
        "LFI": {
            "CRITICAL": ("block", 0),      # Permanent
            "HIGH":     ("block", 60),
        },
        "REVERSE_SHELL": {
            "CRITICAL": ("block", 0),      # Permanent
            "HIGH":     ("block", 120),
        },
        "LATERAL_MOVEMENT": {
            "CRITICAL": ("block", 0),      # Permanent
            "HIGH":     ("block", 60),
        },
        "PERSISTENCE": {
            "CRITICAL": ("block", 60),
            "HIGH":     ("block", 30),
        },
        "TOR": {
            "CRITICAL": ("block", 60),
            "HIGH":     ("block", 30),
            "MEDIUM":   ("log_only", 0),
        },
        "VPN_SUSPICIOUS": {
            "HIGH":     ("block", 30),
            "MEDIUM":   ("log_only", 0),
        },
        "MALFORMED_DATA_FLOOD": {
            "CRITICAL": ("block", 60),
            "HIGH":     ("block", 30),
        },
    }

    # Regex pour extraire des IPs depuis les messages d'alerte
    IP_REGEX = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')

    def __init__(self, database, ws_server=None, clients=None,
                 clients_lock=None, config: Dict = None):
        """
        Initialise le moteur IPS.

        Args:
            database     : Instance SOCDatabase
            ws_server    : Instance WebSocketServer
            clients      : Dict des agents TCP connectés
            clients_lock : threading.Lock pour les clients
            config       : Configuration optionnelle
        """
        self.db = database
        self.ws_server = ws_server
        self.clients = clients or {}
        self.clients_lock = clients_lock or threading.Lock()
        self.enabled = True
        self._running = False

        # --- Blocage local direct (firewall du serveur) ---
        self._local_blocked_ips: Set[str] = set()
        self._local_os = platform.system().lower()
        self._local_has_admin = self._check_local_admin()

        # Whitelist
        self.whitelist: Set[str] = set(self.DEFAULT_WHITELIST)
        if config and "ips" in config:
            ips_conf = config["ips"]
            self.enabled = ips_conf.get("enabled", True)
            extra_whitelist = ips_conf.get("whitelist", [])
            self.whitelist.update(extra_whitelist)
            self._cooldown_seconds = ips_conf.get("cooldown_seconds", 60)
        else:
            self._cooldown_seconds = 60

        # Auto-whitelist : ajouter l'IP locale du serveur pour éviter l'auto-blocage
        self._auto_whitelist_local_ips()

        # Cooldown : empêcher le re-blocage trop rapide de la même IP
        # {ip: last_block_timestamp}
        self._block_cooldown: Dict[str, float] = {}

        # Stats
        self.total_blocks = 0
        self.total_skipped = 0

        print(f"\033[95m[IPS]\033[0m Moteur IPS initialisé "
              f"({'ACTIVÉ' if self.enabled else 'DÉSACTIVÉ'})")
        print(f"\033[95m[IPS]\033[0m Whitelist : {', '.join(sorted(self.whitelist))}")
        print(f"\033[95m[IPS]\033[0m Cooldown blocage : {self._cooldown_seconds}s")
        print(f"\033[95m[IPS]\033[0m Règles : {len(self.BLOCKING_RULES)} types de menace configurés")
        admin_str = '✓ ADMIN' if self._local_has_admin else '✗ PAS ADMIN'
        print(f"\033[95m[IPS]\033[0m Blocage local ({self._local_os}) : {admin_str}")

        # Restaurer les IPs bloquées depuis la DB (survie au redémarrage)
        self._sync_blocked_ips_from_db()

    def _auto_whitelist_local_ips(self):
        """
        Ajoute automatiquement les IPs locales du serveur à la whitelist
        pour éviter l'auto-blocage accidentel.
        """
        try:
            hostname = socket.gethostname()
            # Obtenir toutes les IPs associées au hostname
            local_ips = socket.gethostbyname_ex(hostname)[2]
            for ip in local_ips:
                self.whitelist.add(ip)
        except Exception:
            pass

        # Aussi ajouter l'IP obtenue via la méthode UDP
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            self.whitelist.add(local_ip)
        except Exception:
            pass

    # =========================================================================
    #  ANALYSE DES ALERTES — Point d'entrée principal
    # =========================================================================

    def process_alert(self, alert: Dict, agent_id: str, alert_id: Optional[int] = None):
        """
        Traite une alerte générée par le détecteur et décide de bloquer ou non.

        Args:
            alert    : Dict alerte {type, severity, message, timestamp, …}
            agent_id : ID de l'agent source
            alert_id : ID de l'alerte en DB (si disponible)
        """
        if not self.enabled:
            return

        alert_type = alert.get("type", "").upper()
        severity = alert.get("severity", "MEDIUM").upper()
        message = alert.get("message", "")
        timestamp = alert.get("timestamp", datetime.now().isoformat())

        # Extraire les IPs du message de l'alerte
        source_ips = self._extract_ips(message)

        # Aussi essayer d'extraire l'IP depuis le champ agent_ip
        # (utile quand le message ne contient pas d'IP directement)
        alert_agent_ip = alert.get("agent_ip", "")
        if alert_agent_ip and alert_agent_ip not in self.whitelist:
            # Pour certains types (brute force par agent), l'IP de l'attaquant
            # peut être dans le message ; ne pas prendre l'IP de l'agent lui-même
            pass

        if not source_ips:
            # Pas d'IP trouvée dans le message — on ne peut pas bloquer
            self.total_skipped += 1
            return

        # Chercher la règle de blocage applicable
        action, duration = self._get_blocking_decision(alert_type, severity)

        if action == "log_only" or action is None:
            self.total_skipped += 1
            return

        # Bloquer chaque IP source trouvée (hors IPs d'agents connus)
        agent_ips = self._get_known_agent_ips()
        for ip in source_ips:
            # Ne pas bloquer les IPs des agents connus du SOC
            if ip in agent_ips:
                print(f"\033[93m[IPS]\033[0m IP {ip} est un agent connu — blocage ignoré")
                continue
            self._block_ip(
                ip=ip,
                reason=f"{alert_type} — {message[:200]}",
                severity=severity,
                alert_type=alert_type,
                agent_id=agent_id,
                alert_id=alert_id,
                duration_minutes=duration
            )

    def _get_known_agent_ips(self) -> Set[str]:
        """Retourne les IPs de tous les agents connectés (pour ne pas les bloquer)."""
        agent_ips = set()
        with self.clients_lock:
            for aid, info in self.clients.items():
                ip = info.get("ip", "")
                if ip:
                    agent_ips.add(ip)
        return agent_ips

    # =========================================================================
    #  DÉCISION DE BLOCAGE
    # =========================================================================

    def _get_blocking_decision(self, alert_type: str, severity: str):
        """
        Détermine l'action à effectuer selon le type et la sévérité.

        Returns:
            tuple: (action, duration_minutes) ou (None, 0)
        """
        # Chercher une correspondance exacte
        if alert_type in self.BLOCKING_RULES:
            type_rules = self.BLOCKING_RULES[alert_type]
            if severity in type_rules:
                return type_rules[severity]

        # Chercher une correspondance partielle (ex: "BRUTE_FORCE_AGENT" → "BRUTE_FORCE")
        for rule_type, type_rules in self.BLOCKING_RULES.items():
            if rule_type in alert_type or alert_type in rule_type:
                if severity in type_rules:
                    return type_rules[severity]

        # Fallback : CRITICAL → block 30min, HIGH → block 15min
        if severity == "CRITICAL":
            return ("block", 30)
        if severity == "HIGH":
            return ("block", 15)

        return (None, 0)

    # =========================================================================
    #  BLOCAGE D'IP
    # =========================================================================

    def _block_ip(self, ip: str, reason: str, severity: str, alert_type: str,
                  agent_id: str, alert_id: Optional[int], duration_minutes: int):
        """
        Bloque une IP : vérifie la whitelist, cooldown, enregistre en DB,
        envoie la commande à l'agent, notifie le dashboard.
        """
        # Vérifier whitelist
        if ip in self.whitelist:
            print(f"\033[93m[IPS]\033[0m IP {ip} en whitelist — blocage ignoré")
            self.total_skipped += 1
            return

        # Vérifier cooldown (éviter le re-blocage rapide de la même IP)
        now = time.time()
        last_block = self._block_cooldown.get(ip, 0)
        if now - last_block < self._cooldown_seconds:
            remaining = int(self._cooldown_seconds - (now - last_block))
            print(f"\033[93m[IPS]\033[0m IP {ip} en cooldown ({remaining}s restantes) — ignoré")
            self.total_skipped += 1
            return

        # Vérifier si déjà bloquée
        if self.db.is_ip_blocked(ip):
            print(f"\033[93m[IPS]\033[0m IP {ip} déjà bloquée — ignoré")
            return

        # Enregistrer en DB
        action_id = self.db.insert_ips_action(
            ip=ip,
            action="block",
            reason=reason,
            severity=severity,
            alert_type=alert_type,
            agent_id=agent_id,
            alert_id=alert_id,
            duration_minutes=duration_minutes
        )

        if not action_id:
            print(f"\033[91m[IPS ERREUR]\033[0m Impossible d'enregistrer le blocage de {ip}")
            return

        self.total_blocks += 1

        # Mettre à jour le cooldown
        self._block_cooldown[ip] = time.time()

        duration_str = f"{duration_minutes} min" if duration_minutes > 0 else "permanent"
        print(f"\033[91;1m[IPS BLOCK]\033[0m 🚫 {ip} bloquée "
              f"({alert_type} / {severity}) — durée: {duration_str}")

        # --- Blocage local direct (firewall du serveur) ---
        self._local_block_ip(ip, reason)

        # Envoyer la commande de blocage à l'agent (en plus du local)
        self._send_block_command(agent_id, ip, reason, severity, duration_minutes)

        # Notifier le dashboard via WebSocket
        self._broadcast_ips_event({
            "event": "ip_blocked",
            "id": action_id,
            "ip": ip,
            "reason": reason,
            "severity": severity,
            "alert_type": alert_type,
            "agent_id": agent_id,
            "duration_minutes": duration_minutes,
            "timestamp": datetime.now().isoformat(),
            "status": "active"
        })

    # =========================================================================
    #  DÉBLOCAGE D'IP
    # =========================================================================

    def unblock_ip(self, action_id: int, reason: str = "manual") -> bool:
        """
        Débloque une IP (manuellement ou par expiration).

        Args:
            action_id : ID de l'action IPS
            reason    : Raison du déblocage

        Returns:
            bool : True si déblocage réussi
        """
        # Récupérer l'info du blocage
        blocked = self.db.get_blocked_ips()
        target = None
        for b in blocked:
            if b["id"] == action_id:
                target = b
                break

        if not target:
            return False

        ip = target["ip"]
        agent_id = target.get("agent_id", "")

        # Mettre à jour en DB
        success = self.db.unblock_ip(action_id, reason)
        if not success:
            return False

        print(f"\033[92m[IPS UNBLOCK]\033[0m ✅ {ip} débloquée (raison: {reason})")

        # --- Déblocage local direct (firewall du serveur) ---
        self._local_unblock_ip(ip)

        # Envoyer la commande de déblocage à l'agent
        self._send_unblock_command(agent_id, ip, reason)

        # Notifier le dashboard
        self._broadcast_ips_event({
            "event": "ip_unblocked",
            "id": action_id,
            "ip": ip,
            "reason": reason,
            "agent_id": agent_id,
            "timestamp": datetime.now().isoformat(),
            "status": "unblocked"
        })

        return True

    # =========================================================================
    #  COMMUNICATION AVEC LES AGENTS
    # =========================================================================

    def _send_block_command(self, agent_id: str, ip: str, reason: str,
                            severity: str, duration_minutes: int):
        """Envoie une commande block_ip à l'agent via le socket TCP."""
        command = {
            "action": "block_ip",
            "ip": ip,
            "reason": reason,
            "severity": severity,
            "duration_minutes": duration_minutes
        }
        self._send_command_to_agent(agent_id, command)

    def _send_unblock_command(self, agent_id: str, ip: str, reason: str):
        """Envoie une commande unblock_ip à l'agent via le socket TCP."""
        command = {
            "action": "unblock_ip",
            "ip": ip,
            "reason": reason
        }
        self._send_command_to_agent(agent_id, command)

    def _send_command_to_agent(self, agent_id: str, command: Dict):
        """
        Envoie une commande JSON à un agent spécifique via son socket TCP.
        Envoie aussi à tous les agents si l'agent_id n'est pas trouvé.
        """
        with self.clients_lock:
            targets = []
            if agent_id and agent_id in self.clients:
                targets.append((agent_id, self.clients[agent_id]))
            else:
                # Envoyer à tous les agents connectés
                targets = list(self.clients.items())

        for aid, info in targets:
            try:
                sock = info.get("socket")
                if sock:
                    data = json.dumps(command, ensure_ascii=False) + "\n"
                    sock.sendall(data.encode("utf-8"))
                    print(f"\033[95m[IPS]\033[0m Commande envoyée à {aid}: "
                          f"{command.get('action')} {command.get('ip')}")
            except Exception as e:
                print(f"\033[91m[IPS ERREUR]\033[0m Envoi commande à {aid} échoué : {e}")

    # =========================================================================
    #  BROADCAST DASHBOARD
    # =========================================================================

    def _broadcast_ips_event(self, event_data: Dict):
        """Broadcast un événement IPS au dashboard via WebSocket."""
        if not self.ws_server:
            return
        self.ws_server.broadcast_ips_event(event_data)

    # =========================================================================
    #  EXTRACTION D'IP
    # =========================================================================

    def _extract_ips(self, text: str) -> List[str]:
        """
        Extrait les adresses IP uniques d'un texte.
        Exclut les IPs de la whitelist.

        Args:
            text : Texte à analyser

        Returns:
            List[str] : IPs trouvées (uniques, hors whitelist)
        """
        found = set(self.IP_REGEX.findall(text))
        # Exclure whitelist et IPs non routable
        return [
            ip for ip in found
            if ip not in self.whitelist
            and not ip.startswith("0.")
        ]

    # =========================================================================
    #  BLOCAGE LOCAL DIRECT — Firewall du serveur (netsh / iptables)
    # =========================================================================

    def _sync_blocked_ips_from_db(self):
        """
        Au démarrage, restaure les règles firewall locales pour les IPs
        encore bloquées en DB (survie au redémarrage du serveur).
        """
        try:
            blocked = self.db.get_blocked_ips()
            for b in blocked:
                ip = b.get("ip", "")
                if ip and ip not in self.whitelist:
                    self._local_block_ip(ip, reason="restored_from_db")
            if blocked:
                print(f"\033[95m[IPS]\033[0m {len(blocked)} IP(s) restaurée(s) "
                      f"depuis la DB dans le firewall local")
        except Exception as e:
            print(f"\033[91m[IPS ERREUR]\033[0m Sync DB → firewall local échoué : {e}")

    def _check_local_admin(self) -> bool:
        """Vérifie si le processus a les droits admin/root."""
        try:
            if self._local_os == "windows":
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                import os
                return os.geteuid() == 0
        except Exception:
            return False

    def _local_block_ip(self, ip: str, reason: str = ""):
        """
        Applique une règle de blocage firewall DIRECTEMENT sur le serveur.
        Pas besoin de passer par le relay TCP agent.
        """
        if ip in self._local_blocked_ips:
            return

        if not self._local_has_admin:
            print(f"\033[93m[IPS LOCAL]\033[0m ⚠ Pas de droits admin — "
                  f"impossible de bloquer {ip} localement")
            return

        try:
            if self._local_os == "windows":
                self._local_block_windows(ip)
            else:
                self._local_block_linux(ip)

            self._local_blocked_ips.add(ip)
            print(f"\033[91;1m[IPS LOCAL]\033[0m 🔥 {ip} bloquée dans le firewall local")

            # Fermer les connexions TCP existantes de cette IP
            self._close_existing_connections(ip)

        except Exception as e:
            print(f"\033[91m[IPS LOCAL ERREUR]\033[0m Blocage local de {ip} échoué : {e}")

    def _local_block_windows(self, ip: str):
        """Crée des règles netsh firewall IN + OUT pour bloquer une IP."""
        rule_name_in = f"SOC_IPS_BLOCK_{ip}_IN"
        rule_name_out = f"SOC_IPS_BLOCK_{ip}_OUT"

        # Règle entrante
        subprocess.run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name_in}",
            "dir=in", "action=block",
            f"remoteip={ip}",
            "protocol=any",
            "enable=yes"
        ], capture_output=True, timeout=15)

        # Règle sortante
        subprocess.run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name_out}",
            "dir=out", "action=block",
            f"remoteip={ip}",
            "protocol=any",
            "enable=yes"
        ], capture_output=True, timeout=15)

        # Vérification
        check = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule",
             f"name={rule_name_in}"],
            capture_output=True, text=True, timeout=10
        )
        if "SOC_IPS_BLOCK" not in check.stdout:
            raise RuntimeError(f"La règle {rule_name_in} n'a pas été créée")

    def _local_block_linux(self, ip: str):
        """Crée des règles iptables pour bloquer une IP."""
        subprocess.run(
            ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, timeout=10
        )
        subprocess.run(
            ["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"],
            capture_output=True, timeout=10
        )

    def _local_unblock_ip(self, ip: str):
        """Supprime les règles de blocage firewall locales pour une IP."""
        if ip not in self._local_blocked_ips:
            return

        try:
            if self._local_os == "windows":
                self._local_unblock_windows(ip)
            else:
                self._local_unblock_linux(ip)

            self._local_blocked_ips.discard(ip)
            print(f"\033[92m[IPS LOCAL]\033[0m ✅ {ip} débloquée du firewall local")
        except Exception as e:
            print(f"\033[91m[IPS LOCAL ERREUR]\033[0m Déblocage local de {ip} échoué : {e}")

    def _local_unblock_windows(self, ip: str):
        """Supprime les règles netsh firewall pour une IP."""
        for suffix in ["IN", "OUT"]:
            rule_name = f"SOC_IPS_BLOCK_{ip}_{suffix}"
            subprocess.run([
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={rule_name}"
            ], capture_output=True, timeout=15)

    def _local_unblock_linux(self, ip: str):
        """Supprime les règles iptables pour une IP."""
        subprocess.run(
            ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, timeout=10
        )
        subprocess.run(
            ["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"],
            capture_output=True, timeout=10
        )

    def _close_existing_connections(self, ip: str):
        """
        Ferme toutes les connexions TCP existantes depuis une IP bloquée.
        Empêche l'IP de continuer à envoyer des données après le blocage.
        """
        closed = 0
        with self.clients_lock:
            agents_to_remove = []
            for agent_id, info in self.clients.items():
                client_ip = info.get("ip", "")
                if client_ip == ip:
                    try:
                        sock = info.get("socket")
                        if sock:
                            sock.close()
                        agents_to_remove.append(agent_id)
                        closed += 1
                    except Exception:
                        pass

            for aid in agents_to_remove:
                del self.clients[aid]

        if closed > 0:
            print(f"\033[91m[IPS LOCAL]\033[0m 🔌 {closed} connexion(s) TCP "
                  f"de {ip} fermée(s)")

    def is_ip_locally_blocked(self, ip: str) -> bool:
        """Vérifie si une IP est bloquée localement (pour le rejet TCP côté serveur)."""
        return ip in self._local_blocked_ips or self.db.is_ip_blocked(ip)

    # =========================================================================
    #  AUTO-UNBLOCK — Thread de vérification des expirations
    # =========================================================================

    def start_auto_unblock(self, stop_event: threading.Event = None):
        """
        Démarre le thread d'auto-déblocage.
        Vérifie toutes les 60 secondes si des blocages ont expiré.

        Args:
            stop_event : Event pour arrêter proprement le thread
        """
        self._running = True
        thread = threading.Thread(
            target=self._auto_unblock_loop,
            args=(stop_event,),
            daemon=True,
            name="IPS-AutoUnblock"
        )
        thread.start()
        print(f"\033[95m[IPS]\033[0m Thread auto-déblocage démarré (check toutes les 60s)")

    def _auto_unblock_loop(self, stop_event: threading.Event = None):
        """Boucle d'auto-déblocage des IPs expirées."""
        while self._running:
            if stop_event and stop_event.is_set():
                break
            try:
                expired = self.db.get_expired_blocks()
                for block in expired:
                    self.unblock_ip(block["id"], reason="expired")
                    print(f"\033[95m[IPS]\033[0m Auto-déblocage: {block['ip']} "
                          f"(expiré après {block.get('duration_minutes', '?')} min)")
            except Exception as e:
                print(f"\033[91m[IPS ERREUR]\033[0m Erreur auto-unblock : {e}")

            # Attendre 60 secondes
            if stop_event:
                stop_event.wait(60)
            else:
                time.sleep(60)

    # =========================================================================
    #  WHITELIST MANAGEMENT
    # =========================================================================

    def add_to_whitelist(self, ip: str):
        """Ajoute une IP à la whitelist."""
        self.whitelist.add(ip)
        print(f"\033[95m[IPS]\033[0m {ip} ajoutée à la whitelist")

    def remove_from_whitelist(self, ip: str):
        """Retire une IP de la whitelist."""
        self.whitelist.discard(ip)
        print(f"\033[95m[IPS]\033[0m {ip} retirée de la whitelist")

    def get_whitelist(self) -> List[str]:
        """Retourne la whitelist triée."""
        return sorted(self.whitelist)

    # =========================================================================
    #  TOGGLE & STATS
    # =========================================================================

    def set_enabled(self, enabled: bool):
        """Active ou désactive le moteur IPS."""
        self.enabled = enabled
        state = "ACTIVÉ" if enabled else "DÉSACTIVÉ"
        print(f"\033[95m[IPS]\033[0m Moteur IPS {state}")

    def get_stats(self) -> Dict:
        """Retourne les statistiques IPS."""
        db_stats = self.db.get_ips_stats()
        return {
            "enabled": self.enabled,
            "total_blocks": self.total_blocks,
            "total_skipped": self.total_skipped,
            "active_blocks": db_stats.get("active_blocks", 0),
            "total_blocks_db": db_stats.get("total_blocks", 0),
            "total_unblocks": db_stats.get("total_unblocks", 0),
            "whitelist_size": len(self.whitelist),
            "cooldown_seconds": self._cooldown_seconds,
            "blocking_rules_count": len(self.BLOCKING_RULES),
            "ips_in_cooldown": len([
                ip for ip, ts in self._block_cooldown.items()
                if time.time() - ts < self._cooldown_seconds
            ])
        }
