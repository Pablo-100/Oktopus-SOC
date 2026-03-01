"""
=============================================================================
 Oktopus Agent — Blocker (IPS — Exécution des blocages firewall)
=============================================================================
 Fichier : agent/blocker.py
 Rôle    : Exécute les commandes de blocage/déblocage IP sur la machine locale
           - Détecte automatiquement l'OS (Windows / Linux)
           - Windows : netsh advfirewall firewall
           - Linux   : iptables
           - Vérification pré/post des outils firewall
           - Suivi local des IPs bloquées
           - Thread-safe
           - Logging local dans blocker.log

 Architecture :
   server/ips_engine.py  →  (TCP commande)  →  agent/blocker.py
                                                    ↓
                                              OS Firewall (netsh / iptables)

 Auteur  : Oktopus Team
 Date    : 2026-02-28
 Python  : 3.8+
=============================================================================
"""

import os
import platform
import subprocess
import threading
import logging
import time
from datetime import datetime
from typing import Dict, Set, List, Optional

logger = logging.getLogger("SOC.Blocker")


class IPBlocker:
    """
    Gestionnaire de blocage IP — interface avec le firewall de l'OS.
    
    Attributs :
        os_type         : "windows" ou "linux"
        blocked_ips     : Set des IPs actuellement bloquées par cet agent
        lock            : Threading lock pour accès concurrent
        rule_prefix     : Préfixe des règles firewall (pour identification)
        has_firewall_tool : Indique si l'outil firewall (iptables/netsh) est disponible
    """

    RULE_PREFIX = "SOC_BLOCK"

    def __init__(self):
        self.os_type = platform.system().lower()
        self.blocked_ips: Set[str] = set()
        self.lock = threading.Lock()
        self.total_blocked = 0
        self.total_unblocked = 0
        self.total_errors = 0
        self.has_admin = False            # Indique si on a les droits admin/root
        self.has_firewall_tool = False     # Indique si iptables/netsh est disponible

        # --- Logger local fichier blocker.log ---
        self._setup_file_logger()

        logger.info(f"[BLOCKER] Initialisé pour OS: {self.os_type}")

        # Vérifier la disponibilité de l'outil firewall
        self._check_firewall_tool()

        # Vérifier les permissions — critique pour le fonctionnement IPS
        self._check_permissions()

    # =========================================================================
    #  LOGGER LOCAL — blocker.log
    # =========================================================================

    def _setup_file_logger(self):
        """
        Configure un logger dédié qui écrit chaque action block/unblock
        avec timestamp dans un fichier local blocker.log.
        """
        try:
            log_dir = os.path.dirname(os.path.abspath(__file__))
            log_path = os.path.join(log_dir, "..", "blocker.log")
            log_path = os.path.normpath(log_path)

            self._file_logger = logging.getLogger("SOC.Blocker.File")
            self._file_logger.setLevel(logging.INFO)
            # Éviter les doublons si déjà configuré
            if not self._file_logger.handlers:
                fh = logging.FileHandler(log_path, encoding="utf-8")
                fh.setFormatter(logging.Formatter(
                    "%(asctime)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
                ))
                self._file_logger.addHandler(fh)
            logger.info(f"[BLOCKER] Log fichier configuré : {log_path}")
        except Exception as e:
            self._file_logger = None
            logger.warning(f"[BLOCKER] Impossible de configurer le log fichier : {e}")

    def _log_action(self, action: str, ip: str, success: bool, message: str):
        """
        Écrit une entrée dans blocker.log pour traçabilité locale.
        Format : TIMESTAMP | ACTION | IP | SUCCESS | MESSAGE
        """
        status = "OK" if success else "FAIL"
        line = f"{action} | {ip} | {status} | {message}"
        try:
            if self._file_logger:
                self._file_logger.info(line)
        except Exception:
            pass  # Ne jamais crasher pour un problème de log

    # =========================================================================
    #  VÉRIFICATION DES OUTILS FIREWALL
    # =========================================================================

    def _check_firewall_tool(self):
        """
        Vérifie que l'outil firewall (iptables ou netsh) est disponible sur le système.
        Log une erreur claire si l'outil est absent.
        """
        try:
            if self.os_type == "windows":
                # Vérifier que netsh est accessible
                result = subprocess.run(
                    ["where", "netsh"],
                    capture_output=True, text=True, timeout=10,
                    creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                )
                if result.returncode == 0 and result.stdout.strip():
                    self.has_firewall_tool = True
                    logger.info(f"[BLOCKER] ✓ netsh trouvé : {result.stdout.strip().splitlines()[0]}")
                else:
                    self.has_firewall_tool = False
                    logger.error("[BLOCKER] ✗ netsh NON TROUVÉ — IPS Windows impossible")

            elif self.os_type in ("linux", "darwin"):
                # Vérifier que iptables est accessible via which
                result = subprocess.run(
                    ["which", "iptables"],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0 and result.stdout.strip():
                    self.has_firewall_tool = True
                    logger.info(f"[BLOCKER] ✓ iptables trouvé : {result.stdout.strip()}")
                else:
                    self.has_firewall_tool = False
                    logger.error("[BLOCKER] ✗ iptables NON TROUVÉ — installer avec : apt install iptables")
            else:
                self.has_firewall_tool = False
                logger.warning(f"[BLOCKER] OS non supporté : {self.os_type}")

        except FileNotFoundError:
            self.has_firewall_tool = False
            logger.error("[BLOCKER] ✗ Commande de recherche indisponible (which/where)")
        except subprocess.TimeoutExpired:
            self.has_firewall_tool = False
            logger.error("[BLOCKER] ✗ Timeout lors de la vérification de l'outil firewall")
        except Exception as e:
            self.has_firewall_tool = False
            logger.error(f"[BLOCKER] ✗ Erreur vérification outil firewall : {e}")

    def _check_permissions(self):
        """
        Vérifie si l'agent a les permissions nécessaires pour modifier le firewall.
        CRITIQUE : Sans droits admin/root, aucun blocage ne fonctionnera.
        """
        if self.os_type == "windows":
            try:
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
                if is_admin:
                    self.has_admin = True
                    logger.info("[BLOCKER] ✓ Droits administrateur CONFIRMÉS — IPS opérationnel")
                else:
                    self.has_admin = False
                    logger.error("=" * 70)
                    logger.error("[BLOCKER] ╔═══════════════════════════════════════════════════════╗")
                    logger.error("[BLOCKER] ║  ⚠ ATTENTION: PAS DE DROITS ADMINISTRATEUR !        ║")
                    logger.error("[BLOCKER] ║  Les blocages IPS ne fonctionneront PAS.             ║")
                    logger.error("[BLOCKER] ║                                                       ║")
                    logger.error("[BLOCKER] ║  SOLUTION: Relancer l'agent en tant qu'Administrateur ║")
                    logger.error("[BLOCKER] ║  → Clic droit sur cmd/PowerShell → Exécuter en admin ║")
                    logger.error("[BLOCKER] ╚═══════════════════════════════════════════════════════╝")
                    logger.error("=" * 70)
            except Exception:
                self.has_admin = False
                logger.warning("[BLOCKER] Impossible de vérifier les droits admin")

        elif self.os_type == "linux":
            try:
                if os.geteuid() == 0:
                    self.has_admin = True
                    logger.info("[BLOCKER] ✓ Droits root CONFIRMÉS — IPS opérationnel")
                else:
                    self.has_admin = False
                    logger.error("=" * 70)
                    logger.error("[BLOCKER] ⚠ PAS ROOT — Les blocages IPS ne fonctionneront PAS.")
                    logger.error("[BLOCKER] SOLUTION: Relancer avec sudo → sudo python -m agent.agent")
                    logger.error("=" * 70)
            except AttributeError:
                # os.geteuid() n'existe pas sur certains systèmes
                self.has_admin = False
                logger.warning("[BLOCKER] Impossible de vérifier les droits root (os.geteuid indisponible)")

    # =========================================================================
    #  BLOCAGE D'IP
    # =========================================================================

    def block_ip(self, ip: str, reason: str = "", severity: str = "",
                 duration_minutes: int = 0) -> Dict:
        """
        Bloque une IP dans le firewall de l'OS.

        Args:
            ip               : Adresse IP à bloquer
            reason           : Raison du blocage
            severity         : Sévérité de l'alerte
            duration_minutes : Durée (0 = permanent)

        Returns:
            Dict : {"success": bool, "message": str, "ip": str}
        """
        with self.lock:
            try:
                # Vérifier que l'outil firewall est disponible
                if not self.has_firewall_tool:
                    tool = "netsh" if self.os_type == "windows" else "iptables"
                    msg = (f"BLOCAGE IMPOSSIBLE pour {ip} — outil {tool} non disponible. "
                           f"Installez-le ou vérifiez votre PATH.")
                    logger.error(f"[BLOCKER] ❌ {msg}")
                    self.total_errors += 1
                    self._log_action("BLOCK", ip, False, msg)
                    return {"success": False, "message": msg, "ip": ip}

                # Vérifier les droits admin avant toute tentative
                if not self.has_admin:
                    msg = (f"BLOCAGE IMPOSSIBLE pour {ip} — Pas de droits "
                           f"{'Administrateur' if self.os_type == 'windows' else 'root'}. "
                           f"Relancez l'agent avec les droits nécessaires.")
                    logger.error(f"[BLOCKER] ❌ {msg}")
                    self.total_errors += 1
                    self._log_action("BLOCK", ip, False, msg)
                    return {"success": False, "message": msg, "ip": ip}

                # Vérifier si déjà bloquée localement
                if ip in self.blocked_ips:
                    msg = f"IP {ip} déjà bloquée localement"
                    logger.info(f"[BLOCKER] {msg}")
                    return {"success": True, "message": msg, "ip": ip}

                # Exécuter la commande firewall
                if self.os_type == "windows":
                    result = self._block_windows(ip, reason)
                elif self.os_type in ("linux", "darwin"):
                    result = self._block_linux(ip, reason)
                else:
                    result = {
                        "success": False,
                        "message": f"OS non supporté : {self.os_type}",
                        "ip": ip
                    }

                # Vérification post-blocage : confirmer que la règle existe
                if result["success"]:
                    if self.os_type == "windows":
                        if not self._verify_rule_exists_windows(ip):
                            result["success"] = False
                            result["message"] = (
                                f"Règles créées mais vérification échouée pour {ip} — "
                                f"les commandes netsh ont peut-être échoué silencieusement"
                            )
                    elif self.os_type in ("linux", "darwin"):
                        if not self._verify_rule_exists_linux(ip):
                            result["success"] = False
                            result["message"] = (
                                f"Règles créées mais vérification échouée pour {ip} — "
                                f"les commandes iptables ont peut-être échoué silencieusement"
                            )

                if result["success"]:
                    self.blocked_ips.add(ip)
                    self.total_blocked += 1
                    duration_str = f"{duration_minutes} min" if duration_minutes > 0 else "permanent"
                    logger.info(f"[BLOCKER] 🚫 IP {ip} BLOQUÉE ({reason}) — durée: {duration_str}")
                    self._log_action("BLOCK", ip, True,
                                     f"Raison: {reason} | Sévérité: {severity} | Durée: {duration_str}")
                else:
                    self.total_errors += 1
                    logger.error(f"[BLOCKER] ❌ Échec blocage {ip} : {result['message']}")
                    self._log_action("BLOCK", ip, False, result["message"])

                return result

            except Exception as e:
                # Sécurité ultime : ne JAMAIS crasher
                msg = f"Erreur inattendue lors du blocage de {ip} : {e}"
                logger.error(f"[BLOCKER] ❌ {msg}")
                self.total_errors += 1
                self._log_action("BLOCK", ip, False, msg)
                return {"success": False, "message": msg, "ip": ip}

    def _block_windows(self, ip: str, reason: str) -> Dict:
        """Bloque une IP via netsh advfirewall (Windows)."""
        rule_name = f"{self.RULE_PREFIX}_{ip.replace('.', '_')}"
        
        # Commande : bloquer en entrée ET en sortie
        commands = [
            # Règle entrante (bloquer le trafic entrant depuis cette IP)
            [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}_IN",
                "dir=in",
                "action=block",
                f"remoteip={ip}",
                "enable=yes",
                f"description=SOC IPS Block: {reason[:200]}"
            ],
            # Règle sortante (bloquer le trafic sortant vers cette IP)
            [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}_OUT",
                "dir=out",
                "action=block",
                f"remoteip={ip}",
                "enable=yes",
                f"description=SOC IPS Block: {reason[:200]}"
            ]
        ]

        errors = []
        for cmd in commands:
            try:
                logger.debug(f"[BLOCKER] Exécution: {' '.join(cmd)}")
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=15,
                    creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                )
                if result.returncode != 0:
                    err_msg = result.stderr.strip() or result.stdout.strip()
                    logger.error(f"[BLOCKER] netsh a échoué (code {result.returncode}): {err_msg}")
                    errors.append(err_msg)
                else:
                    logger.info(f"[BLOCKER] ✓ Règle ajoutée: {cmd[6] if len(cmd) > 6 else cmd}")
            except subprocess.TimeoutExpired:
                errors.append("Timeout exécution netsh")
            except FileNotFoundError:
                errors.append("netsh non trouvé sur ce système")
            except Exception as e:
                errors.append(str(e))

        if errors:
            logger.error(f"[BLOCKER] ❌ BLOCAGE ÉCHOUÉ pour {ip} — Vérifiez les droits Administrateur !")
            return {
                "success": False,
                "message": " | ".join(errors),
                "ip": ip
            }

        return {
            "success": True,
            "message": f"Règles firewall Windows créées : {rule_name}_IN, {rule_name}_OUT",
            "ip": ip
        }

    def _verify_rule_exists_windows(self, ip: str) -> bool:
        """
        Vérifie qu'une règle firewall existe réellement pour l'IP donnée (Windows).
        Retourne True si au moins une règle SOC_BLOCK existe pour cette IP.
        """
        rule_name = f"{self.RULE_PREFIX}_{ip.replace('.', '_')}_IN"
        try:
            result = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule",
                 f"name={rule_name}"],
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
            )
            exists = result.returncode == 0 and rule_name in result.stdout
            if exists:
                logger.info(f"[BLOCKER] ✓ Vérification OK — règle {rule_name} confirmée")
            else:
                logger.warning(f"[BLOCKER] ⚠ Vérification ÉCHOUÉE — règle {rule_name} introuvable")
            return exists
        except Exception as e:
            logger.warning(f"[BLOCKER] Vérification impossible: {e}")
            return True  # En cas d'erreur de vérification, on fait confiance

    def _verify_rule_exists_linux(self, ip: str) -> bool:
        """
        Vérifie qu'une règle iptables existe réellement pour l'IP donnée (Linux).
        Utilise iptables -L pour lister les règles et chercher l'IP.
        Retourne True si l'IP est trouvée dans les règles INPUT.
        """
        try:
            result = subprocess.run(
                ["iptables", "-L", "INPUT", "-n", "--line-numbers"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0 and ip in result.stdout:
                logger.info(f"[BLOCKER] ✓ Vérification OK — règle iptables pour {ip} confirmée")
                return True
            else:
                logger.warning(f"[BLOCKER] ⚠ Vérification ÉCHOUÉE — règle iptables pour {ip} introuvable")
                return False
        except Exception as e:
            logger.warning(f"[BLOCKER] Vérification iptables impossible : {e}")
            return True  # En cas d'erreur de vérification, on fait confiance

    def _block_linux(self, ip: str, reason: str) -> Dict:
        """Bloque une IP via iptables (Linux)."""
        commands = [
            # Bloquer en entrée
            ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP",
             "-m", "comment", "--comment", f"SOC_IPS:{reason[:100]}"],
            # Bloquer en sortie
            ["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP",
             "-m", "comment", "--comment", f"SOC_IPS:{reason[:100]}"]
        ]

        errors = []
        for cmd in commands:
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=15
                )
                if result.returncode != 0:
                    errors.append(result.stderr.strip())
            except subprocess.TimeoutExpired:
                errors.append("Timeout exécution iptables")
            except FileNotFoundError:
                errors.append("iptables non trouvé — installer avec : apt install iptables")
            except Exception as e:
                errors.append(str(e))

        if errors:
            return {
                "success": False,
                "message": " | ".join(errors),
                "ip": ip
            }

        return {
            "success": True,
            "message": f"Règles iptables créées pour {ip} (INPUT DROP + OUTPUT DROP)",
            "ip": ip
        }

    # =========================================================================
    #  DÉBLOCAGE D'IP
    # =========================================================================

    def unblock_ip(self, ip: str, reason: str = "") -> Dict:
        """
        Débloque une IP du firewall.

        Args:
            ip     : Adresse IP à débloquer
            reason : Raison du déblocage

        Returns:
            Dict : {"success": bool, "message": str, "ip": str}
        """
        with self.lock:
            try:
                # Vérifier que l'outil firewall est disponible
                if not self.has_firewall_tool:
                    tool = "netsh" if self.os_type == "windows" else "iptables"
                    msg = f"DÉBLOCAGE IMPOSSIBLE pour {ip} — outil {tool} non disponible."
                    logger.error(f"[BLOCKER] ❌ {msg}")
                    self.total_errors += 1
                    self._log_action("UNBLOCK", ip, False, msg)
                    return {"success": False, "message": msg, "ip": ip}

                # Vérifier les droits admin (nécessaires aussi pour débloquer)
                if not self.has_admin:
                    msg = (f"DÉBLOCAGE IMPOSSIBLE pour {ip} — Pas de droits "
                           f"{'Administrateur' if self.os_type == 'windows' else 'root'}.")
                    logger.error(f"[BLOCKER] ❌ {msg}")
                    self.total_errors += 1
                    self._log_action("UNBLOCK", ip, False, msg)
                    return {"success": False, "message": msg, "ip": ip}

                # Exécuter la commande firewall
                if self.os_type == "windows":
                    result = self._unblock_windows(ip)
                elif self.os_type in ("linux", "darwin"):
                    result = self._unblock_linux(ip)
                else:
                    result = {
                        "success": False,
                        "message": f"OS non supporté : {self.os_type}",
                        "ip": ip
                    }

                if result["success"]:
                    self.blocked_ips.discard(ip)
                    self.total_unblocked += 1
                    logger.info(f"[BLOCKER] ✅ IP {ip} DÉBLOQUÉE (raison: {reason})")
                    self._log_action("UNBLOCK", ip, True, f"Raison: {reason}")
                else:
                    self.total_errors += 1
                    logger.error(f"[BLOCKER] ❌ Échec déblocage {ip} : {result['message']}")
                    self._log_action("UNBLOCK", ip, False, result["message"])

                return result

            except Exception as e:
                # Sécurité ultime : ne JAMAIS crasher
                msg = f"Erreur inattendue lors du déblocage de {ip} : {e}"
                logger.error(f"[BLOCKER] ❌ {msg}")
                self.total_errors += 1
                self._log_action("UNBLOCK", ip, False, msg)
                return {"success": False, "message": msg, "ip": ip}

    def _unblock_windows(self, ip: str) -> Dict:
        """
        Supprime les règles firewall Windows (IN + OUT) pour une IP.
        Gère le cas où les règles n'existent plus sans crasher.
        """
        rule_name = f"{self.RULE_PREFIX}_{ip.replace('.', '_')}"

        # Vérifier d'abord si les règles existent encore
        rules_exist = self._check_windows_rule_exists(rule_name)

        commands = [
            ["netsh", "advfirewall", "firewall", "delete", "rule",
             f"name={rule_name}_IN"],
            ["netsh", "advfirewall", "firewall", "delete", "rule",
             f"name={rule_name}_OUT"]
        ]

        errors = []
        deleted_count = 0
        for cmd in commands:
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=15,
                    creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                )
                if result.returncode != 0:
                    stderr = result.stderr.strip() or result.stdout.strip()
                    # Ignorer l'erreur "aucune règle" (règle déjà supprimée ou inexistante)
                    if ("No rules match" in stderr or "Aucune" in stderr or
                            "No rules" in stderr or "no rules" in stderr.lower()):
                        logger.info(f"[BLOCKER] Règle déjà absente : {cmd[5] if len(cmd) > 5 else '?'}")
                    else:
                        errors.append(stderr)
                else:
                    deleted_count += 1
                    logger.info(f"[BLOCKER] ✓ Règle supprimée : {cmd[5] if len(cmd) > 5 else '?'}")
            except subprocess.TimeoutExpired:
                errors.append("Timeout netsh")
            except FileNotFoundError:
                errors.append("netsh non trouvé sur ce système")
            except Exception as e:
                errors.append(str(e))

        if errors:
            return {
                "success": False,
                "message": " | ".join(errors),
                "ip": ip
            }

        # Même si aucune règle n'a été supprimée (déjà absentes), c'est un succès
        if deleted_count == 0 and not rules_exist:
            return {
                "success": True,
                "message": f"Règles pour {ip} déjà absentes du firewall — nettoyage local effectué",
                "ip": ip
            }

        return {
            "success": True,
            "message": f"Règles firewall supprimées pour {ip} ({deleted_count} règle(s))",
            "ip": ip
        }

    def _check_windows_rule_exists(self, rule_name: str) -> bool:
        """
        Vérifie si au moins une des règles (IN/OUT) existe encore dans le firewall Windows.
        Utilisé avant le unblock pour adapter le message.
        """
        try:
            result = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule",
                 f"name={rule_name}_IN"],
                capture_output=True, text=True, timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
            )
            return result.returncode == 0 and rule_name in result.stdout
        except Exception:
            return False

    def _unblock_linux(self, ip: str) -> Dict:
        """
        Supprime les règles iptables (INPUT + OUTPUT) pour une IP.
        Gère le cas où les règles n'existent plus sans crasher.
        Tente de supprimer toutes les occurrences (boucle) en cas de doublons.
        """
        # Supprimer les règles INPUT et OUTPUT
        chains = [
            ("INPUT", ["-D", "INPUT", "-s", ip, "-j", "DROP"]),
            ("OUTPUT", ["-D", "OUTPUT", "-d", ip, "-j", "DROP"])
        ]

        errors = []
        deleted_count = 0

        for chain_name, args in chains:
            # Essayer de supprimer la règle (peut échouer si elle n'existe plus)
            # On boucle pour supprimer les éventuels doublons
            max_attempts = 5  # Sécurité anti-boucle infinie
            for attempt in range(max_attempts):
                try:
                    cmd = ["iptables"] + args
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=15
                    )
                    if result.returncode != 0:
                        stderr = result.stderr.strip()
                        # Règle n'existe pas/plus → sortir de la boucle, pas une erreur
                        if ("Bad rule" in stderr or "does a matching rule" in stderr or
                                "No chain/target" in stderr or "iptables:" in stderr):
                            if attempt == 0:
                                logger.info(f"[BLOCKER] Règle {chain_name} pour {ip} déjà absente")
                            break
                        else:
                            errors.append(f"{chain_name}: {stderr}")
                            break
                    else:
                        deleted_count += 1
                        logger.info(f"[BLOCKER] ✓ Règle {chain_name} supprimée pour {ip} (iter {attempt + 1})")
                except subprocess.TimeoutExpired:
                    errors.append(f"{chain_name}: Timeout iptables")
                    break
                except FileNotFoundError:
                    errors.append("iptables non trouvé sur ce système")
                    break
                except Exception as e:
                    errors.append(f"{chain_name}: {str(e)}")
                    break

        if errors:
            return {
                "success": False,
                "message": " | ".join(errors),
                "ip": ip
            }

        if deleted_count == 0:
            return {
                "success": True,
                "message": f"Règles pour {ip} déjà absentes d'iptables — nettoyage local effectué",
                "ip": ip
            }

        return {
            "success": True,
            "message": f"Règles iptables supprimées pour {ip} ({deleted_count} règle(s))",
            "ip": ip
        }

    # =========================================================================
    #  UTILITAIRES
    # =========================================================================

    def is_blocked(self, ip: str) -> bool:
        """Vérifie si une IP est dans la liste locale des IPs bloquées."""
        return ip in self.blocked_ips

    def get_blocked_list(self) -> List[str]:
        """Retourne la liste des IPs actuellement bloquées."""
        return sorted(self.blocked_ips)

    def get_stats(self) -> Dict:
        """Retourne les statistiques du blocker."""
        return {
            "os_type": self.os_type,
            "has_admin": self.has_admin,
            "has_firewall_tool": self.has_firewall_tool,
            "active_blocks": len(self.blocked_ips),
            "total_blocked": self.total_blocked,
            "total_unblocked": self.total_unblocked,
            "total_errors": self.total_errors,
            "blocked_ips": self.get_blocked_list()
        }

    def cleanup_all(self):
        """
        Supprime toutes les règles SOC du firewall.
        Utile lors de l'arrêt de l'agent.
        """
        logger.info("[BLOCKER] Nettoyage de toutes les règles SOC...")
        ips_to_unblock = list(self.blocked_ips)
        for ip in ips_to_unblock:
            try:
                self.unblock_ip(ip, reason="agent_shutdown")
            except Exception as e:
                logger.error(f"[BLOCKER] Erreur nettoyage {ip} : {e}")
        logger.info(f"[BLOCKER] {len(ips_to_unblock)} règle(s) nettoyée(s)")
        self._log_action("CLEANUP", "*", True,
                         f"{len(ips_to_unblock)} règle(s) nettoyée(s) à l'arrêt de l'agent")
