"""
=============================================================================
 Oktopus Agent — Collecteur Windows
=============================================================================
 Fichier : agent/collectors/windows_collector.py
 Rôle    : Collecte des logs Windows via l'Event Log API
            - Security (Event ID 4624, 4625, 4688, 4720, 4726, 1102)
            - System (erreurs, warnings)
            - Application
            - Utilise win32evtlog si disponible, sinon wevtutil fallback
=============================================================================
"""

import time
import logging
import subprocess
import platform

logger = logging.getLogger("SOC.Collector.Windows")

# Tenter d'importer pywin32
try:
    import win32evtlog
    import win32evtlogutil
    import win32con
    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False
    logger.info("pywin32 non disponible — utilisation du fallback wevtutil")


class WindowsCollector:
    """Collecteur de logs pour systèmes Windows."""

    # Canaux Event Log à surveiller
    CHANNELS = {
        "Security": {
            "event_ids": [4624, 4625, 4634, 4648, 4688, 4720, 4726, 4732, 4756, 1102],
            "description": "Événements de sécurité (logon, processus, comptes)"
        },
        "System": {
            "event_ids": None,  # Tous les événements WARNING+ 
            "description": "Événements système"
        },
        "Application": {
            "event_ids": None,  # Tous les événements WARNING+
            "description": "Événements applicatifs"
        }
    }

    # Mapping Event ID → Description
    EVENT_DESCRIPTIONS = {
        4624: "Ouverture de session réussie",
        4625: "Échec d'ouverture de session",
        4634: "Fermeture de session",
        4648: "Logon avec credentials explicites",
        4688: "Nouveau processus créé",
        4720: "Compte utilisateur créé",
        4726: "Compte utilisateur supprimé",
        4732: "Membre ajouté à un groupe de sécurité",
        4756: "Membre ajouté à un groupe universel",
        1102: "Journal d'audit effacé"
    }

    def __init__(self, channels=None):
        """
        Args:
            channels (dict, optional): Canaux à surveiller. Si None, utilise les défauts.
        """
        self.channels = channels or self.CHANNELS
        self.last_record_numbers = {}  # {channel: dernier_numéro_lu}
        self.is_windows = platform.system() == "Windows"

        if not self.is_windows:
            logger.warning("WindowsCollector exécuté sur un système non-Windows")
            return

        # Initialiser les positions de lecture
        for channel in self.channels:
            self._init_position(channel)

    def _init_position(self, channel):
        """Enregistrer le dernier numéro d'événement actuel pour ne lire que les nouveaux."""
        if HAS_WIN32:
            try:
                handle = win32evtlog.OpenEventLog(None, channel)
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                total = win32evtlog.GetNumberOfEventLogRecords(handle)
                self.last_record_numbers[channel] = total
                win32evtlog.CloseEventLog(handle)
                logger.debug(f"Position initiale {channel}: record #{total}")
            except Exception as e:
                logger.warning(f"Impossible d'initialiser {channel}: {e}")
                self.last_record_numbers[channel] = 0
        else:
            self.last_record_numbers[channel] = 0
            self._init_position_wevtutil(channel)

    def _init_position_wevtutil(self, channel):
        """Fallback : récupérer le count actuel via wevtutil."""
        try:
            result = subprocess.run(
                ["wevtutil", "gli", channel],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.strip().split('\n'):
                if 'numberOfLogRecords' in line.lower() or 'nombre' in line.lower():
                    parts = line.split(':')
                    if len(parts) >= 2:
                        self.last_record_numbers[channel] = int(parts[1].strip())
                        break
        except Exception as e:
            logger.warning(f"wevtutil init échoué pour {channel}: {e}")

    def collect(self):
        """
        Collecter les nouveaux événements Windows.
        
        Returns:
            list[dict]: Liste de logs au format:
                {
                    "source": str,       # nom du canal (Security, System, Application)
                    "line": str,         # description formatée de l'événement
                    "timestamp": str,    # horodatage
                    "collector": "windows",
                    "event_id": int,     # ID de l'événement Windows
                    "level": str         # INFO/WARNING/ERROR/CRITICAL
                }
        """
        if not self.is_windows:
            return self._generate_simulated_logs()

        new_logs = []

        for channel, config in self.channels.items():
            try:
                if HAS_WIN32:
                    events = self._collect_win32(channel, config)
                else:
                    events = self._collect_wevtutil(channel, config)
                new_logs.extend(events)
            except Exception as e:
                logger.error(f"Erreur collecte {channel}: {e}")

        if new_logs:
            logger.debug(f"Collecté {len(new_logs)} événements Windows")

        return new_logs

    def _collect_win32(self, channel, config):
        """Collecter via pywin32 API."""
        events = []
        try:
            handle = win32evtlog.OpenEventLog(None, channel)
            flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            total = win32evtlog.GetNumberOfEventLogRecords(handle)
            last = self.last_record_numbers.get(channel, total)

            if total <= last:
                win32evtlog.CloseEventLog(handle)
                return events

            # Lire les nouveaux événements
            while True:
                records = win32evtlog.ReadEventLog(handle, flags, 0)
                if not records:
                    break

                for event in records:
                    record_num = event.RecordNumber
                    if record_num <= last:
                        continue

                    event_id = event.EventID & 0xFFFF
                    event_type = event.EventType

                    # Filtrer par event_ids si configuré
                    if config.get("event_ids") and event_id not in config["event_ids"]:
                        # Pour System/Application, on ne garde que WARNING+
                        if event_type not in (win32con.EVENTLOG_WARNING_TYPE,
                                              win32con.EVENTLOG_ERROR_TYPE):
                            continue

                    level = self._win32_event_type_to_level(event_type)
                    description = self._format_win32_event(event, event_id)

                    events.append({
                        "source": channel,
                        "line": description,
                        "timestamp": event.TimeGenerated.Format("%Y-%m-%d %H:%M:%S"),
                        "collector": "windows",
                        "event_id": event_id,
                        "level": level
                    })

            self.last_record_numbers[channel] = total
            win32evtlog.CloseEventLog(handle)

        except Exception as e:
            logger.error(f"win32evtlog erreur ({channel}): {e}")

        return events

    def _collect_wevtutil(self, channel, config):
        """Fallback : collecter via wevtutil en ligne de commande."""
        events = []
        try:
            # Récupérer les 50 derniers événements
            cmd = [
                "wevtutil", "qe", channel,
                "/c:50", "/rd:true", "/f:text"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)

            if result.returncode != 0:
                return events

            # Parser la sortie texte
            current_event = {}
            for line in result.stdout.split('\n'):
                line = line.strip()
                if not line:
                    if current_event:
                        events.append(self._format_wevtutil_event(current_event, channel))
                        current_event = {}
                    continue

                if ':' in line:
                    key, _, val = line.partition(':')
                    current_event[key.strip().lower()] = val.strip()

            if current_event:
                events.append(self._format_wevtutil_event(current_event, channel))

        except subprocess.TimeoutExpired:
            logger.warning(f"wevtutil timeout pour {channel}")
        except Exception as e:
            logger.error(f"wevtutil erreur ({channel}): {e}")

        return events

    def _format_win32_event(self, event, event_id):
        """Formater un événement win32 en une ligne lisible."""
        desc = self.EVENT_DESCRIPTIONS.get(event_id, "Événement Windows")
        source_name = event.SourceName or "Unknown"
        strings = event.StringInserts or []
        detail = " | ".join(str(s) for s in strings[:5]) if strings else ""

        line = f"EventID={event_id} Source={source_name} {desc}"
        if detail:
            line += f" [{detail}]"
        return line

    def _format_wevtutil_event(self, event_dict, channel):
        """Formater un événement wevtutil."""
        event_id = int(event_dict.get("event id", event_dict.get("id", 0)))
        ts = event_dict.get("date", event_dict.get("timecreated", time.strftime("%Y-%m-%d %H:%M:%S")))
        desc = self.EVENT_DESCRIPTIONS.get(event_id, event_dict.get("description", "Événement Windows"))
        level = event_dict.get("level", "Information")

        return {
            "source": channel,
            "line": f"EventID={event_id} {desc}",
            "timestamp": ts,
            "collector": "windows",
            "event_id": event_id,
            "level": self._wevtutil_level_to_level(level)
        }

    def _win32_event_type_to_level(self, event_type):
        """Convertir le type d'événement win32 en niveau de log."""
        mapping = {
            0: "INFO",      # EVENTLOG_SUCCESS
            1: "CRITICAL",  # EVENTLOG_ERROR_TYPE
            2: "WARNING",   # EVENTLOG_WARNING_TYPE
            4: "INFO",      # EVENTLOG_INFORMATION_TYPE
            8: "INFO",      # EVENTLOG_AUDIT_SUCCESS
            16: "HIGH"      # EVENTLOG_AUDIT_FAILURE
        }
        return mapping.get(event_type, "INFO")

    def _wevtutil_level_to_level(self, level_str):
        """Convertir le niveau wevtutil en niveau SOC."""
        level_str = level_str.lower()
        if "error" in level_str or "critical" in level_str:
            return "CRITICAL"
        elif "warning" in level_str:
            return "WARNING"
        return "INFO"

    def _generate_simulated_logs(self):
        """
        Générer des logs simulés quand on n'est pas sur Windows.
        Utile pour les tests sur Linux/Mac.
        """
        import random
        events = [
            {"event_id": 4624, "level": "INFO", "line": "EventID=4624 Ouverture de session réussie [DESKTOP-SOC\\admin LogonType=10 IP=192.168.1.100]"},
            {"event_id": 4625, "level": "HIGH", "line": "EventID=4625 Échec d'ouverture de session [DESKTOP-SOC\\unknown LogonType=3 IP=10.0.0.55]"},
            {"event_id": 4688, "level": "INFO", "line": "EventID=4688 Nouveau processus créé [cmd.exe PID=4532 ParentPID=2100]"},
            {"event_id": 1102, "level": "CRITICAL", "line": "EventID=1102 Journal d'audit effacé [SYSTEM]"},
            {"event_id": 4720, "level": "WARNING", "line": "EventID=4720 Compte utilisateur créé [hacker123]"},
        ]

        # Sélectionner aléatoirement 0-2 événements
        count = random.randint(0, 2)
        selected = random.sample(events, min(count, len(events)))

        result = []
        for evt in selected:
            result.append({
                "source": "Security",
                "line": evt["line"],
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "collector": "windows",
                "event_id": evt["event_id"],
                "level": evt["level"]
            })
        return result

    def get_status(self):
        """Retourne le statut du collecteur."""
        return {
            "is_windows": self.is_windows,
            "has_win32": HAS_WIN32,
            "channels": list(self.channels.keys()),
            "last_records": dict(self.last_record_numbers)
        }
