"""
=============================================================================
 Oktopus — Module Géo-IP (Localisation des IPs attaquantes)
=============================================================================
 Fichier : server/geo_ip.py
 Rôle    : Géolocalisation des adresses IP via l'API ip-api.com
           - Lookup IP → pays, ville, coordonnées (lat/lon)
           - Cache mémoire pour éviter les appels API répétés
           - Filtrage des IPs privées (RFC 1918 + loopback)
           - Conversion code pays → emoji drapeau
 
 API     : http://ip-api.com/json/{IP}?fields=status,country,countryCode,city,lat,lon
 Limite  : 45 requêtes/minute (gratuit, sans clé API)
 
 Auteur  : Oktopus Team
 Python  : 3.8+
=============================================================================
"""

import json
import urllib.request
import urllib.error
import re
import threading
from datetime import datetime, timedelta
from typing import Optional, Dict


class GeoIPLookup:
    """
    Service de géolocalisation IP pour le SOC.
    
    Utilise l'API gratuite ip-api.com pour résoudre les IPs publiques
    en coordonnées géographiques. Les résultats sont mis en cache
    pour éviter les appels API redondants.
    
    Attributs :
        cache       : Dict {ip: {data, timestamp}} — cache mémoire
        cache_ttl   : Durée de vie du cache en secondes (défaut: 3600)
        timeout     : Timeout HTTP en secondes (défaut: 3)
        lock        : Verrou pour accès concurrent au cache
    """

    # Regex pour détecter les IPs privées (RFC 1918 + loopback + link-local)
    PRIVATE_IP_PATTERNS = [
        re.compile(r'^10\.'),                          # 10.0.0.0/8
        re.compile(r'^172\.(1[6-9]|2[0-9]|3[01])\.'), # 172.16.0.0/12
        re.compile(r'^192\.168\.'),                    # 192.168.0.0/16
        re.compile(r'^127\.'),                         # 127.0.0.0/8 (loopback)
        re.compile(r'^0\.'),                           # 0.0.0.0/8
        re.compile(r'^169\.254\.'),                    # 169.254.0.0/16 (link-local)
        re.compile(r'^fc00:', re.IGNORECASE),          # IPv6 ULA
        re.compile(r'^fe80:', re.IGNORECASE),          # IPv6 link-local
        re.compile(r'^::1$'),                          # IPv6 loopback
    ]

    def __init__(self, cache_ttl: int = 3600, timeout: int = 3):
        """
        Initialise le service Géo-IP.
        
        Args:
            cache_ttl : Durée de vie du cache en secondes (défaut: 1 heure)
            timeout   : Timeout des requêtes HTTP en secondes (défaut: 3s)
        """
        self.cache: Dict[str, Dict] = {}
        self.cache_ttl = cache_ttl
        self.timeout = timeout
        self.lock = threading.Lock()
        
        # Statistiques
        self.total_lookups = 0
        self.cache_hits = 0
        self.api_calls = 0
        self.api_errors = 0
        
        print(f"\033[96m[GEO-IP]\033[0m Service initialisé "
              f"(cache TTL: {cache_ttl}s, timeout: {timeout}s)")

    def lookup(self, ip: str) -> Optional[Dict]:
        """
        Géolocalise une adresse IP.
        
        Processus :
        1. Vérifie si l'IP est privée → retourne None
        2. Vérifie le cache → retourne le résultat si trouvé et valide
        3. Appel API ip-api.com → stocke en cache et retourne
        
        Args:
            ip : Adresse IP à géolocaliser
        
        Returns:
            Dict contenant :
                - ip           : Adresse IP
                - country      : Nom du pays
                - country_code : Code pays ISO (ex: "FR")
                - city         : Ville
                - lat          : Latitude
                - lon          : Longitude
                - flag         : Emoji drapeau du pays
            None si IP privée, invalide, ou erreur API
        """
        self.total_lookups += 1
        
        if not ip or not isinstance(ip, str):
            return None
        
        ip = ip.strip()
        
        # --- 1. IPs privées → retourner position "Réseau Local" ---
        if self._is_private_ip(ip):
            return {
                "ip": ip,
                "country": "Réseau Local",
                "country_code": "LAN",
                "city": "Private Network",
                "lat": 48.8566,   # Paris par défaut (position neutre)
                "lon": 2.3522,
                "flag": "🏠",
            }
        
        # --- 2. Vérifier le cache ---
        with self.lock:
            if ip in self.cache:
                entry = self.cache[ip]
                age = (datetime.now() - entry["cached_at"]).total_seconds()
                if age < self.cache_ttl:
                    self.cache_hits += 1
                    return entry["data"]
                else:
                    # Entrée expirée
                    del self.cache[ip]
        
        # --- 3. Appel API ip-api.com ---
        try:
            url = (
                f"http://ip-api.com/json/{ip}"
                f"?fields=status,country,countryCode,city,lat,lon"
            )
            
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "SOC-SIEM/1.0")
            
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                raw = response.read().decode("utf-8")
                data = json.loads(raw)
            
            self.api_calls += 1
            
            if data.get("status") != "success":
                return None
            
            # Construire le résultat
            result = {
                "ip": ip,
                "country": data.get("country", "Unknown"),
                "country_code": data.get("countryCode", ""),
                "city": data.get("city", "Unknown"),
                "lat": data.get("lat", 0),
                "lon": data.get("lon", 0),
                "flag": self._country_code_to_flag(data.get("countryCode", "")),
            }
            
            # Stocker en cache
            with self.lock:
                self.cache[ip] = {
                    "data": result,
                    "cached_at": datetime.now()
                }
            
            return result
        
        except (urllib.error.URLError, urllib.error.HTTPError) as e:
            self.api_errors += 1
            print(f"\033[93m[GEO-IP]\033[0m Erreur API pour {ip}: {e}")
            return None
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            self.api_errors += 1
            print(f"\033[93m[GEO-IP]\033[0m Erreur parsing pour {ip}: {e}")
            return None
        except Exception as e:
            self.api_errors += 1
            print(f"\033[93m[GEO-IP]\033[0m Erreur inattendue pour {ip}: {e}")
            return None

    def _is_private_ip(self, ip: str) -> bool:
        """
        Vérifie si une IP est privée (RFC 1918, loopback, link-local).
        
        Args:
            ip : Adresse IP à vérifier
        
        Returns:
            bool : True si l'IP est privée
        """
        for pattern in self.PRIVATE_IP_PATTERNS:
            if pattern.search(ip):
                return True
        return False

    def _country_code_to_flag(self, country_code: str) -> str:
        """
        Convertit un code pays ISO 3166-1 alpha-2 en emoji drapeau.
        
        Utilise les Regional Indicator Symbols Unicode.
        Chaque lettre du code pays est convertie en son caractère
        Regional Indicator Symbol correspondant (U+1F1E6 à U+1F1FF).
        
        Exemples :
            "FR" → 🇫🇷
            "US" → 🇺🇸
            "CN" → 🇨🇳
        
        Args:
            country_code : Code pays ISO alpha-2 (ex: "FR", "US")
        
        Returns:
            str : Emoji drapeau, ou chaîne vide si code invalide
        """
        if not country_code or len(country_code) != 2:
            return ""
        
        try:
            # Regional Indicator Symbol Letter A = U+1F1E6
            # Offset = ord('A') = 65
            flag = ""
            for char in country_code.upper():
                if 'A' <= char <= 'Z':
                    flag += chr(0x1F1E6 + ord(char) - ord('A'))
                else:
                    return ""
            return flag
        except (ValueError, TypeError):
            return ""

    def extract_ip_from_alert(self, alert: Dict) -> Optional[str]:
        """
        Extrait l'adresse IP source depuis le message d'une alerte.
        
        Cherche des patterns d'IP dans le message de l'alerte.
        Ignore les IPs privées et retourne la première IP publique trouvée.
        
        Args:
            alert : Dictionnaire de l'alerte (contient au moins 'message')
        
        Returns:
            str : Première IP publique trouvée, ou None
        """
        message = alert.get("message", "")
        if not message:
            return None
        
        # Pattern IPv4
        ip_pattern = re.compile(
            r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
            r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
        )
        
        matches = ip_pattern.findall(message)
        
        for ip in matches:
            if not self._is_private_ip(ip):
                return ip
        
        return None

    def get_stats(self) -> Dict:
        """
        Retourne les statistiques du service Géo-IP.
        
        Returns:
            Dict : {total_lookups, cache_hits, cache_size, api_calls, api_errors}
        """
        with self.lock:
            cache_size = len(self.cache)
        
        return {
            "total_lookups": self.total_lookups,
            "cache_hits": self.cache_hits,
            "cache_size": cache_size,
            "api_calls": self.api_calls,
            "api_errors": self.api_errors,
        }

    def cleanup_cache(self):
        """
        Supprime les entrées expirées du cache.
        À appeler périodiquement pour éviter les fuites mémoire.
        """
        now = datetime.now()
        expired = []
        
        with self.lock:
            for ip, entry in self.cache.items():
                age = (now - entry["cached_at"]).total_seconds()
                if age >= self.cache_ttl:
                    expired.append(ip)
            
            for ip in expired:
                del self.cache[ip]
        
        if expired:
            print(f"\033[90m[GEO-IP]\033[0m Cache nettoyé : "
                  f"{len(expired)} entrée(s) expirée(s) supprimée(s)")


# =============================================================================
#  POINT D'ENTRÉE — Test standalone
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("  SOC Geo-IP — Test Standalone")
    print("=" * 60)

    geo = GeoIPLookup()

    # Test 1 : IP privée
    print("\n--- Test 1 : IP privée (doit retourner None) ---")
    result = geo.lookup("192.168.1.100")
    print(f"  192.168.1.100 → {result}")

    result = geo.lookup("10.0.0.5")
    print(f"  10.0.0.5 → {result}")

    result = geo.lookup("127.0.0.1")
    print(f"  127.0.0.1 → {result}")

    # Test 2 : IP publique (Google DNS)
    print("\n--- Test 2 : IP publique (8.8.8.8) ---")
    result = geo.lookup("8.8.8.8")
    if result:
        print(f"  IP     : {result['ip']}")
        print(f"  Pays   : {result['flag']} {result['country']}")
        print(f"  Ville  : {result['city']}")
        print(f"  Coords : {result['lat']}, {result['lon']}")
    else:
        print("  Erreur ou pas de résultat")

    # Test 3 : Cache
    print("\n--- Test 3 : Cache (même IP) ---")
    result2 = geo.lookup("8.8.8.8")
    print(f"  Cache hit : {geo.cache_hits > 0}")

    # Test 4 : Extraction IP depuis alerte
    print("\n--- Test 4 : Extraction IP depuis alerte ---")
    alert = {
        "message": "Brute force détecté depuis 203.0.113.50 — 10 tentatives en 60s"
    }
    extracted = geo.extract_ip_from_alert(alert)
    print(f"  IP extraite : {extracted}")

    # Test 5 : Flag emoji
    print("\n--- Test 5 : Flag emoji ---")
    print(f"  FR → {geo._country_code_to_flag('FR')}")
    print(f"  US → {geo._country_code_to_flag('US')}")
    print(f"  CN → {geo._country_code_to_flag('CN')}")
    print(f"  JP → {geo._country_code_to_flag('JP')}")

    # Stats
    print(f"\n--- Stats : {geo.get_stats()} ---")

    print("\n" + "=" * 60)
    print("  ✅ Tests Geo-IP terminés !")
    print("=" * 60)
