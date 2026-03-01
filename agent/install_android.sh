#!/data/data/com.termux/files/usr/bin/bash
# =============================================================================
#  Oktopus SOC — Script d'installation Android (Termux)
# =============================================================================
#  Fichier : agent/install_android.sh
#  Rôle    : Installe automatiquement l'environnement nécessaire pour
#            l'agent Android dans Termux.
#
#  Usage   : bash install_android.sh
#  
#  Ce script :
#  1. Met à jour les packages Termux
#  2. Installe Python 3, pip, git
#  3. Installe psutil via pip
#  4. Vérifie que tout fonctionne
#  5. Donne les instructions de lancement
# =============================================================================

set -e  # Arrêter en cas d'erreur

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Bannière
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║    🐙 Oktopus SOC — Installation Android 🐙     ║${NC}"
echo -e "${CYAN}║           📱 Termux Edition                      ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# =============================================================================
#  Vérification de l'environnement Termux
# =============================================================================

echo -e "${BLUE}[1/6]${NC} Vérification de l'environnement Termux..."

if [ ! -d "/data/data/com.termux" ]; then
    echo -e "${RED}  ✗ Ce script doit être exécuté dans Termux !${NC}"
    echo -e "${YELLOW}  Installez Termux depuis F-Droid : https://f-droid.org/packages/com.termux/${NC}"
    exit 1
fi

echo -e "${GREEN}  ✓ Termux détecté${NC}"

# =============================================================================
#  Mise à jour des packages
# =============================================================================

echo ""
echo -e "${BLUE}[2/6]${NC} Mise à jour des packages Termux..."
pkg update -y
pkg upgrade -y
echo -e "${GREEN}  ✓ Packages mis à jour${NC}"

# =============================================================================
#  Installation de Python et des outils de base
# =============================================================================

echo ""
echo -e "${BLUE}[3/6]${NC} Installation de Python 3 et des outils..."

# Python
if command -v python3 &> /dev/null; then
    PYTHON_VER=$(python3 --version 2>&1)
    echo -e "${GREEN}  ✓ Python déjà installé : ${PYTHON_VER}${NC}"
else
    pkg install python -y
    echo -e "${GREEN}  ✓ Python installé${NC}"
fi

# Git (optionnel mais utile pour cloner le projet)
if command -v git &> /dev/null; then
    echo -e "${GREEN}  ✓ Git déjà installé${NC}"
else
    pkg install git -y
    echo -e "${GREEN}  ✓ Git installé${NC}"
fi

# Outils réseau (pour le diagnostic)
if command -v ifconfig &> /dev/null; then
    echo -e "${GREEN}  ✓ net-tools déjà installé${NC}"
else
    pkg install net-tools -y 2>/dev/null || echo -e "${YELLOW}  ⚠ net-tools non disponible (optionnel)${NC}"
fi

# =============================================================================
#  Installation des dépendances Python
# =============================================================================

echo ""
echo -e "${BLUE}[4/6]${NC} Installation des dépendances Python..."

# Mettre à jour pip
python3 -m pip install --upgrade pip 2>/dev/null || pip install --upgrade pip

# Installer psutil (nécessaire pour la collecte système)
echo -e "  Installation de psutil..."
pip install psutil
echo -e "${GREEN}  ✓ psutil installé${NC}"

# =============================================================================
#  Vérification de l'installation
# =============================================================================

echo ""
echo -e "${BLUE}[5/6]${NC} Vérification de l'installation..."

# Vérifier Python
PYTHON_OK=false
if python3 -c "print('Python OK')" &> /dev/null; then
    PYTHON_VER=$(python3 --version 2>&1)
    echo -e "${GREEN}  ✓ Python : ${PYTHON_VER}${NC}"
    PYTHON_OK=true
else
    echo -e "${RED}  ✗ Python ne fonctionne pas !${NC}"
fi

# Vérifier psutil
PSUTIL_OK=false
if python3 -c "import psutil; print(f'psutil {psutil.__version__}')" 2>/dev/null; then
    PSUTIL_VER=$(python3 -c "import psutil; print(psutil.__version__)" 2>/dev/null)
    echo -e "${GREEN}  ✓ psutil : ${PSUTIL_VER}${NC}"
    PSUTIL_OK=true
else
    echo -e "${RED}  ✗ psutil ne fonctionne pas !${NC}"
    echo -e "${YELLOW}    Essayez : pip install psutil --no-binary :all:${NC}"
fi

# Vérifier la batterie
python3 -c "
import psutil
b = psutil.sensors_battery()
if b:
    print(f'  ✓ Batterie détectée : {b.percent:.0f}%')
else:
    print('  ⚠ sensors_battery() retourne None (normal sur certains appareils)')
" 2>/dev/null || echo -e "${YELLOW}  ⚠ Test batterie échoué (pas grave)${NC}"

# Vérifier le réseau
python3 -c "
import psutil
try:
    conns = psutil.net_connections(kind='inet')
    print(f'  ✓ net_connections : {len(conns)} connexions actives')
except (psutil.AccessDenied, PermissionError):
    print('  ⚠ net_connections : permission refusée (normal sans root)')
except Exception as e:
    print(f'  ⚠ net_connections : {e}')
" 2>/dev/null || echo -e "${YELLOW}  ⚠ Test réseau échoué (pas grave)${NC}"

# =============================================================================
#  Résumé et instructions
# =============================================================================

echo ""
echo -e "${BLUE}[6/6]${NC} Installation terminée !"
echo ""

if $PYTHON_OK && $PSUTIL_OK; then
    echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║          ✅ Installation réussie !                ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
else
    echo -e "${YELLOW}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║     ⚠️  Installation partielle — voir ci-dessus   ║${NC}"
    echo -e "${YELLOW}╚══════════════════════════════════════════════════╝${NC}"
fi

echo ""
echo -e "${CYAN}=== INSTRUCTIONS DE LANCEMENT ===${NC}"
echo ""
echo -e "  1. Naviguez vers le répertoire du projet :"
echo -e "     ${YELLOW}cd soc-system${NC}"
echo ""
echo -e "  2. Lancez l'agent Android :"
echo -e "     ${YELLOW}python3 -m agent.android_agent --server <IP_SERVEUR>${NC}"
echo ""
echo -e "  Exemples :"
echo -e "     ${YELLOW}python3 -m agent.android_agent --server 192.168.1.100${NC}"
echo -e "     ${YELLOW}python3 -m agent.android_agent --server 192.168.1.100 --port 9999${NC}"
echo -e "     ${YELLOW}python3 -m agent.android_agent --server 10.0.0.1 --interval 10${NC}"
echo ""
echo -e "  Options :"
echo -e "     --server  IP du serveur SOC (défaut: 127.0.0.1)"
echo -e "     --port    Port TCP (défaut: 9999)"
echo -e "     --interval  Intervalle de collecte en secondes (défaut: 5)"
echo -e "     --agent-id  ID personnalisé de l'agent"
echo ""
echo -e "${CYAN}=== ARRÊT ===${NC}"
echo -e "  Appuyez sur Ctrl+C pour arrêter l'agent."
echo ""
echo -e "🐙 ${GREEN}Oktopus SOC — Rise from the deep. Crush every threat.${NC} 🐙"
echo ""
