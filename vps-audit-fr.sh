#!/usr/bin/env bash

# Couleurs pour l'affichage
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
GRAY='\033[0;90m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # Pas de couleur

# Obtenir le timestamp actuel pour le nom du fichier de rapport
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE="rapport-audit-vps-${TIMESTAMP}.txt"

print_header() {
    local header="$1"
    echo -e "\n${BLUE}${BOLD}$header${NC}"
    echo -e "\n$header" >> "$REPORT_FILE"
    echo "================================" >> "$REPORT_FILE"
}

print_info() {
    local label="$1"
    local value="$2"
    echo -e "${BOLD}$label:${NC} $value"
    echo "$label: $value" >> "$REPORT_FILE"
}

# Démarrage de l'audit
echo -e "${BLUE}${BOLD}Outil d'audit de sécurité VPS${NC}"
echo -e "${GRAY}https://github.com/linkeaz/vps-audit-fr${NC}"
echo -e "${GRAY}Début de l'audit à $(date)${NC}\n"

echo "Outil d'audit de sécurité VPS" > "$REPORT_FILE"
echo "https://github.com/linkeaz/vps-audit-fr" >> "$REPORT_FILE"
echo "Début de l'audit à $(date)" >> "$REPORT_FILE"
echo "================================" >> "$REPORT_FILE"

# Section Informations Système
print_header "Informations Système"

# Récupérer les informations système
OS_INFO=$(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2)
KERNEL_VERSION=$(uname -r)
HOSTNAME=$HOSTNAME
UPTIME=$(uptime -p)
UPTIME_SINCE=$(uptime -s)
CPU_INFO=$(lscpu | grep "Model name" | cut -d':' -f2 | xargs)
CPU_CORES=$(nproc)
TOTAL_MEM=$(free -h | awk '/^Mem:/ {print $2}')
TOTAL_DISK=$(df -h / | awk 'NR==2 {print $2}')
PUBLIC_IP=$(curl -s https://api.ipify.org)
LOAD_AVERAGE=$(uptime | awk -F'load average:' '{print $2}' | xargs)

# Afficher les informations système
print_info "Nom d'hôte" "$HOSTNAME"
print_info "Système d'exploitation" "$OS_INFO"
print_info "Version du noyau" "$KERNEL_VERSION"
print_info "Temps de fonctionnement" "$UPTIME (depuis $UPTIME_SINCE)"
print_info "Modèle de CPU" "$CPU_INFO"
print_info "Cœurs de CPU" "$CPU_CORES"
print_info "Mémoire Totale" "$TOTAL_MEM"
print_info "Espace Disque Total" "$TOTAL_DISK"
print_info "IP Publique" "$PUBLIC_IP"
print_info "Charge Moyenne" "$LOAD_AVERAGE"

echo "" >> "$REPORT_FILE"

# Section Résultats de l'audit de sécurité
print_header "Résultats de l'audit de sécurité"

# Fonction pour vérifier et rapporter avec trois états
check_security() {
    local test_name="$1"
    local status="$2"
    local message="$3"
    
    case $status in
        "PASS")
            echo -e "${GREEN}[PASS]${NC} $test_name ${GRAY}- $message${NC}"
            echo "[PASS] $test_name - $message" >> "$REPORT_FILE"
            ;;
        "WARN")
            echo -e "${YELLOW}[WARN]${NC} $test_name ${GRAY}- $message${NC}"
            echo "[WARN] $test_name - $message" >> "$REPORT_FILE"
            ;;
        "FAIL")
            echo -e "${RED}[FAIL]${NC} $test_name ${GRAY}- $message${NC}"
            echo "[FAIL] $test_name - $message" >> "$REPORT_FILE"
            ;;
    esac
    echo "" >> "$REPORT_FILE"
}

# Vérifier le temps de fonctionnement du système
UPTIME=$(uptime -p)
UPTIME_SINCE=$(uptime -s)
echo -e "\nInformations sur le temps de fonctionnement du système:" >> "$REPORT_FILE"
echo "Temps de fonctionnement actuel: $UPTIME" >> "$REPORT_FILE"
echo "Système en marche depuis: $UPTIME_SINCE" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo -e "Temps de fonctionnement du système: $UPTIME (depuis $UPTIME_SINCE)"

# Vérifier si le système nécessite un redémarrage
if [ -f /var/run/reboot-required ]; then
    check_security "Redémarrage Système" "WARN" "Le système nécessite un redémarrage pour appliquer les mises à jour"
else
    check_security "Redémarrage Système" "PASS" "Aucun redémarrage requis"
fi

# Vérifier les surcharges de configuration SSH
SSH_CONFIG_OVERRIDES=$(grep "^Include" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')

# Vérifier l'accès root en SSH (gérer à la fois la config principale et les surcharges si elles existent)
if [ -n "$SSH_CONFIG_OVERRIDES" ] && [ -d "$(dirname "$SSH_CONFIG_OVERRIDES")" ]; then
    SSH_ROOT=$(grep "^PermitRootLogin" $SSH_CONFIG_OVERRIDES /etc/ssh/sshd_config 2>/dev/null | head -1 | awk '{print $2}')
else
    SSH_ROOT=$(grep "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null | head -1 | awk '{print $2}')
fi
if [ -z "$SSH_ROOT" ]; then
    SSH_ROOT="prohibit-password"
fi
if [ "$SSH_ROOT" = "no" ]; then
    check_security "Connexion SSH en tant que root" "PASS" "La connexion root est correctement désactivée dans la configuration SSH"
else
    check_security "Connexion SSH en tant que root" "FAIL" "La connexion root est actuellement autorisée - c'est un risque de sécurité. Désactivez-la dans /etc/ssh/sshd_config"
fi

# Vérifier l'authentification par mot de passe en SSH (gérer à la fois la config principale et les surcharges si elles existent)
if [ -n "$SSH_CONFIG_OVERRIDES" ] && [ -d "$(dirname "$SSH_CONFIG_OVERRIDES")" ]; then
    SSH_PASSWORD=$(grep "^PasswordAuthentication" $SSH_CONFIG_OVERRIDES /etc/ssh/sshd_config 2>/dev/null | head -1 | awk '{print $2}')
else
    SSH_PASSWORD=$(grep "^PasswordAuthentication" /etc/ssh/sshd_config 2>/dev/null | head -1 | awk '{print $2}')
fi
if [ -z "$SSH_PASSWORD" ]; then
    SSH_PASSWORD="yes"
fi
if [ "$SSH_PASSWORD" = "no" ]; then
    check_security "Authentification par mot de passe en SSH" "PASS" "L'authentification par mot de passe est désactivée, authentification par clé uniquement"
else
    check_security "Authentification par mot de passe en SSH" "FAIL" "L'authentification par mot de passe est activée - envisagez d'utiliser uniquement l'authentification par clé"
fi

# Vérifier les ports SSH par défaut/non sécurisés 
UNPRIVILEGED_PORT_START=$(sysctl -n net.ipv4.ip_unprivileged_port_start)
SSH_PORT=""
if [ -n "$SSH_CONFIG_OVERRIDES" ] && [ -d "$(dirname "$SSH_CONFIG_OVERRIDES")" ]; then
    SSH_PORT=$(grep "^Port" $SSH_CONFIG_OVERRIDES /etc/ssh/sshd_config 2>/dev/null | head -1 | awk '{print $2}')
else
    SSH_PORT=$(grep "^Port" /etc/ssh/sshd_config 2>/dev/null | head -1 | awk '{print $2}')
fi
if [ -z "$SSH_PORT" ]; then
    SSH_PORT="22"
fi

if [ "$SSH_PORT" = "22" ]; then
    check_security "Port SSH" "WARN" "Utilisation du port par défaut 22 - envisagez de le changer pour un port non standard par sécurité par obscurité"
elif [ "$SSH_PORT" -ge "$UNPRIVILEGED_PORT_START" ]; then
    check_security "Port SSH" "FAIL" "Utilisation d'un port non privilégié $SSH_PORT - utilisez un port inférieur à $UNPRIVILEGED_PORT_START pour une meilleure sécurité"
else
    check_security "Port SSH" "PASS" "Utilisation d'un port non par défaut $SSH_PORT, ce qui aide à prévenir les attaques automatisées"
fi

# Vérifier l'état du pare-feu
check_firewall_status() {
    if command -v ufw >/dev/null 2>&1; then
        if ufw status | grep -qw "active"; then
            check_security "État du Pare-feu (UFW)" "PASS" "Le pare-feu UFW est actif et protège votre système"
        else
            check_security "État du Pare-feu (UFW)" "FAIL" "Le pare-feu UFW n'est pas actif - votre système est exposé aux attaques réseau"
        fi
    elif command -v firewall-cmd >/dev/null 2>&1; then
        if firewall-cmd --state 2>/dev/null | grep -q "running"; then
            check_security "État du Pare-feu (firewalld)" "PASS" "Firewalld est actif et protège votre système"
        else
            check_security "État du Pare-feu (firewalld)" "FAIL" "Firewalld n'est pas actif - votre système est exposé aux attaques réseau"
        fi
    elif command -v iptables >/dev/null 2>&1; then
        if iptables -L -n | grep -q "Chain INPUT"; then
            check_security "État du Pare-feu (iptables)" "PASS" "Les règles iptables sont actives et protègent votre système"
        else
            check_security "État du Pare-feu (iptables)" "FAIL" "Aucune règle iptables active trouvée - votre système pourrait être exposé"
        fi
    elif command -v nft >/dev/null 2>&1; then
        if nft list ruleset | grep -q "table"; then
            check_security "État du Pare-feu (nftables)" "PASS" "Les règles nftables sont actives et protègent votre système"
        else
            check_security "État du Pare-feu (nftables)" "FAIL" "Aucune règle nftables active trouvée - votre système pourrait être exposé"
        fi
    else
        check_security "État du Pare-feu" "FAIL" "Aucun outil de pare-feu reconnu n'est installé sur ce système"
    fi
}

# Vérification du pare-feu
check_firewall_status

# Vérifier les mises à jour automatiques (unattended upgrades)
if dpkg -l | grep -q "unattended-upgrades"; then
    check_security "Mises à jour automatiques" "PASS" "Les mises à jour de sécurité automatiques sont configurées"
else
    check_security "Mises à jour automatiques" "FAIL" "Les mises à jour de sécurité automatiques ne sont pas configurées - le système pourrait manquer des mises à jour critiques"
fi

# Vérifier les systèmes de prévention d'intrusion (Fail2ban ou CrowdSec)
IPS_INSTALLED=0
IPS_ACTIVE=0

if dpkg -l | grep -q "fail2ban"; then
    IPS_INSTALLED=1
    systemctl is-active fail2ban >/dev/null 2>&1 && IPS_ACTIVE=1
fi

# Vérifier si un conteneur Docker exécutant Fail2ban est présent
if command -v docker >/dev/null 2>&1; then
    if systemctl is-active --quiet docker; then
        if docker ps -a | awk '{print $2}' | grep "fail2ban" >/dev/null 2>&1; then
            IPS_INSTALLED=1
            docker ps | grep -q "fail2ban" && IPS_ACTIVE=1
        fi
    else
        check_security "Prévention d'intrusion" "WARN" "Docker est installé mais non actif - impossible de vérifier les conteneurs Fail2ban"
    fi
fi

if dpkg -l | grep -q "crowdsec"; then
    IPS_INSTALLED=1
    systemctl is-active crowdsec >/dev/null 2>&1 && IPS_ACTIVE=1
fi

# Vérifier si un conteneur Docker exécutant CrowdSec est présent
if command -v docker >/dev/null 2>&1; then
    if systemctl is-active --quiet docker; then
        if docker ps -a | awk '{print $2}' | grep "crowdsec" >/dev/null 2>&1; then
            IPS_INSTALLED=1
            docker ps | grep -q "crowdsec" && IPS_ACTIVE=1
        fi
    else
        check_security "Prévention d'intrusion" "WARN" "Docker est installé mais non actif - impossible de vérifier les conteneurs CrowdSec"
    fi
fi

case "$IPS_INSTALLED$IPS_ACTIVE" in
    "11") check_security "Prévention d'intrusion" "PASS" "Fail2ban ou CrowdSec est installé et actif" ;;
    "10") check_security "Prévention d'intrusion" "WARN" "Fail2ban ou CrowdSec est installé mais non actif" ;;
    *)    check_security "Prévention d'intrusion" "FAIL" "Aucun système de prévention d'intrusion (Fail2ban ou CrowdSec) n'est installé" ;;
esac

# Vérifier les tentatives de connexion échouées
LOG_FILE="/var/log/auth.log"

if [ -f "$LOG_FILE" ]; then
    FAILED_LOGINS=$(grep -c "Failed password" "$LOG_FILE" 2>/dev/null || echo 0)
else
    FAILED_LOGINS=0
    echo "Attention : Fichier log $LOG_FILE introuvable ou illisible. On suppose 0 tentatives de connexion échouées." >> "$REPORT_FILE"
fi

# S'assurer que FAILED_LOGINS est numérique et enlever les espaces
FAILED_LOGINS=$(echo "$FAILED_LOGINS" | tr -d '[:space:]')
# Supprimer les zéros en début (le cas échéant)
FAILED_LOGINS=$((10#$FAILED_LOGINS)) # Utiliser l'évaluation arithmétique pour s'assurer que c'est numérique et correctement formaté.

if [ "$FAILED_LOGINS" -lt 10 ]; then
    check_security "Connexions échouées" "PASS" "Seulement $FAILED_LOGINS tentatives de connexion échouées détectées - ce qui est dans la norme"
elif [ "$FAILED_LOGINS" -lt 50 ]; then
    check_security "Connexions échouées" "WARN" "$FAILED_LOGINS tentatives de connexion échouées détectées - pourrait indiquer des tentatives de violation"
else
    check_security "Connexions échouées" "FAIL" "$FAILED_LOGINS tentatives de connexion échouées détectées - possible attaque par force brute en cours"
fi

# Vérifier les mises à jour système
UPDATES=$(apt-get -s upgrade 2>/dev/null | grep -P '^\d+ upgraded' | cut -d" " -f1)
if [ -z "$UPDATES" ]; then
    UPDATES=0
fi
if [ "$UPDATES" -eq 0 ]; then
    check_security "Mises à jour système" "PASS" "Tous les paquets du système sont à jour"
else
    check_security "Mises à jour système" "FAIL" "$UPDATES mises à jour de sécurité disponibles - le système est vulnérable aux exploits connus"
fi

# Vérifier les services en cours d'exécution
SERVICES=$(systemctl list-units --type=service --state=running | grep -c "loaded active running")
if [ "$SERVICES" -lt 20 ]; then
    check_security "Services en cours" "PASS" "Nombre minimal de services en cours ($SERVICES) - bon pour la sécurité"
elif [ "$SERVICES" -lt 40 ]; then
    check_security "Services en cours" "WARN" "$SERVICES services en cours - envisagez de réduire la surface d'attaque"
else
    check_security "Services en cours" "FAIL" "Trop de services en cours ($SERVICES) - augmente la surface d'attaque"
fi

# Vérifier les ports avec netstat ou ss
if command -v netstat >/dev/null 2>&1; then
    LISTENING_PORTS=$(netstat -tuln | grep LISTEN | awk '{print $4}')
elif command -v ss >/dev/null 2>&1; then
    LISTENING_PORTS=$(ss -tuln | grep LISTEN | awk '{print $5}')
else
    check_security "Scan des ports" "FAIL" "Ni 'netstat' ni 'ss' ne sont disponibles sur ce système."
    LISTENING_PORTS=""
fi

# Traiter LISTENING_PORTS pour extraire les ports publics uniques
if [ -n "$LISTENING_PORTS" ]; then
    PUBLIC_PORTS=$(echo "$LISTENING_PORTS" | awk -F':' '{print $NF}' | sort -n | uniq | tr '\n' ',' | sed 's/,$//')
    PORT_COUNT=$(echo "$PUBLIC_PORTS" | tr ',' '\n' | wc -w)
    INTERNET_PORTS=$(echo "$PUBLIC_PORTS" | tr ',' '\n' | wc -w)

    if [ "$PORT_COUNT" -lt 10 ] && [ "$INTERNET_PORTS" -lt 3 ]; then
        check_security "Sécurité des ports" "PASS" "Bonne configuration (Total: $PORT_COUNT, Public: $INTERNET_PORTS ports accessibles): $PUBLIC_PORTS"
    elif [ "$PORT_COUNT" -lt 20 ] && [ "$INTERNET_PORTS" -lt 5 ]; then
        check_security "Sécurité des ports" "WARN" "Recommandation à revoir (Total: $PORT_COUNT, Public: $INTERNET_PORTS ports accessibles): $PUBLIC_PORTS"
    else
        check_security "Sécurité des ports" "FAIL" "Exposition élevée (Total: $PORT_COUNT, Public: $INTERNET_PORTS ports accessibles): $PUBLIC_PORTS"
    fi
else
    check_security "Scan des ports" "WARN" "Le scan des ports a échoué en raison de l'absence d'outils. Assurez-vous que 'ss' ou 'netstat' est installé."
fi

# Fonction pour formater le message avec une indentation appropriée pour le fichier de rapport
format_for_report() {
    local message="$1"
    echo "$message" >> "$REPORT_FILE"
}

# Vérifier l'utilisation de l'espace disque
DISK_TOTAL=$(df -h / | awk 'NR==2 {print $2}')
DISK_USED=$(df -h / | awk 'NR==2 {print $3}')
DISK_AVAIL=$(df -h / | awk 'NR==2 {print $4}')
DISK_USAGE=$(df -h / | awk 'NR==2 {print int($5)}')
if [ "$DISK_USAGE" -lt 50 ]; then
    check_security "Utilisation du disque" "PASS" "Espace disque sain (${DISK_USAGE}% utilisé - Utilisé: ${DISK_USED} sur ${DISK_TOTAL}, Disponible: ${DISK_AVAIL})"
elif [ "$DISK_USAGE" -lt 80 ]; then
    check_security "Utilisation du disque" "WARN" "Utilisation modérée du disque (${DISK_USAGE}% utilisé - Utilisé: ${DISK_USED} sur ${DISK_TOTAL}, Disponible: ${DISK_AVAIL})"
else
    check_security "Utilisation du disque" "FAIL" "Utilisation critique du disque (${DISK_USAGE}% utilisé - Utilisé: ${DISK_USED} sur ${DISK_TOTAL}, Disponible: ${DISK_AVAIL})"
fi

# Vérifier l'utilisation de la mémoire
MEM_TOTAL=$(free -h | awk '/^Mem:/ {print $2}')
MEM_USED=$(free -h | awk '/^Mem:/ {print $3}')
MEM_AVAIL=$(free -h | awk '/^Mem:/ {print $7}')
MEM_USAGE=$(free | awk '/^Mem:/ {printf "%.0f", $3/$2 * 100}')
if [ "$MEM_USAGE" -lt 50 ]; then
    check_security "Utilisation de la mémoire" "PASS" "Utilisation saine de la mémoire (${MEM_USAGE}% utilisé - Utilisé: ${MEM_USED} sur ${MEM_TOTAL}, Disponible: ${MEM_AVAIL})"
elif [ "$MEM_USAGE" -lt 80 ]; then
    check_security "Utilisation de la mémoire" "WARN" "Utilisation modérée de la mémoire (${MEM_USAGE}% utilisé - Utilisé: ${MEM_USED} sur ${MEM_TOTAL}, Disponible: ${MEM_AVAIL})"
else
    check_security "Utilisation de la mémoire" "FAIL" "Utilisation critique de la mémoire (${MEM_USAGE}% utilisé - Utilisé: ${MEM_USED} sur ${MEM_TOTAL}, Disponible: ${MEM_AVAIL})"
fi

# Vérifier l'utilisation du CPU
CPU_CORES=$(nproc)
CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{print int($2)}')
CPU_IDLE=$(top -bn1 | grep "Cpu(s)" | awk '{print int($8)}')
CPU_LOAD=$(uptime | awk -F'load average:' '{ print $2 }' | awk -F',' '{ print $1 }' | tr -d ' ')
if [ "$CPU_USAGE" -lt 50 ]; then
    check_security "Utilisation du CPU" "PASS" "Utilisation saine du CPU (${CPU_USAGE}% utilisé - Actif: ${CPU_USAGE}%, Inactif: ${CPU_IDLE}%, Charge: ${CPU_LOAD}, Cœurs: ${CPU_CORES})"
elif [ "$CPU_USAGE" -lt 80 ]; then
    check_security "Utilisation du CPU" "WARN" "Utilisation modérée du CPU (${CPU_USAGE}% utilisé - Actif: ${CPU_USAGE}%, Inactif: ${CPU_IDLE}%, Charge: ${CPU_LOAD}, Cœurs: ${CPU_CORES})"
else
    check_security "Utilisation du CPU" "FAIL" "Utilisation critique du CPU (${CPU_USAGE}% utilisé - Actif: ${CPU_USAGE}%, Inactif: ${CPU_IDLE}%, Charge: ${CPU_LOAD}, Cœurs: ${CPU_CORES})"
fi

# Vérifier la configuration de sudo
if grep -q "^Defaults.*logfile" /etc/sudoers; then
    check_security "Journalisation sudo" "PASS" "Les commandes sudo sont enregistrées pour audit"
else
    check_security "Journalisation sudo" "FAIL" "Les commandes sudo ne sont pas enregistrées - capacité d'audit réduite"
fi

# Vérifier la politique de mot de passe
if [ -f "/etc/security/pwquality.conf" ]; then
    if grep -q "minlen.*12" /etc/security/pwquality.conf; then
        check_security "Politique de mot de passe" "PASS" "Une politique de mot de passe robuste est appliquée"
    else
        check_security "Politique de mot de passe" "FAIL" "Politique de mot de passe faible - les mots de passe peuvent être trop simples"
    fi
else
    check_security "Politique de mot de passe" "FAIL" "Aucune politique de mot de passe configurée - le système accepte des mots de passe faibles"
fi

# Vérifier les fichiers SUID suspects
COMMON_SUID_PATHS='^/usr/bin/|^/bin/|^/sbin/|^/usr/sbin/|^/usr/lib|^/usr/libexec'
KNOWN_SUID_BINS='ping$|sudo$|mount$|umount$|su$|passwd$|chsh$|newgrp$|gpasswd$|chfn$'

SUID_FILES=$(find / -type f -perm -4000 2>/dev/null | \
    grep -v -E "$COMMON_SUID_PATHS" | \
    grep -v -E "$KNOWN_SUID_BINS" | \
    wc -l)

if [ "$SUID_FILES" -eq 0 ]; then
    check_security "Fichiers SUID" "PASS" "Aucun fichier SUID suspect trouvé - bonne pratique de sécurité"
else
    check_security "Fichiers SUID" "WARN" "$SUID_FILES fichiers SUID trouvés en dehors des emplacements standards - vérifiez s'ils sont légitimes"
fi

# Ajouter un résumé des informations système au rapport
echo "================================" >> "$REPORT_FILE"
echo "Résumé des Informations Système:" >> "$REPORT_FILE"
echo "Nom d'hôte: $(hostname)" >> "$REPORT_FILE"
echo "Noyau: $(uname -r)" >> "$REPORT_FILE"
echo "OS: $(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2)" >> "$REPORT_FILE"
echo "Cœurs de CPU: $(nproc)" >> "$REPORT_FILE"
echo "Mémoire Totale: $(free -h | awk '/^Mem:/ {print $2}')" >> "$REPORT_FILE"
echo "Espace Disque Total: $(df -h / | awk 'NR==2 {print $2}')" >> "$REPORT_FILE"
echo "================================" >> "$REPORT_FILE"

echo -e "\nAudit VPS terminé. Rapport complet enregistré dans $REPORT_FILE"
echo -e "Consultez $REPORT_FILE pour des recommandations détaillées."

# Ajouter le résumé au rapport
echo "================================" >> "$REPORT_FILE"
echo "Fin du Rapport d'Audit VPS" >> "$REPORT_FILE"
echo "Veuillez vérifier toutes les vérifications ayant échoué et mettre en œuvre les correctifs recommandés." >> "$REPORT_FILE"
