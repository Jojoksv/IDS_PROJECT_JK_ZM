# Configuration settings for the IDS project
# config/settings.py

import os

# --- Paramètres du moniteur de fichiers (FileMonitor) ---
CRITICAL_FILE_PATHS = [
    "/etc/passwd",
    "/etc/shadow", 
    "/etc/sudoers",
    "/var/log/auth.log",
    "/bin",
    "/usr/bin",
    "/sbin"
]

# --- Paramètres du scanner de ports (PortScanner avec Nmap) ---
NMAP_SCAN_TARGETS = "127.0.0.1"  # ou "192.168.1.1/24" pour un réseau local

NMAP_SCAN_INTERVAL_SECONDS = 30

NMAP_PORTS_TO_SCAN = "1-1024,3306,8080"

NMAP_SCAN_OPTIONS = "-sV"  # Ou "-sT -sV" si vous n'avez pas les droits admin pour -sS

ALLOWED_OPEN_PORTS = [
    22,   # SSH
    80,   # HTTP
    443,  # HTTPS
    3306, # MySQL
    8080  # Serveurs de dev ou applicatifs
]

# --- Paramètres du moniteur de processus (ProcessMonitor) ---
PROCESS_MONITOR_INTERVAL_SECONDS = 60

# Liste blanche des processus connus et sûrs.
# **IMPORTANT : ADAPTEZ CETTE LISTE À VOTRE SYSTÈME LINUX !**
WHITELISTED_PROCESS_NAMES = [
    # Processus système
    "systemd", "kthreadd", "ksoftirqd", "kworker", "rcu_sched",
    "sshd", "cron", "rsyslogd", "dbus-daemon", "systemd-logind",

    # Services web
    "nginx", "apache2", "httpd",

    # Bases de données
    "mysqld", "postgres", "mongod",

    # Scripts système
    "bash", "sh", "python", "perl",

    # Shells alternatifs à surveiller
    "zsh", "tcsh", "ksh", "fish"
]

SUSPICIOUS_CPU_THRESHOLD_PERCENT = 80
SUSPICIOUS_MEMORY_THRESHOLD_PERCENT = 70

# --- Paramètres du générateur de rapports (ReportGenerator) ---
REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'reports')
#---- Intervalle de generation de rapport en secondes
REPORT_GENERATION_INTERVAL_SECONDS = 360
#---- Période couverte par chaque rapport en heure(ex 24h pour un rapport quotidient)
REPORT_PERIOD_HOURS = 24
#---- Niveau de criticité 
MIN_REPORT_LEVEL = "CRITICAL"

# --- Paramètres du logger centralisé ---
LOG_FILE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'logs', 'ids_events.log')
MAX_LOG_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 Mo
LOG_FILE_BACKUP_COUNT = 5
DEFAULT_LOG_LEVEL = "INFO"

# --- Paramètres du service de notification (Placeholder pour plus tard) ---
NOTIFICATION_API_URL = "http://localhost:3000/api/alert"
NOTIFICATION_API_KEY = "your_secret_api_key_here"

