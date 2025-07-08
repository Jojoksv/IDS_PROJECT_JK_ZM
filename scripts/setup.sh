#!/bin/bash

echo "🛠️  [SETUP] Démarrage de l'installation..."

# Vérifie que le script est exécuté avec des droits root
if [ "$EUID" -ne 0 ]; then
  echo "❌ Veuillez exécuter ce script avec sudo."
  exit 1
fi

# 🔄 Mise à jour du système
echo "🔄 Mise à jour des paquets..."
apt update && apt upgrade -y

# 🐍 Installation de Python 3, pip et venv
echo "🐍 Installation de Python 3, pip et venv..."
apt install -y python3 python3-pip python3-venv

# 🔍 Installation des outils réseau et mail
echo "🔧 Installation de Nmap, ssmtp, mailutils, inotify-tools..."
apt install -y nmap ssmtp mailutils inotify-tools

# 🧩 Installation de Node.js et npm
echo "🧩 Installation de Node.js et npm..."
apt install -y nodejs npm

# 📁 Création de l’environnement virtuel Python s'il n'existe pas
if [ ! -d "../venv" ]; then
  echo "📁 Création de l’environnement virtuel Python dans le dossier parent..."
  python3 -m venv ../venv
fi

# ⚙️  Activation de l’environnement virtuel
echo "⚙️  Activation de l’environnement virtuel Python..."
source ../venv/bin/activate

# 📦 Installation des dépendances Python dans le venv
echo "📦 Installation des dépendances Python nécessaires..."
pip install --upgrade pip
pip install watchdog python-nmap psutil requests

# 🔚 Désactivation de l’environnement virtuel
deactivate

# 🚀 Installation des dépendances Node.js du serveur de notification
NOTIF_DIR="../src/notification_service"

if [ -d "$NOTIF_DIR" ]; then
  echo "📦 Installation des dépendances Node.js dans '$NOTIF_DIR'..."
  cd "$NOTIF_DIR"
  npm install
  cd - > /dev/null
else
  echo "⚠️  Le dossier '$NOTIF_DIR' est introuvable. Vérifiez l’arborescence du projet."
fi

echo "✅ Installation terminée avec succès !"

