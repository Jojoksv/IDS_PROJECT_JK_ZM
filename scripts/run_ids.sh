#!/bin/bash
# Run script: démarre les services IDS avec environnement virtuel

echo "🚨 Lancement du système IDS..."

# Aller dans le dossier racine du projet
cd "$(dirname "$0")/.." || {
  echo "❌ Impossible d'accéder au dossier parent (racine du projet)."
  exit 1
}

# Chemin du script principal
MAIN_SCRIPT="src/main.py"

# Vérifie que le fichier main.py existe
if [ ! -f "$MAIN_SCRIPT" ]; then
  echo "❌ Erreur : Le fichier $MAIN_SCRIPT est introuvable depuis $(pwd)."
  exit 1
fi

# Active l’environnement virtuel (qui se trouve dans scripts/venv)
if [ -d "scripts/venv" ]; then
  echo "⚙️  Activation de l’environnement virtuel..."
  source scripts/venv/bin/activate
else
  echo "❌ L’environnement virtuel 'scripts/venv/' est introuvable. Veuillez exécuter './scripts/setup.sh' d’abord."
  exit 1
fi

# Définir le PYTHONPATH pour que Python trouve le module src/
export PYTHONPATH=$(pwd)

# Exécute le programme
python "$MAIN_SCRIPT"

# Désactivation (optionnelle)
deactivate
