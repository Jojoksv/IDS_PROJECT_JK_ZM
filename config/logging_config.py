# Logging configuration setup
import logging
import os
from logging.handlers import RotatingFileHandler
from config.settings import LOG_FILE_PATH, MAX_LOG_FILE_SIZE_BYTES, LOG_FILE_BACKUP_COUNT, DEFAULT_LOG_LEVEL

def setup_logging():
    """
    Configure le système de logging pour l'IDS en utilisant les paramètres de settings.py.
    """
    # Crée le répertoire des logs s'il n'existe pas
    log_dir = os.path.dirname(LOG_FILE_PATH)
    os.makedirs(log_dir, exist_ok=True)

    # Configuration du handler de fichier avec rotation
    file_handler = RotatingFileHandler(
        LOG_FILE_PATH,
        maxBytes=MAX_LOG_FILE_SIZE_BYTES,
        backupCount=LOG_FILE_BACKUP_COUNT
    )
    # Format des logs pour le fichier
    file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_formatter)

    # Configuration du handler de console
    stream_handler = logging.StreamHandler()
    # Format des logs pour la console (peut être différent si souhaité)
    stream_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    stream_handler.setFormatter(stream_formatter)

    # Récupérer le logger racine et configurer ses handlers et son niveau
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, DEFAULT_LOG_LEVEL.upper()))

    # Supprimer les handlers existants pour éviter les doublons si la fonction est appelée plusieurs fois
    if root_logger.handlers:
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)

    root_logger.addHandler(file_handler)
    root_logger.addHandler(stream_handler)