# -----------------------------------------------------------------------------------------------
# Script per la lettura di log da una coda Redis e l'inserimento nel database immutabile immudb.
# -----------------------------------------------------------------------------------------------

import redis
import json
import hashlib
import time
import logging
import signal
import sys
from immudb.client import ImmudbClient

# ----------------------
# CONFIGURAZIONE SISTEMA
# ----------------------

# Parametri di connessione a Redis
REDIS_HOST = '192.168.56.10'
REDIS_PORT = 6379
REDIS_PASSWORD = ''
REDIS_QUEUE_NAME = 'redis-queue-immudb'  # Nome della coda Redis da cui leggere i log

# Parametri di connessione a immudb
IMMUD_HOST = '127.0.0.1'
IMMUD_PORT = 3322
IMMUD_USER = ''
IMMUD_PASSWORD = ''
IMMUD_DATABASE = 'logs_immudb'  # Nome del database immudb in cui verranno scritti i log

# -------------------
# CONFIGURAZIONE LOG
# -------------------

# Imposta il livello di logging e il formato dei messaggi
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Flag globale per controllare l'esecuzione del ciclo principale
running = True

def cleanup_and_exit(signum, frame):
    """
    Funzione chiamata alla ricezione dei segnali SIGINT e SIGTERM.
    Imposta la flag globale 'running' a False per terminare ordinatamente il ciclo principale.
    Qui si possono inserire operazioni di cleanup come chiusura di file,
    connessioni al database o flush di buffer.
    """
    global running
    logging.info(f"Segnale ricevuto ({signum}), avvio cleanup e terminazione...")
    running = False

# Registrazione dei segnali SIGINT (Ctrl+C) e SIGTERM (systemctl stop)
signal.signal(signal.SIGINT, cleanup_and_exit)
signal.signal(signal.SIGTERM, cleanup_and_exit)

# -------------------
# FUNZIONI DI SUPPORTO
# -------------------

def hash_key(data: str) -> str:
    """
    Calcola l'hash SHA-256 della stringa fornita.
    Utilizzato per generare una chiave primaria unica e deterministica per ogni log.
    """
    return hashlib.sha256(data.encode()).hexdigest()

def connect_redis():
    """
    Inizializza e restituisce una connessione al server Redis.
    """
    return redis.Redis(host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD, decode_responses=True)

def connect_immudb():
    """
    Inizializza e restituisce una connessione a immudb.
    Esegue il login e seleziona il database specificato.
    Se non esiste, crea la tabella `logs` con chiave primaria `log_key`.
    """
    client = ImmudbClient()
    client.login(IMMUD_USER, IMMUD_PASSWORD)
    client.useDatabase(IMMUD_DATABASE)
    client.sqlExec("""
        CREATE TABLE IF NOT EXISTS logs (
            log_key VARCHAR(64) PRIMARY KEY,
            value VARCHAR(10000)
        )
    """)
    return client

# -------------------
# LOGICA PRINCIPALE
# -------------------

def process_and_print():
    """
    Avvia il ciclo principale:
    - Legge i log dalla coda Redis in modalità bloccante (`blpop`)
    - Valida e normalizza i log in formato JSON
    - Calcola l'hash SHA-256 come chiave
    - Inserisce i dati in immudb nella tabella `logs`
    """
    r = connect_redis()
    immu = connect_immudb()

    logging.info(f"In ascolto su Redis '{REDIS_QUEUE_NAME}' e scrittura su immudb (database '{IMMUD_DATABASE}')...")

    global running
    while running:
        try:
            # Legge un elemento dalla coda (attende massimo 5 secondi)
            item = r.blpop(REDIS_QUEUE_NAME, timeout=5)
            if item:
                _, raw_log = item
                try:
                    # Prova a decodificare il JSON
                    log_data = json.loads(raw_log)
                except json.JSONDecodeError:
                    logging.warning(f"Log non valido JSON: {raw_log}")
                    continue

                # Serializza il JSON in forma ordinata per assicurare coerenza dell'hash
                log_str = json.dumps(log_data, sort_keys=True)
                key = hash_key(log_str)

                # Inserisce il log in immudb con chiave hash e valore serializzato
                immu.sqlExec(
                    "INSERT INTO logs (log_key, value) VALUES (@log_key, @value)",
                    {"log_key": key, "value": log_str}
                )

                logging.info(f"[KEY] Chiave immudb generata e inserita: {key}")

        except redis.ConnectionError as e:
            logging.error(f"Errore Redis: {e}")
            time.sleep(5)

        except Exception as e:
            logging.error(f"Errore generale: {e}")
            time.sleep(2)

    # Cleanup finale se serve
    logging.info("Pulizia finale eseguita, uscita script.")

# -------------------
# AVVIO DELLO SCRIPT
# -------------------

if __name__ == '__main__':
    try:
        process_and_print()
    except Exception as e:
        logging.error(f"Errore inatteso: {e}")
    finally:
        logging.info("Script terminato.")
