 # -----------------------------------------------------------------------------------------------
# Script per la lettura di log da una coda Redis e l'inserimento nel database immutabile immudb.
# Modalità KV con supporto a retention time.
# -----------------------------------------------------------------------------------------------

import redis
import json
import hashlib
import time
import logging
import signal
from immudb.client import ImmudbClient

# ----------------------
# CONFIGURAZIONE SISTEMA
# ----------------------

# Parametri di connessione a Redis
REDIS_HOST = '192.168.56.10'
REDIS_PORT = 6379
REDIS_PASSWORD = 'whyareyourunning?'
REDIS_QUEUE_NAME = 'redis-queue-immudb'  # Nome della coda Redis da cui leggere i log

# Parametri di connessione a immudb
IMMUD_HOST = '127.0.0.1'
IMMUD_PORT = 3322
IMMUD_USER = 'immudb'
IMMUD_PASSWORD = 'immudbcaps'
IMMUD_DATABASE = 'logs_immudb'  # Nome del database immudb in cui vengono scritti i log

# -------------------
# CONFIGURAZIONE LOG
# -------------------

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Flag globale per il ciclo
running = True

def cleanup_and_exit(signum, frame):
    global running
    logging.info(f"Segnale ricevuto ({signum}), avvio cleanup e terminazione...")
    running = False

signal.signal(signal.SIGINT, cleanup_and_exit)
signal.signal(signal.SIGTERM, cleanup_and_exit)

# -------------------
# FUNZIONI DI SUPPORTO
# -------------------

def hash_key(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()

def connect_redis():
    return redis.Redis(host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD, decode_responses=True)

def connect_immudb():
    client = ImmudbClient()
    client.login(IMMUD_USER, IMMUD_PASSWORD)
    client.useDatabase(IMMUD_DATABASE)
    return client

# -------------------
# LOGICA PRINCIPALE
# -------------------

def process_and_print():
    r = connect_redis()
    immu = connect_immudb()

    logging.info(f"In ascolto su Redis '{REDIS_QUEUE_NAME}' e scrittura su immudb KV (database '{IMMUD_DATABASE}')...")

    global running
    while running:
        try:
            item = r.blpop(REDIS_QUEUE_NAME, timeout=5)
            if item:
                _, raw_log = item
                try:
                    log_data = json.loads(raw_log)
                except json.JSONDecodeError:
                    logging.warning(f"Log non valido JSON: {raw_log}")
                    continue

                log_str = json.dumps(log_data, sort_keys=True)
                ts = int(time.time())
                key = f"log:{ts}:{hash_key(log_str)}"

                # Inserimento in modalità KV (chiave e valore codificati come bytes)
                immu.set(key.encode(), log_str.encode())

                logging.info(f"[KV] Log inserito in immudb con chiave: {key}")

        except redis.ConnectionError as e:
            logging.error(f"Errore Redis: {e}")
            time.sleep(5)

        except Exception as e:
            logging.error(f"Errore generale: {e}")
            time.sleep(2)

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
