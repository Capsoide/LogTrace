# Sistema di monitoraggio Audit Logs

## Introduzione
Questo sistema si occupa dell'acquisizione automatica dei log di audit relativi agli accessi amministrativi ai sistemi Windows. I log vengono archiviati in un database immutabile per garantirne l’integrità e resi consultabili tramite una dashboard interattiva, pensata per facilitare l’analisi e il monitoraggio delle attività.

Il processo viene realizzato attraverso una pipeline composta dai seguenti componenti:
- ```Winlogbeat```, installato su un'istanza Windows Server, è il servizio responsabile del recupero e dell'invio degli eventi log di audit raccolti da Event Viewer.
- ```Logstash```, in esecuzione su un sistema Debian, riceve i log da Winlogbeat processandoli e duplicandoli in due differenti code Redis.
- ```Redis```, funge da sistema di gestione delle code, permettendo la separazione dei flussi di log:
  - La **coda 0** (`redis-queue-elastic`) invia i log a **Elasticsearch** per l'indicizzazione e la visualizzazione tramite interfaccia front-end.
  - La **coda 1** (`redis-queue-immudb`)  è dedicata alla persistenza dei log in un database immutabile (immudb), progettato per garantire integrità, non ripudiabilità e conservazione a lungo termine. In questo contesto, è configurata una retention time pari a 24 ore.

Questa architettura garantisce la duplicazione dei dati per scopi distinti come analisi e conservazione forense in modo tale da garantirne l'integrità e l'inalterabilità nel tempo. 
I singoli componenti svolgono i seguenti ruoli:

- `Winlogbeat`: acquisizione dei log da Event Viewer.
- `Logstash`: duplicazione dei flussi di log e invio alle rispettive code Redis.
- `Redis`: gestione dei buffer dei dati.
- `Immudb`: archiviazione sicura e immutabile dei log.
- `Elasticsearch`: indicizzazione e front-end per analisi interattiva dei log.

L'intero sistema è progettato per soddisfare i requisiti normativi previsti dalle direttive **ACN**, **ISO/IEC 27001** e **NIS2**, che impongono il tracciamento, la conservazione e l’integrità dei log di sicurezza:

- [**ACN**](https://www.acn.gov.it/portale/nis/aggiornamento-informazioni) (Agenzia per la Cybersicurezza Nazionale) stabilisce standard per la sicurezza delle infrastrutture critiche italiane.
- [**ISO/IEC 27001**](https://edirama.org/wp-content/uploads/2023/10/document-1.pdf) è uno standard internazionale per la gestione della sicurezza delle informazioni (ISMS), che richiede la registrazione e l’analisi degli eventi di accesso.
- [**NIS2**](https://www.acn.gov.it/portale/nis) è la direttiva europea sulla sicurezza delle reti e dei sistemi informativi, che impone obblighi di logging, conservazione e risposta agli incidenti per gli operatori di servizi essenziali.

---


# Schema infrastruttura
<div align="center" style="border:1px solid #ccc; padding:10px; display: inline-block;"> 
  <img src="https://github.com/user-attachments/assets/b3270ac1-cef3-4cdf-8747-8dfef05f4ffa" alt="image" /> 
</div>

---

# Comunicazione Windows Server - Debian via VirtualBox

In questa prima parte si descrive come creare una rete locale tra due macchine virtuali (VM) usando **VirtualBox** con una rete **Host-Only**.

## Topologia di rete

| Sistema Operativo |       IP      |           Ruolo            | 
|-------------------|---------------|----------------------------|
| Windows Server    | 192.168.56.2  | Sender (Winlogbeat)        |
| Ubuntu/Debian     | 192.168.56.10 | Receiver (Redis, Logstash) |


## Configurazione adattatore Host-Only (Virtualbox)

#### 1. Aprire **VirtualBox** → `File` → `Host Network Manager`
#### 2. Cliccare su **Crea** per aggiungere un nuovo adattatore
#### 3. Configurazione:
   - **IP**: `192.168.56.1`
   - **Subnet Mask**: `255.255.255.0`
   - **DHCP**: disabilitato
#### 4. Assegnare l’adattatore come **Adattatore 2** alle VM:
   - Modalità: `Host-Only`
   - Nome: ad esempio `vboxnet0`

## Configurazione IP Statici (Windows Server)

#### 1. Aprire `Centro connessioni di rete` > `Modificare impostazioni scheda`
#### 2. Scegliere l’interfaccia collegata a `vboxnet0` (“Ethernet 2”)
#### 3. Cliccare su `Proprietà` > `TCP/IPv4` e impostare:
   - **IP**: `192.168.56.2`
   - **Subnet mask**: `255.255.255.0`
   - **Gateway**: lascia vuoto

#### 4. Verificare con ```ipconfig``` 

```powershell
C:\Users\vboxuser> ipconfig
Windows IP Configuration


Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . : sigmaspa.lan
   IPv6 Address. . . . . . . . . . . : fd00::be82:30db:2cc8:18ab
   Link-local IPv6 Address . . . . . : fe80::b789:33f2:febd:1d7%14
   IPv4 Address. . . . . . . . . . . : 10.0.2.15
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : fe80::2%14
                                       10.0.2.2

Ethernet adapter Ethernet 2:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::6894:81ba:3678:5341%13
   IPv4 Address. . . . . . . . . . . : 192.168.56.2    <---
   Subnet Mask . . . . . . . . . . . : 255.255.255.0   <---
   Default Gateway . . . . . . . . . :
```

---

## Configurazione interfacce di rete (Debian)

Configurare le interfacce di rete modificando direttamente il file  ```interfaces``` posizionato in ```/etc/network/```.

```text
# Include configurazioni aggiuntive (se presenti)
source /etc/network/interfaces.d/*

# Interfaccia loopback
auto lo
iface lo inet loopback

# Interfaccia NAT (internet)
auto enp0s3
iface enp0s3 inet dhcp

# Interfaccia Host-Only (rete interna con VirtualBox)
auto enp0s8
iface enp0s8 inet static
    address 192.168.56.10   <---
    netmask 255.255.255.0   <---
```
## Regola firewall: permettere il ping da Debian a Windows Server

E' necessario creare una regola per Windows Server poichè il firewall (di Windows) blocca di default i pacchetti ICMP Echo Request (ping) in ingresso. 

### Passaggi step-by-step

#### 1. Aprire Windows Defender Firewall con sicurezza avanzata
   
    Premere il tasto Windows, digitare "Windows Defender Firewall with Advanced Security", successivamente aprire l’app.
                                                                                                                       
  	
#### 2. Selezionare “Regole in ingresso” (Inbound Rules)
   
    Nel pannello a sinistra, cliccare su Inbound Rules.
  	
#### 3. Creare una nuova regola
   
    Nel pannello a destra, cliccare su New Rule... (Nuova regola).
  	
#### 4. Scegliere il tipo di regola
   
    Selezionare Custom (Personalizzata), poi cliccare su Avanti.
  	
#### 5. Selezionare il protocollo
    
    Alla voce “Protocol and Ports” (Protocollo e porte), scegliere ICMPv4 dal menu a tendina “Protocol type”.
  	
#### 6. Specificare il tipo di pacchetto ICMP
   
    Cliccare sul pulsante Customize accanto a ICMP Settings.
  	
    Selezionare Echo Request (il tipo usato dal ping).
  	
    Confermare con OK.
  	
#### 7. Indirizzi IP
   
    Nella schermata “Scope” lasciare l’opzione “Any IP address” (qualsiasi indirizzo) sia per origine sia per destinazione (, o limita all’IP del Debian se si vuole maggiore sicurezza).
  	
#### 8. Azione della regola
    
    Selezionare Allow the connection (Consenti la connessione).
   	
#### 9. Quando applicare la regola
    
    Spuntare tutte le caselle: Domain, Private, Public.
   	
#### 10. Dare un nome alla regola
    
    Scrivere un nome tipo "Consenti ping ICMP Echo Request" e confermare.


### Verifica

```bash
vboxuser@vbox:~$ ip link
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000
    link/ether 08:00:27:e0:87:cc brd ff:ff:ff:ff:ff:ff
3: enp0s8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000   <---
    link/ether 08:00:27:9d:3a:10 brd ff:ff:ff:ff:ff:ff

#Applicazione delle modifiche
vboxuser@vbox:~$ sudo systemctl restart networking

#Se necessario utilizzare il seguente comando (o inalternativa riaviare la vm)
vboxuser@vbox:~$ sudo ifdown enp0s8 && sudo ifup enp0s8
```
```bash
#Verifica che l'indirizzo sia stato applicato correttamente
vboxuser@vbox:~$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute 
       valid_lft forever preferred_lft forever
2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:e0:87:cc brd ff:ff:ff:ff:ff:ff
    inet 10.0.2.15/24 brd 10.0.2.255 scope global dynamic enp0s3
       valid_lft 84997sec preferred_lft 84997sec
    inet6 fd00::a00:27ff:fee0:87cc/64 scope global dynamic mngtmpaddr 
       valid_lft 86245sec preferred_lft 14245sec
    inet6 fe80::a00:27ff:fee0:87cc/64 scope link 
       valid_lft forever preferred_lft forever
3: enp0s8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:9d:3a:10 brd ff:ff:ff:ff:ff:ff
    inet 192.168.56.10/24 brd 192.168.56.255 scope global enp0s8   <---
       valid_lft forever preferred_lft forever
    inet6 fe80::a00:27ff:fe9d:3a10/64 scope link 
       valid_lft forever preferred_lft forever
```

### Ping da Debian a Windows Server

```bash
vboxuser@vbox:~$ ping -c 192.168.56.2
PING 192.168.56.2 (192.168.56.2) 56(84) bytes of data.
64 bytes from 192.168.56.2: icmp_seq=1 ttl=128 time=6.43 ms
64 bytes from 192.168.56.2: icmp_seq=2 ttl=128 time=1.18 ms
64 bytes from 192.168.56.2: icmp_seq=3 ttl=128 time=1.16 ms

--- 192.168.56.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms   <---
rtt min/avg/max/mdev = 1.160/2.923/6.434/2.482 ms
```

### Ping da Windows Server a Debian

```powershell
C:\Users\vboxuser>ping 192.168.56.10
Pinging 192.168.56.10 with 32 bytes of data:
Reply from 192.168.56.10: bytes=32 time=1ms TTL=64
Reply from 192.168.56.10: bytes=32 time=1ms TTL=64
Reply from 192.168.56.10: bytes=32 time=1ms TTL=64
Reply from 192.168.56.10: bytes=32 time=1ms TTL=64

Ping statistics for 192.168.56.10:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),   <---
Approximate round trip times in milli-seconds:
    Minimum = 1ms, Maximum = 1ms, Average = 1ms
```

# Winlogbeat

Winlogbeat è un agente software che raccoglie e invia i Windows Event Log verso endpoint **Redis**, **Logstash** ed **Elasticsearch**.

### Azioni Winlogbeat

1. **Monitoraggio del Registro Eventi**: legge in tempo reale eventi da log come `Security`, `System`, `Application`, `ForwardedEvents`, e altri.
2. **Filtraggio intelligente**: raccoglie solo specifici `event_id`, provider o livelli, riducendo il rumore.
3. **Spedizione dei log**: inoltra i dati verso Redis, Logstash ed Elasticsearch.
4. **Supporto ECS**: normalizza i dati secondo l’Elastic Common Schema.
5. **Dashboard Kibana integrate**: fornisce visualizzazioni pronte all’uso.

## Gerarchia directory: Winlogbeat

```
Winlogbeat/
├── winlogbeat.exe
├── winlogbeat.yml
├── winlogbeat.reference.yml
├── install-service-winlogbeat.ps1
├── uninstall-service-winlogbeat.ps1
├── fields.yml
├── LICENSE.txt, NOTICE.txt, README.md
├── .build_hash.txt
├── winlogbeat.yml_bk
├── data/
│   ├── winlogbeat.yml
│   └── meta.json
└── module/
    ├── powershell/
    │   └── config/
    │       └── winlogbeat-powershell.js
    ├── security/
    │   ├── dashboards.yml
    │   └── config/
    │       └── winlogbeat-security.js
    └── sysmon/
        └── config/
            └── winlogbeat-sysmon.js
```

## winlogbeat.yml

Percorso: ```/Winlogbeat/data/winlogbeat.yml```

```yaml
winlogbeat.event_logs:
  - name: Security
    event_id: 4624, 4634
  - name: System
  - name: Application

output.redis:
  hosts: ["192.168.56.10:6379"]
  key: "winlogbeat"
  db: 0
  timeout: 5

setup.template.enabled: false
setup.ilm.enabled: false

logging:
  level: info
  to_files: true
  files:
    path: C:/ProgramData/winlogbeat/Logs
    name: winlogbeat.log
    keepfiles: 7
```

## Installazione come Servizio Windows

```powershell
cd C:\\Winlogbeat
.\install-service-winlogbeat.ps1
Start-Service winlogbeat
Set-Service -Name winlogbeat -StartupType Automatic
```

## Disinstallazione

```powershell
Stop-Service winlogbeat
.\uninstall-service-winlogbeat.ps1
```

---

## Debug e Verifica

- **Log locale**: `C:\\ProgramData\\winlogbeat\\Logs\\winlogbeat.log`

- **Verifica output Redis**:

  ```bash
  redis-cli -h 192.168.56.10 -p 6379
  LRANGE winlogbeat 0 0
  ```

- **Test manuale**:

  ```powershell
  .\winlogbeat.exe -c winlogbeat.yml -e -v
  ```

---

# Logstash

Logstash è una pipeline open source utilizzata per  la gestione, elaborazione e inoltro in tempo reale di dati provenienti da diverse fonti verso una o più destinazioni.

Nel contesto di questo sistema, Logstash riceve eventi in formato JSON da Winlogbeat, li processa e invia i dati in output a due code Redis distinte, permettendo la duplicazione del flusso: 
- una prima coda destinata all’ingestione in Elasticsearch per analisi;
- una seconda coda per la storicizzazione in immuDB.

## Gerarchia directory: Logstash

```
/etc/logstash/
    ├── conf.d/
    │   ├── logstash.conf
    │   └── logstash1.conf
    ├── jvm.options
    ├── log4j2.properties
    ├── logstash.yml
    ├── pipelines.yml
    └── startup.options
```

## logstash.conf

Percorso: ```/etc/logstash/conf.d/logstash.conf```

File di configurazione Logstash che definisce una pipeline impostato per ricevere i log da ```Winlogbeat``` via Beats protocol (porta 5044) e per la duplicazione dei log su due code Redis.

```yaml
# Input: riceve dati da Winlogbeat tramite protocollo Beats sulla porta 5044
input {
    beats {
    port => 5044
  }
}

filter {
  # Inserire eventuali filtri o parsing (ad esempio, grok, mutate, ecc.)
}

# Output: invia i dati processati verso due code Redis diverse (duplicazione)

output {
# output (1): manda i dati alla coda Redis "redis-queue-elastic"
  redis {
    host => "192.168.56.10"
    port => 6379
    password => ""
    key => "redis-queue-elastic"
    data_type => "list"
    db => 0
  }

  # output (2): manda gli stessi dati alla coda Redis "redis-queue-immudb"
  redis {
    host => "192.168.56.10"
    port => 6379
    password => ""
    key => "redis-queue-immudb"
    data_type => "list"
    db => 0
  }
}
```

## logstash1.conf

Percorso: ```/etc/logstash/conf.d/logstash1.conf```

File di confogurazione (2) impostato per leggere i log da ```Redis``` e inviarli ad ```Elasticsearch```.

```yaml
input {
  redis {
    host => "192.168.56.10"       # Indirizzo del server Redis dove leggere la coda
    data_type => "list"           # Tipo struttura dati usata in Redis: lista         
    port => 6379                  # Porta del server Redis: 6379 è quella di default
    key => "redis-queue-elastic"  # Key Redis: nome lista Redis da cui Logstash legge i dati
    password => ""                # PSW key Redis
    codec => json                 # Codec usato per decodificare i dati ricevuti da Redis: formato JSON, quindi Logstash li trasforma automaticamente in oggetti leggibili e filtrabili
  }
}

filter {
  #Qui è possibile inserire eventuali filtri per elaborare o arricchire i dati ricevuti prima di inviarli ad Elastic
}

output {
  elasticsearch {
    hosts => ["http://192.168.56.10:9200"]   # Indirizzo del cluster Elasticsearch (modifica in base all'ambiente che si utilizza)
    index => "from-redis-%{+YYYY.MM.dd}"     # Nome dell'indice su Elasticsearch. Viene usata una data dinamica per indicizzazione giornaliera
  
    # Autenticazione Elasticsearch e certificato ssl
    user => ""
    password => ""
    ssl => true
    cacert => "/etc/elasticsearch/certs/ca.crt"
  }
  stdout{
    codec => rubydebug
  }
}
```

## logstash.yml

Percorso: ```/etc/logstash/logstash.yml```

File di configurazione principale di Logstash, in cui si definisce la directory per l’archiviazione dei dati interni.

```yaml                                                     
# ------------ Data path ------------
# Which directory should be used by logstash and its plugins
#for any persistent needs. Defaults to LOGSTASH_HOME/data
#
path.data: /var/lib/logstash
#
```

## pipelines.yml

Percorso: ```/etc/logstash/pipelines.yml```

Definizione delle pipeline distinte per Logstash
  - ```main```: pipeline utlizziata per immudb,
  - ```elastic-pipeline```: utilizzata per elasticsearch.

```yaml                                                     
# This file is where you define your pipelines. You can define multiple.
# For more information on multiple pipelines, see the documentation:
# https://www.elastic.co/guide/en/logstash/current/multiple-pipelines.html

# pipeline immudb
- pipeline.id: main
  path.config: "/etc/logstash/conf.d/logstash.conf"

# pipeline elasticsearch
- pipeline.id: elastic-pipeline
  path.config: "/etc/logstash/conf.d/logstash1.conf"
```

---

# Accesso e verifica delle code Redis

Accedere al server Redis remoto ed elencare le chiavi disponibili per verificare la presenza delle due code:

```bash
vboxuser@vbox:/$ redis-cli -h 192.168.56.10
192.168.56.10> auth inserisci_la_tua_password
OK
192.168.56.10> keys *
1) "redis-queue-immudb"
2) "redis-queue-elastic
```

Verificare che i log siano stati inseriti correttamente nelle due code Redis:

```bash
192.168.56.10> LLEN redis-queue-immudb
(integer) 144
192.168.56.10> LLEN redis-queue-elastic
(integer) 144
```

---

# Immudb

## Gerarchia directory (file configurazione di immudb)
```
/etc/immudb/
     └── immudb.toml
```

## immudb.toml

Percorso: ```/etc/immudb/immudb.toml```

File di configurazione principale per il servizio immudb.

```yaml
# Porta, directory dei dati, autenticazione

address = "0.0.0.0"
admin-password = ''
auth = true
certificate = ''
clientcas = ''
dbname = 'logs_immudb'
detached = 'false'
devmode = true
dir = '/var/lib/immudb'
network = 'tcp'
port 3322
# Log path with filename
logfile = 'immudb.log'
mtls = false
pidfile = '/var/lib/immudb/immudb.pid'
PKEY = ''
log-level = "DEBUG"
[retention]
tables = [
  { db = "logs_immudb", table = "logstash_logs", retentionPeriod = "24h" }
]

```
Nel file di configurazione ```immudb.toml```, sono specificati i path fondamentali per il funzionamento del database: ```/var/lib/immudb``` è la directory principale dei dati che contiene:

- I database configurati ed utilizzati (```defaultdb``` e ```logs_immudb```).
- Le strutture immutabili dei dati (Merkle tree, indici, log transazionali).

```
/var/lib/immudb
         ├── defaultdb
         ├── logs_immudb          
         ├── immudb.identifier
         ├── immudb.pid           
         ├── immulog
         |   └──immudb.log
         └── systemdb
```

Il file ```immudb-log``` contiene tutte le informazioni di esecuzione del server immudb: 
- path utilizzati (dati, log, configurazione, PID),
- stato del servizio;
- connessioni;
- operazioni di scrittura e lettura;
- eventuali errori;
- debug/monitoraggio del sistema.

## Verifica log generati

```bash
vboxuser@vbox:~$ sudo tail -n 50 /var/lib/immudb/immulog/immudb.log
```

## Login

```bash
vboxuser@vbox:~$ immuadmin login inerisci_tuo_username
Password: inserisci_la_tua_password
logged in
```

## Creazione di un nuovo database con retention time period

```bash
vboxuser@vbox:~$ immuadmin database create nome_database --retention-period=24h --tokenfile ~/immuadmin_token
```

## Listare database esistenti

```bash
vboxuser@vbox:~$ immuadmin database list --tokenfile ~/immuadmin_token
2 database(s)
-  --------------  ----------  ----------  ------  ----------  ---------  ------------
#  Databases Name  Created At  Created By  Status  Is Replica  Disk Size  Transactions
-  --------------  ----------  ----------  ------  ----------  ---------  ------------
1  defaultdb       2025-06-18  systemdb    LOADED  FALSE       21.3 MB    6045
2  logs_immudb     2025-06-17  nome_utente LOADED  FALSE       1.8 MB     184
-  --------------  ----------  ----------  ------  ----------  ---------  ------------
```

---

# queue_consumer.py

Percorso: ```/var/consumer-immudb/queue_consumer.py```

## Descrizione

Questo script (`queue_consumer.py`) consuma log JSON da una coda Redis (`redis-queue-immudb`) e li inserisce nella tabella `logs` di immudb usando le API SQL.

## Funzionamento

- I log vengono letti in modalità bloccante da Redis.
- Ogni log viene serializzato con ordinamento delle chiavi.
- Si calcola un hash SHA-256 del contenuto: è usato come chiave primaria (`log_key`).
- Il log completo viene salvato come stringa (`value`).

## Definizione tabella `logs`

```sql
CREATE TABLE IF NOT EXISTS logs (
    log_key VARCHAR(64) PRIMARY KEY,
    value VARCHAR(10000)
);
```
- log_key: campo di tipo VARCHAR(64) che funge da chiave primaria. In questo caso contiene l’hash SHA-256 calcolato dal contenuto del log, che assicura unicità e integrità.

- value: campo di tipo VARCHAR(10000) che contiene il log serializzato in formato JSON (come stringa).

```python
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

```

## Output atteso

```bash
vboxuser@vbox:/$ source /home/vboxuser/my-venv/bin/activate
(my-venv) vboxuser@vbox:/$ /home/vboxuser/my-venv/bin/python /home/vboxuser/Documents/redis_reader.py
2025-06-18 15:45:36,783 - INFO - In ascolto su Redis 'redis-queue-immudb' e scrittura su immudb (database 'logs_immudb')...
2025-06-18 15:45:36,854 - INFO - [KEY] Chiave immudb generata e inserita: 149cf3c7024285a6539433d1f84b17411f0527b67da963ddf4b421e5ee2c540c
```

## Visualizzazione in immuDB

```bash
+--------------------------------------------------------------------+--------------------------------------------------------+
|                           (key.value)                              |                         (logs.value)                   |   
+--------------------------------------------------------------------+--------------------------------------------------------+
|                                                                    | "{"@timestamp": "2025-06-18 15:45:36,854.089Z",        |    
|                                                                    | "@version": "1", "agent": {"ephemeral_id":             |       
|                                                                    | "70d8b8eb-8915-459e-badf-05c9118e73c6", "hostname":    |        
|                                                                    | "WIN-S", "id": "c156a342-40dc-47ca-977a-f100ebd8e89f", |        
|                                                                    | "name": "WIN-S", "type": "winlogbeat", "version":      |      
| "149cf3c7024285a6539433d1f84b17411f0527b67da963ddf4b421e5ee2c540c" | "7.17.7"}, "ecs": {"version": "1.12.0"},               |      
|                                                                    | "event": {"action": "Logon", "code": "4624",           |     
|                                                                    | "created": "2025-06-17T12:02:18.364Z", "kind":         |      
|                                                                    | "event", "outcome": "success", "provider":             |        
|                                                                    | "Microsoft-Windows-Security-Auditing"}, "host":        |       
|                                                                    |                          ...                           |        
|                                                                    |                          ...                           |       
|                                                                    |                          ...                           |       
+--------------------------------------------------------------------+--------------------------------------------------------+
```

## Verifica in redis: Consumazione coda

```bash
vboxuser@vbox:/$ redis-cli -h 192.168.56.10
192.168.56.10> auth inserisci_la_tua_password
OK
192.168.56.10> keys *
1) "redis-queue-elastic"
192.168.56.10> LLEN "redis-queue-immudb"
(integer) 0
```
La coda è stata consumata in modo corretto e i log sono salvati in immuDB.

---

# Analisi Log e UX Grafica con Elasticsearch e Kibana

# Elasticsearch 

### Gerarchia directory (file configurazione di Elasticsearch)

```
/etc/elasticsearch/
├── certs/
│   ├── ca.crt                 # Certificato pubblico della Certificate Authority (CA) usata per firmare gli altri certificati.
│   ├── ca.key                 # Chiave privata della CA (va tenuta segreta).
│   ├── ca.srl                 # Seriale CA, tiene traccia dei certificati già emessi.
│   ├── elasticsearch.crt      # Certificato pubblico di Elasticsearch, firmato dalla CA.
│   ├── elasticsearch.csr      # Richiesta di firma del certificato per Elasticsearch.
│   ├── elasticsearch.key      # Chiave privata di Elasticsearch, usata per TLS.
│   ├── kibana.crt             # Certificato pubblico di Kibana, firmato dalla CA.
│   ├── kibana.csr             # Richiesta di firma del certificato per Kibana.
│   └── kibana.key             # Chiave privata di Kibana (usata da Kibana, ma conservata qui).
|
├── elasticsearch.keystore     # File keystore sicuro con segreti (es. password, token).
├── elasticsearch-plugins.example.yml
├── elasticsearch.yml          # File principale di configurazione di Elasticsearch.
├── jvm.options                # Opzioni JVM (heap size, GC, ecc.).
├── jvm.options.d/             # Directory per opzioni JVM aggiuntive.
├── log4j2.properties          # Configurazione logging di Elasticsearch.
├── role_mapping.yml           # Mappatura ruoli utenti.
├── roles.yml                  # Definizione dei ruoli RBAC.
├── users                      # File contenente gli utenti locali (realm `file`).
└── users_roles                # Associazione tra utenti e ruoli.
```

Elasticsearch è un motore di ricerca e analisi distribuito, progettato per archiviare grandi volumi di dati e permettere ricerche molto veloci e flessibili. In questo caso Elasticsearch raccoglie e indicizza i log per permettere analisi approfondite e visualizzazioni in tempo reale tramite Kibana. I dati, che arrivano in formato JSON da altri componenti, vengono indicizzati per essere rapidamente consultabili con query flessibili, ad esempio per event.code, host.name, @timestamp e altri campi.

Come spiegato in precedenza i log nella coda Redis ``redis-queue-elastic`` vengono consumati da Logstash, il quale li elabora e li invia a Elasticsearch per l’archiviazione e la ricerca dei log di sistema.

# Kibana

## Gerarchia directory (file configurazione di Kibana)

```
/etc/kibana/
     ├── certs/
     │   ├── ca.crt                 # Certificato della CA usato da Kibana per validare Elasticsearch.
     │   ├── kibana.crt             # Certificato pubblico usato da Kibana per TLS.
     │   └── kibana.key             # Chiave privata associata al certificato di Kibana.
     |
     ├── kibana.keystore           # File keystore per password e token sensibili.
     ├── kibana.yml                # File principale di configurazione di Kibana.
     └── node.options              # Opzioni del nodo Kibana (es. parametri Node.js).
```

Kibana è l’interfaccia grafica di Elasticsearch. Permette di visualizzare, esplorare e analizzare i dati archiviati su Elasticsearch tramite dashboard, grafici e strumenti interattivi (come Discover, Visualize, Dashboard, Alerting).
<!--
Kibana è utilizzato per:

- Visualizzare i log raccolti dai sistemi monitorati;
- filtrare eventi per codici o intervalli temporali;
- creare dashboard personalizzate per la sicurezza e l'analisi degli audit-log;
- configurare alert (tramite il modulo Watcher) per notificare condizioni anomale (es. tentativi di accesso sospetti).
-->
## Certificati SSL/TLS

Genera una Certificate Authority (CA) privata e crea certificati firmati per Elasticsearch e Kibana, necessari per abilitare la comunicazione sicura tramite TLS.
I certificati vengono poi copiati nelle rispettive cartelle di configurazione.

```bash
# Entra nella cartella dei certificati
mkdir -p /etc/elasticsearch/certs /etc/kibana/certs
cd /etc/elasticsearch/certs

# Crea la chiave privata della CA
openssl genrsa -out ca.key 4096

# Crea il certificato autofirmato della CA
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.crt \
  -subj "/C=IT/ST=Italy/L=Torino/O=AuditSecure/OU=IT/CN=ElasticCA"

# Crea chiave e richiesta CSR per Elasticsearch
openssl genrsa -out elasticsearch.key 2048
openssl req -new -key elasticsearch.key -out elasticsearch.csr \
  -subj "/C=IT/ST=Italy/L=Torino/O=AuditSecure/OU=IT/CN=elasticsearch"

# Firma il certificato per Elasticsearch
openssl x509 -req -in elasticsearch.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out elasticsearch.crt -days 365 -sha256

# Copia i certificati anche per Kibana
cp ca.crt /etc/kibana/certs/
cp /etc/elasticsearch/certs/elasticsearch.crt /etc/kibana/certs/kibana.crt
cp /etc/elasticsearch/certs/elasticsearch.key /etc/kibana/certs/kibana.key

```

### Permessi sicuri

Le seguenti istruzioni vengono utilizzate per assegnare i permessi corretti ai certificati TLS di Elasticsearch e Kibana, garantendo:

- che solo i rispettivi servizi possano accedere alle proprie chiavi private;
- la protezione dei file sensibili da accessi non autorizzati;
- il corretto funzionamento dei servizi in ambiente TLS/HTTPS.

```bash
# Elasticsearch
chown elasticsearch:elasticsearch /etc/elasticsearch/certs/*
chmod 600 /etc/elasticsearch/certs/*.key
chmod 644 /etc/elasticsearch/certs/*.crt

# Kibana
chown kibana:kibana /etc/kibana/certs/*
chmod 600 /etc/kibana/certs/*.key
chmod 644 /etc/kibana/certs/*.crt
```

## elasticsearch.yml

Percorso: ```/etc/elasticsearch/elasticsearch.yml```

File di configurazione principale per il servizio elasticsearch.

```yaml
# ======================== Elasticsearch Configuration =========================
#
# NOTE: Elasticsearch comes with reasonable defaults for most settings.
#       Before you set out to tweak and tune the configuration, make sure you
#       understand what are you trying to accomplish and the consequences.
#
# The primary way of configuring a node is via this file. This template lists
# the most important settings you may want to configure for a production cluster.
#
# Please consult the documentation for further information on configuration options:
# https://www.elastic.co/guide/en/elasticsearch/reference/index.html
#
# ---------------------------------- Cluster -----------------------------------
#
# Use a descriptive name for your cluster:
#
cluster.name: my-audit-log
#
# ------------------------------------ Node ------------------------------------
#
# Use a descriptive name for the node:
#
node.name: vbox-node
#
# Add custom attributes to the node:
#
#node.attr.rack: r1
#
# ----------------------------------- Paths ------------------------------------
#
# Path to directory where to store the data (separate multiple locations by comma):
#
path.data: /var/lib/elasticsearch
#
# Path to log files:
#
path.logs: /var/log/elasticsearch
#
# ----------------------------------- Memory -----------------------------------
#
# Lock the memory on startup:
#
#bootstrap.memory_lock: true
#
# Make sure that the heap size is set to about half the memory available
# on the system and that the owner of the process is allowed to use this
# limit.
#
# Elasticsearch performs poorly when the system is swapping the memory.
#
# ---------------------------------- Network -----------------------------------
#
# By default Elasticsearch is only accessible on localhost. Set a different
# address here to expose this node on the network:
#
network.host: 192.168.56.10
#
# By default Elasticsearch listens for HTTP traffic on the first free port it
# finds starting at 9200. Set a specific HTTP port here:
#
http.port: 9200
#
# For more information, consult the network module documentation.
#
# --------------------------------- Discovery ----------------------------------
#
# Pass an initial list of hosts to perform discovery when this node is started:
# The default list of hosts is ["127.0.0.1", "[::1]"]
#
discovery.type: single-node
#
#discovery.seed_hosts: ["host1", "host2"]
#
# Bootstrap the cluster using an initial set of master-eligible nodes:
#
#cluster.initial_master_nodes: ["node-1", "node-2"]
#
# For more information, consult the discovery and cluster formation module documentation.
#
# ---------------------------------- Various -----------------------------------
#
# Require explicit names when deleting indices:
#
#action.destructive_requires_name: true
#
# ---------------------------------- Security ----------------------------------
#
#                                 *** WARNING ***
#
# Elasticsearch security features are not enabled by default.
# These features are free, but require configuration changes to enable them.
# This means that users don't have to provide credentials and can get full access
# to the cluster. Network connections are also not encrypted.
#
# To protect your data, we strongly encourage you to enable the Elasticsearch security features. 
# Refer to the following documentation for instructions.
#
# https://www.elastic.co/guide/en/elasticsearch/reference/7.16/configuring-stack-security.html

xpack.security.enabled: true

xpack.security.http.ssl.enabled: true
xpack.security.http.ssl.key: /etc/elasticsearch/certs/elasticsearch.key
xpack.security.http.ssl.certificate: /etc/elasticsearch/certs/elasticsearch.crt
xpack.security.http.ssl.certificate_authorities: [ "/etc/elasticsearch/certs/ca.crt" ]

```

## kibana.yml

Percorso: ```/etc/kibana/kibana.yml```

File di configurazione principale per il servizio kibana.

```yaml
server.port: 5601

server.host: "192.168.56.10"

elasticsearch.hosts: ["https://192.168.56.10:9200"]

elasticsearch.username: ""
elasticsearch.password: ""

server.ssl.enabled: true
server.ssl.certificate: /etc/kibana/certs/kibana.crt
server.ssl.key: /etc/kibana/certs/kibana.key

elasticsearch.ssl.certificateAuthorities: ["/etc/kibana/certs/ca.crt"]

elasticsearch.ssl.verificationMode: certificate

```

## Avvio e abilitazione

Questi comandi vanno eseguiti dopo la configurazione dei file .service, delle directory e dei certificati, per assicurare che i servizi si avviino correttamente e in modo persistente.

```bash
# Ricarica completamente il processo systemd (utile dopo aggiornamenti di systemd stesso)
systemctl daemon-reexec

# Rilegge i file di configurazione delle unità systemd (necessario dopo modifiche a file .service)
systemctl daemon-reload

# Abilita Elasticsearch all'avvio automatico del sistema
systemctl enable elasticsearch

# Avvia immediatamente il servizio Elasticsearch
systemctl start elasticsearch

# Abilita Kibana all'avvio automatico del sistema
systemctl enable kibana

# Avvia immediatamente il servizio Kibana
systemctl start kibana

```

## Verifica e funzionamento

### Elasticsearch

Per verificare che Elasticsearch sia correttamente avviato e accessibile in HTTPS con autenticazione:

1. Aprire il browser e accedere all'indirizzo ``https://192.168.56.10:9200``;
2. Inserire le credenziali di autenticazione (username e password) quando richiesto;
3. Se tutto è configurato correttamente (TLS e certificati), il servizio risponde con un JSON simile al seguente, che conferma l’avvio del nodo e le informazioni sul cluster:

```html
name	"vbox-node"
cluster_name	"my-audit-log"
cluster_uuid	"eNKo8m_4Ra6YkKBC7Kx-Ag"
version	
  number	"7.17.29"
  build_flavor	"default"
  build_type	"deb"
  build_hash	"580aff1a0064ce4c93293aaab6fcc55e22c10d1c"
  build_date	"2025-06-19T01:37:57.847711500Z"
  build_snapshot	false
  lucene_version	"8.11.3"
  minimum_wire_compatibility_version	"6.8.0"
  minimum_index_compatibility_version	"6.0.0-beta1"
tagline	"You Know, for Search"

```


### Kibana

1. Aprire il browser e accedere all'indirizzo ``https://192.168.56.10:5601``;
2. Inserire le credenziali di autenticazione (username e password) quando richiesto;
3. Se tutto è configurato correttamente (TLS e certificati), sarà possibile visualizzare dashboard, log e strumenti di analisi collegati a Elasticsearch.

## Visualizzazione dashboard

## Dashboard Discover

La dashboard Discover di Kibana consente di esplorare i dati indicizzati in Elasticsearch in tempo reale. È lo strumento principale per visualizzare i log e i documenti ricevuti, ordinati cronologicamente. Attraverso l’interfaccia è possibile effettuare ricerche, applicare filtri e analizzare i dati tramite query personalizzate. Ogni documento può essere visualizzato sia in formato JSON che in forma tabellare, facilitando l'ispezione delle singole voci. Discover è particolarmente utile per il monitoraggio, la verifica dei log in ingresso e per individuare rapidamente eventi rilevanti.

Di seguito, un esempio reale dell’interfaccia Discover in uso:

<div align="center" style="border:1px solid #ccc; padding:10px; display: inline-block;"> 
  <img src="https://github.com/user-attachments/assets/a9aaa176-db37-4f84-aa42-147515be21e0" alt="image" /> 
</div>

## Dashboard custom: : Analisi eventi di audit Windows

La dashboard è stata realizzata per fornire una panoramica dettagliata e immediatamente leggibile degli eventi di sicurezza raccolti dai log di audit di Windows.

## Tabella generale degli eventi
La parte superiore della dashboard mostra una tabella dinamica in cui ogni riga rappresenta un evento di audit. Le colonne visualizzano informazioni fondamentali per l’analisi e la tracciabilità degli eventi:

- Host IP: indirizzo IP del sistema sorgente.
- Host ID: identificativo univoco della macchina che ha generato il log.
- Computer Name: nome host configurato sulla macchina Windows.
- Event Code: codice identificativo dell’evento Windows.
- Event Action: tipo di azione registrata (es. Success, Failure, ecc.).
- Message Event: descrizione testuale dettagliata dell’evento.

<div align="center" style="border:1px solid #ccc; padding:10px; display: inline-block;"> 
  <img src="https://github.com/user-attachments/assets/9d44f6b4-6096-4573-a31b-fb38fcd97ee5" alt="image" /> 
</div>

Questa tabella consente di monitorare in tempo reale cosa accade sui vari host della rete, rendendo immediata l’individuazione di accessi sospetti e anomali.

## Grafico a torta: distribuzione eventi
Successivamente è presente un grafico a torta (donut chart) che mostra la distribuzione percentuale degli Event ID raccolti. Questo permette di avere una visione aggregata su quali tipi di eventi si verificano più frequentemente e se vi sono anomalie (ad esempio, un numero elevato di login falliti o tentativi di accesso non autorizzati).

<div align="center" style="border:1px solid #ccc; padding:10px; display: inline-block;"> 
  <img src="https://github.com/user-attachments/assets/6448ae63-4761-4006-b38f-f5ce82c53f9e" alt="image" /> 
</div>

## Tabella di descrizione Event ID
Di seguito è presente una tabella che associa ogni Event ID a una descrizione sintetica e, se noto, al relativo tipo di evento. Questa sezione è particolarmente utile per chi non conosce a memoria il significato dei codici evento di Windows, poiché consente una rapida identificazione del contesto.

<div align="center" style="border:1px solid #ccc; padding:10px; display: inline-block;"> 
  <img src="https://github.com/user-attachments/assets/363044c5-7698-48d6-9819-bc4feb7f9571" alt="image" /> 
</div>

## Istogramma eventi più frequenti
Infine, la dashboard presenta un grafico a barre che mostra i Top Event ID ricevuti nel tempo. Questo consente di evidenziare con immediatezza quali eventi sono più ricorrenti e quindi meritano attenzione, per esempio un picco improvviso di Event ID legati a tentativi di accesso non autorizzati.

<div align="center" style="border:1px solid #ccc; padding:10px; display: inline-block;"> 
  <img src="https://github.com/user-attachments/assets/b781ec87-9e7b-4fff-9661-284938012a91" alt="image" /> 
</div>

La dashboard è pensata per offrire uno strumento di controllo centralizzato e immediatamente fruibile anche da chi non è esperto di analisi log. È utile sia per il monitoraggio costante che per analisi forensi su eventi passati. Grazie alla categorizzazione e visualizzazione intuitiva dei dati, ogni componente può essere utilizzato in fase investigativa, operativa o preventiva.

---

# Mappa IP/Porte dei Moduli di Logging

| **Modulo**                      | **IP**           | **Porta/e**                       | **Protocollo**     | **Note**                                                                 |
|---------------------------------|------------------|-----------------------------------|---------------------|--------------------------------------------------------------------------|
| **Winlogbeat**                  | 192.168.56.2     | 5044                              | TCP                 | Invia log a Logstash tramite il modulo Beats                            |
| **Logstash**                    | 192.168.56.10    | 5044 (input), 6379 (output)       | TCP, Beats          | Riceve i log da Winlogbeat e li duplica in due code Redis distinte      |
| **Redis (coda per Elasticsearch)** | 192.168.56.10 | 6379                              | TCP, RESP           | Coda letta da Logstash per inviare i log a Elasticsearch                |
| **Redis (coda per immudb)**        | 192.168.56.10 | 6379                              | TCP, RESP           | Coda duplicata per immudb (chiave o DB separato)                        |
| **Elasticsearch**               | 192.168.56.10    | 9200 (REST API), 9300 (transport) | HTTPS/TCP/TLS       | Espone l’API REST e comunica tra nodi tramite protocollo interno        |
| **Kibana**                      | 192.168.56.10    | 5601                              | HTTPS/TCP/TLS       | Interfaccia grafica per interrogare Elasticsearch                       |
| **immudb**                      | 192.168.56.10    | 3322 (default), 9497 (gRPC API)   | TCP/gRPC            | Legge i log dalla coda Redis per la storicizzazione immutabile          |

---
# Configurazione dei servizi con systemd

Per orchestrare l'intero sistema di raccolta, archiviazione e visualizzazione dei log, vengono utilizzate diverse unità systemd che automatizzano e gestiscono l'esecuzione periodica degli script e il database immutabile immuDB.

## queue_consumer.service

Percorso: ```/etc/systemd/system/queue_consumer.service```

Servizio associato allo script ```queue_consumer.py```. Viene eseguito periodicamente per la lettura e il consumo continuo dei log dalla coda ```redis-queue-immudb```, con successiva scrittura su immuDB.

⚠️ Assicurarsi che venv sia correttamente creato nella nuova directory ```/home/vboxuser/my-venv```.

```bash
[Unit]
Description=Servizio queue_consumer Python con virtualenv
After=network.target

[Service]
Type=simple
User=vboxuser
WorkingDirectory=/var/consumer-immudb
ExecStart=/home/vboxuser/my-venv/bin/python /var/consumer-immudb/queue_consumer.py
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target

```

## redis.service

Percorso: ```/etc/systemd/system/redis.service```

Servizio systemd che esegue il demone redis-server utilizzando il file di configurazione ```/etc/redis/redis.conf```, con tipo notify per integrazione corretta con systemd.
Include meccanismi di sicurezza avanzati (isolamento delle risorse, restrizioni di privilegio, protezione del filesystem) e supporto al riavvio automatico.

```bash
[Unit]
Description=Advanced key-value store
After=network.target
Documentation=http://redis.io/documentation, man:redis-server(1)

[Service]
Type=notify
ExecStart=/usr/bin/redis-server /etc/redis/redis.conf
TimeoutStopSec=0
Restart=always
User=redis
Group=redis
RuntimeDirectory=redis
RuntimeDirectoryMode=2755
UMask=007
PrivateTmp=yes
LimitNOFILE=65535
PrivateDevices=yes
ProtectHome=yes
ReadOnlyDirectories=/
ReadWriteDirectories=-/var/lib/redis
ReadWriteDirectories=-/var/log/redis
ReadWriteDirectories=-/run/redis
NoNewPrivileges=true
CapabilityBoundingSet=CAP_SYS_RESOURCE
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
MemoryDenyWriteExecute=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictNamespaces=true
ProtectSystem=true
ReadWriteDirectories=-/etc/redis

[Install]
WantedBy=multi-user.target
Alias=redis.service

```

## immudb.service

Percorso: ```/etc/systemd/system/immudb.service```

Servizio systemd che avvia il demone immudb, il database immutabile dove vengono scritti i log. Configurato tramite il file TOML specificato nel percorso ```/etc/immudb/immudb.toml```.

```bash
[Unit]
Description=immudb immutable database
After=network.target

[Service]
ExecStart=/usr/local/bin/immudb --config /etc/immudb/immudb.toml
Restart=on-failure
User=immudb
Group=immudb
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=immudb

[Install]
WantedBy=multi-user.target

```

## logstash.service

Percorso: ```/etc/systemd/system/logstash.service ```

Servizio systemd che avvia il demone Logstash con configurazione in ```/etc/logstash```, eseguito con privilegi limitati dall’utente e gruppo logstash. Garantisce il riavvio automatico in caso di fallimento, imposta priorità CPU bassa (nice=19) e un limite massimo di file aperti pari a 16384 per gestire grandi carichi di lavoro.

```bash
[Unit]
Description=logstash

[Service]
Type=simple
User=logstash
Group=logstash
EnvironmentFile=-/etc/default/logstash
EnvironmentFile=-/etc/sysconfig/logstash
ExecStart=/usr/share/logstash/bin/logstash "--path.settings" "/etc/logstash"
Restart=always
WorkingDirectory=/
Nice=19
LimitNOFILE=16384
TimeoutStopSec=infinity

[Install]
WantedBy=multi-user.target

```

## kibana.service

Percorso: ```/etc/systemd/system/kibana.service ```

Servizio systemd che avvia il demone Kibana con configurazione in ```/etc/kibana```, fornisce l’interfaccia web per visualizzare, analizzare e interrogare i dati presenti in Elasticsearch. Questo file systemd definisce l'avvio automatico di Kibana come processo in background, configurandone utente, percorso di esecuzione, variabili d’ambiente e log. È essenziale per rendere Kibana disponibile agli utenti tramite browser.

```bash
[Unit]
Description=Kibana
Documentation=https://www.elastic.co
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=kibana
Group=kibana
Environment=KBN_HOME=/usr/share/kibana
Environment=KBN_PATH_CONF=/etc/kibana
EnvironmentFile=-/etc/default/kibana
EnvironmentFile=-/etc/sysconfig/kibana
ExecStart=/usr/share/kibana/bin/kibana --logging.dest="/var/log/kibana/kibana.log" --pid.file="/run/kibana/kibana.pid" --deprecation.skip_d>
Restart=on-failure
RestartSec=3
StartLimitBurst=3
StartLimitInterval=60
WorkingDirectory=/usr/share/kibana
StandardOutput=journal
StandardError=inherit

[Install]
WantedBy=multi-user.target

```

## elasticsearch.service

Percorso: ```/lib/systemd/system/elasticsearch.service```

Servizio systemd che gestisce l'avvio del demone Elasticsearch, utilizzando il binario systemd-entrypoint, che supporta le notifiche a systemd (Type=notify) per un'integrazione corretta con il sistema di init.

La configurazione principale del servizio si trova in ```/etc/elasticsearch```. Il servizio viene eseguito con l'utente dedicato elasticsearch per motivi di sicurezza e isolamento dei privilegi.

Sono definiti limiti di sistema elevati (come LimitNOFILE=65535, LimitNPROC=4096, memoria e file illimitati) per garantire performance e stabilità. L'avvio del nodo può richiedere tempo: systemd è configurato per attendere fino a 900 secondi (TimeoutStartSec=900) prima di considerarlo fallito.

I log iniziali vengono inviati a journalctl tramite StandardOutput=journal, ma Elasticsearch mantiene anche i propri file di log in ```/var/log/elasticsearch```.

```bash
[Unit]
Description=Elasticsearch
Documentation=https://www.elastic.co
Wants=network-online.target
After=network-online.target

[Service]
Type=notify
RuntimeDirectory=elasticsearch
PrivateTmp=true
Environment=ES_HOME=/usr/share/elasticsearch
Environment=ES_PATH_CONF=/etc/elasticsearch
Environment=PID_DIR=/var/run/elasticsearch
Environment=ES_SD_NOTIFY=true
EnvironmentFile=-/etc/default/elasticsearch
WorkingDirectory=/usr/share/elasticsearch
User=elasticsearch
Group=elasticsearch
ExecStart=/usr/share/elasticsearch/bin/systemd-entrypoint -p ${PID_DIR}/elasticsearch.pid --quiet
StandardOutput=journal
StandardError=inherit
LimitNOFILE=65535
LimitNPROC=4096
LimitAS=infinity
LimitFSIZE=infinity
TimeoutStopSec=0
KillSignal=SIGTERM
KillMode=process
SendSIGKILL=no
SuccessExitStatus=143
TimeoutStartSec=900

[Install]
WantedBy=multi-user.target

```
---
# Debug
Per monitorare il corretto funzionamento dei servizi, è possibile consultare i log nei seguenti percorsi o comandi:

immudb : ``` DEVO TROVARE IL PERSO, NON MEE LO RICORDOOOOH``` nononononnoo

elasticsearch: ```/var/log/elasticsearch/elasticsearch.log```

redis: ```/var/log/redis/redis-server.log```

logstash: ```/var/log/logstash/logstash-plain.log```




run-logs : modalità dinamica journalctl -u run-logs.service -f | modalità statica /var/log/logtrace/run-logs.log

uvicorn-api : modalità dinamica journalctl -u uvicorn-api.service -f | modalità statica /var/log/logtrace/uvicorn-api.log







