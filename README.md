# Sistema di monitoraggio Audit Logs
---
## Introduzione
Il sistema descritto si occupa dell'acquisizione automatica dei log di audit relativi agli accessi amministrativi ai sistemi Windows, con l'obiettivo di garantire tracciabilità, integrità e conformità alle normative vigenti in materia di sicurezza informatica.

Il processo viene realizzato attraverso una pipeline composta dai seguenti componenti:
- ```Winlogbeat```, installato su un'istanza Windows Server, è il servizio responsabile del recupero e dell'invio degli eventi log di audit raccolti da Event Viewer.
- ```Logstash```, in esecuzione su un sistema Debian, riceve i log da Winlogbeat processandoli e duplicandoli in due differenti code Redis.
- ```Redis```, funge da sistema di gestione delle code, permettendo la separazione dei flussi di log:
  - La **coda 0** (`redis-queue-elastic`) invia i log a **Elasticsearch** per l'indicizzazione e la visualizzazione tramite interfaccia front-end.
  - La **coda 1** (`redis-queue-immudb`)  è dedicata alla persistenza dei log in un database immutabile (immudb), progettato per garantire integrità, non ripudiabilità e conservazione a lungo termine. In questo contesto, è configurata una retention time pari a 1 giorno.

Questa architettura garantisce la duplicazione dei dati per scopi distinti: analisi e conservazione forense. 
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

# Comunicazione tra Windows Server e Ubuntu/Debian via VirtualBox

In questa prima parte si descrive come creare una rete locale tra due macchine virtuali (VM) usando **VirtualBox** con una rete **Host-Only**.

---

## Topologia di rete
+-------------------+---------------+----------------------------+
| Sistema Operativo |       IP      |           Ruolo            | 
|-------------------|---------------|----------------------------|
| Windows Server    | 192.168.56.2  | Sender (Winlogbeat)        |
| Ubuntu/Debian     | 192.168.56.10 | Receiver (Redis, Logstash) |
+-------------------+---------------+----------------------------+

---

## Configurazione VirtualBox

### Creazione e configurazione dell'adattatore Host-Only

#### 1. Aprire **VirtualBox** → `File` > `Host Network Manager`
#### 2. Cliccare su **Crea** per aggiungere un nuovo adattatore
#### 3. Configurazione:
   - **IP**: `192.168.56.1`
   - **Subnet Mask**: `255.255.255.0`
   - **DHCP**: disabilitato
#### 4. Assegnare l’adattatore come **Adattatore 2** alle VM:
   - Modalità: `Solo host (Host-Only)`
   - Nome: ad esempio `vboxnet0`

---

## Configurazione degli IP Statici

### Windows Server

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
   IPv4 Address. . . . . . . . . . . : 192.168.56.2    <--
   Subnet Mask . . . . . . . . . . . : 255.255.255.0   <--
   Default Gateway . . . . . . . . . :
```

---

## Configurazione interfacce di rete in `/etc/network/interfaces` (Ubuntu/Debian)

Se il sistema non utilizza Netplan (come accade spesso su Debian o alcune versioni legacy di Ubuntu), è possibile configurare le interfacce di rete modificando direttamente il file ```/etc/network/interfaces```.

### Aprire il file interfaces (descrive le interfacce di rete presenti nel sistema e definisce come devono essere attivate)

```bash
vboxuser@vbox:~$ sudo nano /etc/network/interfaces
```

### Modificare il file come segue, assicurandosi che i nomi delle interfacce (es. enp0s3, enp0s8) corrispondano a quelli presenti nel sistema

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
    address 192.168.56.10   <--
    netmask 255.255.255.0   <--
```

#### Verifica delle interfacce

```bash
vboxuser@vbox:~$ ip link
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000
    link/ether 08:00:27:e0:87:cc brd ff:ff:ff:ff:ff:ff
3: enp0s8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000   <--
    link/ether 08:00:27:9d:3a:10 brd ff:ff:ff:ff:ff:ff
```

### Applicare le modifiche

```bash
vboxuser@vbox:~$ sudo systemctl restart networking
```

#### Se necessario utilizzare il seguente comando (o in alternativa riavviare la macchina virtuale)

```bash
vboxuser@vbox:~$ sudo ifdown enp0s8 && sudo ifup enp0s8
```

### Verificare che l'indirizzo sia stato applicato correttamente

```bash
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
    inet 192.168.56.10/24 brd 192.168.56.255 scope global enp0s8   <--
       valid_lft forever preferred_lft forever
    inet6 fe80::a00:27ff:fe9d:3a10/64 scope link 
       valid_lft forever preferred_lft forever
```
---

## Creare regola firewall per permettere il ping da Debian a Windows Server

E' necessario creare una regola per Windows Server, perchè il firewall (di Windows) blocca di default i pacchetti ICMP Echo Request (ping) in ingresso. 
### Passaggi per creare la regola firewall su Windows:

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

## Verifica finale

### Ping da Debian a Windows Server

```bash
vboxuser@vbox:~$ ping -c 192.168.56.2
PING 192.168.56.2 (192.168.56.2) 56(84) bytes of data.
64 bytes from 192.168.56.2: icmp_seq=1 ttl=128 time=6.43 ms
64 bytes from 192.168.56.2: icmp_seq=2 ttl=128 time=1.18 ms
64 bytes from 192.168.56.2: icmp_seq=3 ttl=128 time=1.16 ms

--- 192.168.56.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms   <--
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

## Overview

Winlogbeat è un lightweight shipper, ovvero un piccolo agente software, il quale raccoglie e invia i Windows Event Log verso endpoint **Redis**, **Logstash** ed **Elasticsearch**.

### Azioni Winlogbeat

1. **Monitoraggio del Registro Eventi**: legge in tempo reale eventi da log come `Security`, `System`, `Application`, `ForwardedEvents`, e altri.
2. **Filtraggio intelligente**: raccoglie solo specifici `event_id`, provider o livelli, riducendo il rumore.
3. **Spedizione dei log**: inoltra i dati verso Redis, Logstash ed Elasticsearch.
4. **Supporto ECS**: normalizza i dati secondo l’Elastic Common Schema.
5. **Dashboard Kibana integrate**: fornisce visualizzazioni pronte all’uso.

---

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
├── kibana/
│   └── 7/
│       ├── dashboard/
│       ├── search/
│       └── visualization/
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

---

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

---

## Installazione come Servizio Windows

```powershell
cd C:\\Winlogbeat
.\install-service-winlogbeat.ps1
Start-Service winlogbeat
Set-Service -Name winlogbeat -StartupType Automatic
```

### Disinstallazione

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

## Sicurezza

- Proteggi il file `winlogbeat.yml`.
- Limita accesso a Redis/Logstash.
- Esegui come `SYSTEM`.

---

# Logstash

Logstash è una pipeline open source utilizzata per  la gestion, elaborazione e inoltro in tempo reale di dati provenienti da diverse fonti verso una o più destinazioni.

Nel contesto di questa infrastruttura, Logstash riceve eventi in formato JSON da Winlogbeat, li processa e infine invia i dati in output a due code Redis distinte, permettendo la duplicazione del flusso: 
- una prima coda destinata all’ingestione in Elasticsearch per analisi;
- una seconda coda per la storicizzazione in immuDB.

---

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

---

## logstash.conf

Percorso: ```/etc/logstash/conf.d/logstash.conf```

Snippet Logstash impostato per ricevere i log da ```Winlogbeat``` (via Beats protocol sulla porta 5044) e per la duplicazione dei log su due code Redis.

```yaml
# Input: riceve dati da Winlogbeat tramite protocollo Beats sulla porta 5044
input {
    beats {
    port => 5044
  }
}

# Filter: qui puoi aggiungere regole per elaborare o filtrare i dati prima dell’output
filter {
  # Inserisci qui eventuali filtri o parsing (ad esempio, grok, mutate, ecc.)
}

# Output: invia i dati processati verso due code Redis diverse (duplicazione)
output {
# Primo output: manda i dati alla coda Redis "redis-queue-elastic"
  redis {
    host => "192.168.56.10"
    port => 6379
    password => ""
    key => "redis-queue-elastic"
    data_type => "list"
    db => 0
  }

  # Secondo output: manda gli stessi dati alla coda Redis "redis-queue-immudb"
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

### logstash1.conf

Percorso: ```/etc/logstash/conf.d/logstash1.conf```

Pipeline Logstash per leggere da ```Redis``` e inviare ad ```Elasticsearch```.

```yaml
input {
        redis {
                # Indirizzo del server Redis dove leggere la coda
                host => "192.168.56.10"

                # Tipo struttura dati usata in Redis: lista
                data_type => "list"

                # Porta del server Redis: 6379 è quella di default
                port => 6379

                # Key Redis: nome lista Redis da cui Logstash legge i dati
                key => "redis-queue-elastic"

                # PSW key Redis
                password => ""

                # Codec usato per decodificare i dati ricevuti da Redis: formato JSON, quindi Logstash li trasforma automaticamente in oggetti leggibili e filtrabili
                codec => json
        }
}

filter {
        #Qui è possibile inserire eventuali filtri per elaborare o arricchire i dati ricevuti prima di inviarli ad Elastic,
        #Ad esempio: parsing, timestamp, normalizzazione dei campi, aggiunta di tag, ...
}

output {
        elasticsearch {
                        # Indirizzo del cluster Elasticsearch (modifica in base all'ambiente che si utilizza)
                        hosts => ["http://192.168.56.10:9200"]

                        # Nome dell'indice su Elasticsearch. Viene usata una data dinamica per indicizzazione giornaliera
                        index => "from-redis-%{+YYYY.MM.dd}"

                        # Autenticazione Elasticsearch
                        #user => ""
                        #password => ""
        }
        stdout{
                codec => rubydebug
        }
}
```

---
## logstash.yml

Percorso: ```/etc/logstash/logstash.yml```

File di configurazione principale di Logstash che definisce le impostazioni globali del sistema: contiene solo la configurazione che specifica la directory di archiviazione dei dati interni di Logstash. Le restanti impostazioni sono lasciate ai valori predefiniti di Logstash.

```yaml                                                     
# ------------ Data path ------------
# Which directory should be used by logstash and its plugins
#for any persistent needs. Defaults to LOGSTASH_HOME/data
#
path.data: /var/lib/logstash
#
```

---
## pipelines.yml

Percorso: ```/etc/logstash/pipelines.yml```

Definizione delle due pipeline distinte per Logstash
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

Verificare che i log siano stati inseriti correttamente nelle due code Redis tramite ```LLEN```:

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
    ├── immudb.toml
```

## immudb.toml

Percorso: ```/etc/immudb/immudb.toml```

File di configurazione principale per il servizio immudb.

```yaml
# Porta, directory dei dati, autenticazione

address = "0.0.0.0"
admin-password = 'xxx'
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
```
Nel file di configurazione ```immudb.toml```, sono specificati i path fondamentali per il funzionamento del database: ```**/var/lib/immudb**``` è la directory principale dei dati che contiene:

- I database configurati ed utilizzati (```defaultdb``` e ```logs_immudb```).
- Le strutture immutabili dei dati (Merkle tree, indici, log transazionali).

```
/var/lib/immudb
         ├── defaultdb
         ├── logs_immudb           --> db usato per immutabilità logs registrati
         ├── immudb.identifier
         ├── immudb.pid            --> contiene il Process ID (PID) del processo immudb attualmente in esecuzione
         ├── immulog
                   ├──immudb.log
         ├── systemdb
```


Il file ```immudb-log``` contiene tutte le informazioni di esecuzione del server immudb: 
- path utilizzati (dati, log, configurazione, PID),
- stato del servizio;
- connessioni;
- operazioni di scrittura e lettura;
- eventuali errori;
- debug/monitoraggio del sistema.

## Login

```bash
vboxuser@vbox:~$ immuadmin login inerisci_tuo_username
Password: inserisci_la_tua_password
logged in
```

## Creazione di un nuovo database con retention time period = 24h 

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

Script che consuma la coda ```redis-queue-immudb``` e inserisce i log in immuDB (successivamente diventerà un servizio).

Lo script ```redis_queue_consumer_to_immudb.py``` legge i log dalla redis-queue-immudb per poi inserirli in una tabella relazionale all’interno di immuDB. Il funzionamento si basa su un ciclo continuo che, in modalità bloccante, attende messaggi JSON dalla coda Redis. Ogni log ricevuto viene validato, serializzato in modo deterministico (ordinando le chiavi del JSON) e sottoposto ad hashing tramite l’algoritmo ```SHA-256```. Il risultato di questo hash viene utilizzato come chiave primaria (log_key) nella tabella logs, dove viene salvata anche la rappresentazione testuale del log (value). La persistenza avviene tramite le funzionalità SQL di immudb, non nel modello chiave-valore. Questo approccio garantisce l'integrità dei dati, evita duplicazioni e sfrutta le proprietà immutabili di immudb per assicurare la non alterabilità dei log una volta scritti.

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
                                                          ...
                                                          ...
                                                          ...
                                                          ...
                                                          ...
```

## Visualizzazione in immuDB

```bash
+--------------------------------------------------------------------+------------------------------------------------------------+
|                           (key.value)                              |                         (logs.value)                       |    
+--------------------------------------------------------------------+------------------------------------------------------------+
|                                                                    | "{"@timestamp": "2025-06-18 15:45:36,854.089Z",            |    
|                                                                    | "@version": "1", "agent": {"ephemeral_id":                 |    
|                                                                    | "70d8b8eb-8915-459e-badf-05c9118e73c6", "hostname":        |     
|                                                                    | "WIN-S", "id": "c156a342-40dc-47ca-977a-f100ebd8e89f",     |     
|                                                                    | "name": "WIN-S", "type": "winlogbeat", "version":          |     
| "149cf3c7024285a6539433d1f84b17411f0527b67da963ddf4b421e5ee2c540c" | "7.17.7"}, "ecs": {"version": "1.12.0"},                   |     
|                                                                    | "event": {"action": "Logon", "code": "4624",               |     
|                                                                    | "created": "2025-06-17T12:02:18.364Z", "kind":             |     
|                                                                    | "event", "outcome": "success", "provider":                 |     
|                                                                    | "Microsoft-Windows-Security-Auditing"}, "host":            |     
|                                                                    |                          ...                               |     
|                                                                    |                          ...                               |     
|                                                                    |                          ...                               |     
+--------------------------------------------------------------------+------------------------------------------------------------+
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
# Configurazione dei servizi con systemd

Per orchestrare l'intero sistema di raccolta, archiviazione e visualizzazione dei log, vengono utilizzate diverse unità systemd che automatizzano e gestiscono l'esecuzione periodica degli script E il database immutabile immuDB.

## queue_consumer.service

Percorso: ```/etc/systemd/system/queue_consumer.service```

Servizio associato allo script ```queue_consumer.py```. Viene eseguito periodicamente per la lettura e il consumo continuo dei log dalla coda ```redis-queue-immudb```, con successiva scrittura su immuDB.

```
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

```
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

# redis-server can write to its own config file when in cluster mode so we
# permit writing there by default. If you are not using this feature, it is
# recommended that you replace the following lines with "ProtectSystem=full".
ProtectSystem=true
ReadWriteDirectories=-/etc/redis

[Install]
WantedBy=multi-user.target
Alias=redis.service
```


















