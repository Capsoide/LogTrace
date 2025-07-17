# LogTrace: Sistema di monitoraggio Audit Logs Windows

## Introduzione
Questo sistema si occupa dell'acquisizione automatica dei log di audit relativi agli accessi amministrativi ai sistemi Windows. I log vengono archiviati in un database immutabile per garantirne l’integrità e resi consultabili tramite una dashboard interattiva, pensata per facilitare l’analisi e il monitoraggio delle attività.

Il processo viene realizzato attraverso una pipeline composta dai seguenti componenti:
- ```Winlogbeat```, installato su un'istanza Windows Server, è il servizio responsabile del recupero e dell'invio degli eventi log di audit raccolti da Event Viewer.
- ```Logstash```, in esecuzione su un sistema Debian, riceve i log da Winlogbeat processandoli e duplicandoli in due differenti code Redis.
- ```Redis```, in esecuzione su un sistema Debian, funge da sistema di gestione delle code, permettendo la separazione dei flussi di log:
  - La **coda 0** (`redis-queue-elastic`) invia i log a **Elasticsearch** per l'indicizzazione e la visualizzazione tramite interfaccia front-end.
  - La **coda 1** (`redis-queue-immudb`)  è dedicata alla persistenza dei log in un database immutabile (immudb), progettato per garantire integrità, non ripudiabilità e conservazione a lungo termine. In questo contesto, è configurata una retention time pari a 24 ore.

Questa architettura garantisce la duplicazione dei dati per scopi distinti come analisi e conservazione forense in modo tale da garantirne l'integrità e l'inalterabilità nel tempo. 
I singoli componenti svolgono i seguenti ruoli:

- `Winlogbeat`: acquisizione dei log da Event Viewer.
- `Logstash`: duplicazione dei flussi di log e invio alle rispettive code Redis.
- `Redis`: gestione dei buffer dei dati.
- `Immudb`: archiviazione sicura e immutabile dei log.
- `Elasticsearch`: indicizzazione e conservazione dei log. Fornisce il backend per l’analisi interattiva dei dati.
- `Kibana`: GUI per la ricerca, visualizzazione e monitoraggio dei log indicizzati.

L'intero sistema è progettato per soddisfare i requisiti normativi previsti dalle direttive **ACN**, **ISO/IEC 27001** e **NIS2**, che impongono il tracciamento, la conservazione e l’integrità dei log di sicurezza:

- [**ACN**](https://www.acn.gov.it/portale/nis/aggiornamento-informazioni) (Agenzia per la Cybersicurezza Nazionale) stabilisce standard per la sicurezza delle infrastrutture critiche italiane.
- [**ISO/IEC 27001**](https://edirama.org/wp-content/uploads/2023/10/document-1.pdf) è uno standard internazionale per la gestione della sicurezza delle informazioni (ISMS), che richiede la registrazione e l’analisi degli eventi di accesso.
- [**NIS2**](https://www.acn.gov.it/portale/nis) è la direttiva europea sulla sicurezza delle reti e dei sistemi informativi, che impone obblighi di logging, conservazione e risposta agli incidenti per gli operatori di servizi essenziali.


## Schema infrastruttura
<div align="center" style="border:1px solid #ccc; padding:10px; display: inline-block;"> 
  <img src="https://github.com/user-attachments/assets/35074374-ca95-4a12-97eb-0501cb1db141" alt="image" /> 
</div>



## Mappa Servizi e Interfacce di Rete LogTrace

| **Modulo**                      | **IP**           | **Porta/e**                       | **Protocollo**     | **Note**                                                                 |
|---------------------------------|------------------|-----------------------------------|---------------------|--------------------------------------------------------------------------|
| **Winlogbeat**                  | 192.168.56.2     | 5044                              | TCP                 | Invia log a Logstash tramite il modulo Beats                            |
| **Logstash**                    | 192.168.56.10    | 5044 (input), 6379 (output)       | TCP, Beats          | Riceve i log da Winlogbeat e li duplica in due code Redis distinte      |
| **Redis (coda per Elasticsearch)** | 192.168.56.10 | 6379                              | TCP, RESP           | Coda letta da Logstash per inviare i log a Elasticsearch                |
| **Redis (coda per immudb)**        | 192.168.56.10 | 6379                              | TCP, RESP           | Coda duplicata per immudb (chiave o DB separato)                        |
| **Elasticsearch**               | 192.168.56.10    | 9200 (REST API), 9300 (transport) | HTTPS/TCP/TLS       | Espone l’API REST e comunica tra nodi tramite protocollo interno        |
| **Kibana**                      | 192.168.56.10    | 5601                              | HTTPS/TCP/TLS       | Interfaccia grafica per interrogare Elasticsearch                       |
| **immudb**                      | 192.168.56.10    | 3322 (default), 9497 (gRPC API)   | TCP/gRPC            | Legge i log dalla coda Redis per la storicizzazione immutabile          |

## Comunicazione Windows Server → Debian 

In questa sezione viene illustrata la configurazione di una rete Host-Only in VirtualBox, utilizzata per stabilire la comunicazione diretta tra le due macchine virtuali: Windows Server (mittente dei log) e Debian (ricevente e processore dei log).

## Configurazione adattatore Host-Only (Virtualbox)

1. Aprire **VirtualBox** → `File` → `Host Network Manager`
   
2. Cliccare su **Crea** per aggiungere un nuovo adattatore
      
3. Configurazione:
   - **IP**: `192.168.56.1`
   - **Subnet Mask**: `255.255.255.0`
   - **DHCP**: disabilitato
     
4. Assegnare l’adattatore come `Adattatore 2` alle VM:
   - Modalità: `Host-Only`
   - Nome: ad esempio `vboxnet0`

## Configurazione IP Statici (Windows Server)

1. Aprire `Centro connessioni di rete` > Modificare `Impostazioni scheda`
   
2. Scegliere l’interfaccia collegata a `vboxnet0` (“Ethernet 2”)
   
3. Cliccare su `Proprietà` > `TCP/IPv4` e impostare:
   - **IP**: `192.168.56.2`
   - **Subnet mask**: `255.255.255.0`
   - **Gateway**: lascia vuoto
    
4. Verificare con ```ipconfig``` 

```powershell
C:\Users\vboxuser> ipconfig
Windows IP Configuration


Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . : xyz.lan
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

## Winlogbeat

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

## Logstash

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

## logstash.conf

Percorso: ```/etc/logstash/conf.d/logstash.conf```

File di configurazione definito per una pipeline Logstash che riceve i log da ``Winlogbeat`` (tramite protocollo Beats) e li duplica su due code Redis distinte.

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

File di configurazione impostato per leggere i log da ```Redis``` e inviarli ad ```Elasticsearch```.

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
## Redis

Redis è uno store chiave-valore in memoria, open source e ad alte prestazioni, usato  come sistema di **code distribuite** permettendo la separazione dei flussi di log. Grazie al supporto nativo per le liste (`LPUSH`, `RPUSH`, `LPOP`, `BRPOP`, `LLEN`, ecc.), Redis consente di implementare code `FIFO` semplici e veloci per la gestione asincrona di log, eventi o messaggi tra più componenti. È ideale come buffer temporaneo o broker leggero in architetture distribuite.

File di configurazione Redis: ```/etc/redis/redis.conf```

```
/etc/redis/
    ├── redis.conf
    └── redis.conf.save
```


## Accesso e verifica delle code Redis

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

## Immudb

L'archiviazione dei log è gestita tramite immuDB, un database immutabile progettato per garantire l'integrità dei dati.
I log vengono salvati con una struttura chiave:valore, in cui:

- **Chiave**: identificatore univoco del log
- **Valore**: contenuto JSON del log stesso

Questa struttura consente di:

- garantire l’integrità e la non modificabilità dei dati
- effettuare ricerche e recuperi rapidi attraverso il prefisso delle chiavi log


### Database utilizzati
Sono presenti due database distinti all'interno di immuDB:

- **defaultdb**: database di default utilizzato per testing

- **logs_immudb**: dedicato agli audit log

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

```
Nel file di configurazione ``immudb.toml``, sono specificati i path per il funzionamento del database: ``/var/lib/immudb`` è la directory principale dei dati che contiene:

- I database configurati ed utilizzati (``defaultdb`` e ``logs_immudb``).
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

## Lista database esistenti

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

## queue_consumer.py

Percorso: ``/var/consumer-immudb/queue_consumer.py``

## Descrizione

Lo script `queue_consumer.py` consuma la coda Redis `redis-queue-immudb`, estraendo in modalità bloccante messaggi di log in formato JSON e inserendoli nel database immudb tramite il metodo `key-value` (KV).

## Funzionamento

• I log vengono consumati dalla coda Redis in modalità bloccante tramite il comando `BLPOP`.

• Ogni log estratto è una stringa JSON che viene deserializzata in un oggetto dati.

• Il contenuto JSON viene riorganizzato con ordinamento delle chiavi per garantire coerenza nella serializzazione.

• Viene calcolato l’hash `SHA-256` del log, utilizzato come `chiave` per l’inserimento nel database.

• La chiave è costruita concatenando un prefisso, il `timestamp` corrente e l’`hash calcolato`.

• Il log viene memorizzato nel database immudb in modalità `key-value` (KV), con chiave e valore codificati in bytes.


## Funzioni principali

### Calcolo dell’hash SHA-256
```python
def hash_key(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()
```
Riceve in input una stringa `data`, la codifica in bytes e ne calcola l’hash SHA-256. Restituisce l’hash in formato esadecimale, usato per generare la chiave unica.

### Lettura bloccante da Redis e deserializzazione JSON

```python
item = r.blpop(REDIS_QUEUE_NAME, timeout=5)
if item:
    _, raw_log = item
    try:
        log_data = json.loads(raw_log)
    except json.JSONDecodeError:
        logging.warning(f"Log non valido JSON: {raw_log}")
        continue
```

Il comando `blpop` estrae un elemento dalla coda Redis in modalità bloccante con timeout di 5 secondi. Se riceve un elemento, prende il contenuto: `raw_log` e tenta di deserializzarlo in un oggetto Python: `log_data`. Se il JSON non è valido, lo ignora e continua.

### Serializzazione ordinata e generazione chiave

```python
log_str = json.dumps(log_data, sort_keys=True)
ts = int(time.time())
key = f"log:{ts}:{hash_key(log_str)}"
```
Il log viene serializzato in stringa JSON con chiavi ordinate (`sort_keys=True`) per assicurare coerenza. Viene preso il timestamp corrente in secondi e si costruisce la chiave unica concatenando un prefisso (`log:`), il `timestamp` e l’`hash SHA-256` del log serializzato.

### Inserimento nel database immudb in modalità KV

```python
immu.set(key.encode(), log_str.encode())
```

La coppia chiave-valore viene inserita nel database immudb usando il metodo `set`. Entrambi, chiave e valore, sono codificati in bytes come richiesto dal client immudb in modalità key-value.

## Debug

### Inserimento in immudb
```bash
Jul 15 08:55:50 vbox python[2449]: 2025-07-14 08:55:50,220 - INFO - [KV] Log inserito in immudb con chiave: log:1752488806:e721a405b4e0ee229b55b15b8c257d9e19a80d239355586888030beae6749267
```

### Get Key

```bash
immuclient get log:1752488806:e721a405b4e0ee229b55b15b8c257d9e19a80d239355586888030beae6749267
tx:       154
rev:      1
key:      log:1752488806:e721a405b4e0ee229b55b15b8c257d9e19a80d239355586888030beae6749267
value:    {"@timestamp": "2025-07-14T08:19:34.948Z", "@version": "1", "agent": {"ephemeral_id": "a1e0f7b5-dd55-4a58-b962-64d6a2b6808a", "hostname": "WIN-S", "id": "c156a342-40dc-47ca-977a-f100ebd8e89f", "name": "WIN-S", "type": "winlogbeat", "version": "7.17.7"}, "ecs": {"version": "1.12.0"}, "event": {"action": "File System", "code": "4658", "created": "2025-07-14T08:19:38.072Z", "kind": "event", "outcome": "success", "provider": "Microsoft-Windows-Security-Auditing"}, "host": {"architecture": "x86_64", "hostname": "WIN-S", "id": "01f96cfe-269f-4a90-9547-e093ff3f1e46", "ip": ["fd00::be82:30db:2cc8:18ab", "fe80::b789:33f2:febd:1d7", "10.0.2.15", "fe80::6894:81ba:3678:5341", "192.168.56.2"], "mac": ["08:00:27:97:5f:fb", "08:00:27:e8:bf:ff"], "name": "WIN-S", "os": {"build": "26100.1742", "family": "windows", "kernel": "10.0.26100.1742 (WinBuild.160101.0800)", "name": "Windows Server 2025 Datacenter Evaluation", "platform": "windows", "type": "windows", "version": "10.0"}}, "log": {"level": "information"}, "message": "The handle to an object was closed.\n\nSubject :\n\tSecurity ID:\t\tS-1-5-18\n\tAccount Name:\t\tWIN-S$\n\tAccount Domain:\t\tWORKGROUP\n\tLogon ID:\t\t0x3E7\n\nObject:\n\tObject Server:\t\tSecurity\n\tHandle ID:\t\t0x170\n\nProcess Information:\n\tProcess ID:\t\t0xec\n\tProcess Name:\t\tC:\\Windows\\WinSxS\\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.26100.1738_none_a5031b637767a4e7\\TiWorker.exe", "tags": ["beats_input_codec_plain_applied"], "winlog": {"api": "wineventlog", "channel": "Security", "computer_name": "WIN-S", "event_data": {"HandleId": "0x170", "ObjectServer": "Security", "ProcessId": "0xec", "ProcessName": "C:\\Windows\\WinSxS\\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.26100.1738_none_a5031b637767a4e7\\TiWorker.exe", "SubjectDomainName": "WORKGROUP", "SubjectLogonId": "0x3e7", "SubjectUserName": "WIN-S$", "SubjectUserSid": "S-1-5-18"}, "event_id": "4658", "keywords": ["Audit Success"], "opcode": "Info", "process": {"pid": 4, "thread": {"id": 884}}, "provider_guid": "{54849625-5478-4994-a5ba-3e3b0328c30d}", "provider_name": "Microsoft-Windows-Security-Auditing", "record_id": 6959975, "task": "File System"}}

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

## Retention period

È stata configurata una `retention period` di 24 ore sul database `logs_immudb`, al fine di eliminare automaticamente i dati più vecchi dalla value log, riducendo lo spazio su disco e garantendo una gestione efficiente e sicura dei log. La configurazione è stata effettuata nel momento della creazione del DB tramite il comando:

```bash
immuadmin database create logs_immudb \
  --retention-period=24h \
  --truncation-frequency=24h
```

Per verificare il corretto funzionamento della `retention period` sulla tabella `logs` del database `logs_immudb`, è possibile eseguire un `get` su una chiave precedentemente inserita. Se la chiave è stata rimossa automaticamente da immudb a causa della scadenza del periodo di retention, il comando restituirà un messaggio di assenza.
```bash
immuclient get 149cf3c7024285a6539433d1f84b17411f0527b67da963ddf4b421e5ee2c540c
immuclient tbtree: key not found
```
Questo conferma che la chiave non esiste più, perché è stata eliminata automaticamente dal sistema in base alla retention configurata.

## Gestione degli indici from-redis-* in Elasticsearch
In Elasticsearch, i dati di log vengono raccolti da Redis, tramite Logstash. Per gestire al meglio il volume elevato e continuo di log, i dati vengono organizzati in indici Elasticsearch separati in base al giorno di raccolta.

Ogni indice rappresenta quindi un “contenitore” isolato che raccoglie esclusivamente i documenti generati in una specifica data, con una nomenclatura strutturata secondo il pattern `from-redis-YYYY.MM.DD`. 
Questo approccio consente: 

• **Organizzazione temporale** dei dati, utile per ricerche e analisi su intervalli specifici.

• **Migliori performance**, grazie a indici più piccoli e gestibili.

• **Gestione della retention** semplificata, con la possibilità di eliminare interi indici obsoleti.

• **Scalabilità orizzontale**, evitando la crescita eccessiva di un singolo indice nel tempo.

• **Nomenclatura chiara**, che identifica l’origine dei dati (Redis) e facilita l’integrazione con strumenti di analisi, automazione e visualizzazione.

### Indici giornalieri `from-redis-YYYY.MM.DD`
I log raccolti da Redis vengono indicizzati in Elasticsearch tramite indici giornalieri, il cui nome segue il formato `from-redis-2025.07.11`, `from-redis-2025.07.10`, e così via.
Ciò significa che ogni giorno viene creato un nuovo indice che contiene tutti i log relativi a quella giornata.

È possibile cancellare dati storici eliminando interi indici, evitando la rimozione documento per documento.
Questo approccio garantisce un controllo granulare sul periodo di retention dei dati.

Il comando: 
```bash
curl -u username:password -k "https://192.168.56.10:9200/_cat/indices?v&s=index"
health status index                            uuid                   pri rep docs.count docs.deleted store.size pri.store.size
yellow open   from-redis-2025.07.01            ISqshOdJQTynHlVYOAB8xw   1   1       9451            0      4.4mb          4.4mb
yellow open   from-redis-2025.07.02            LQUa1aatTnS2RpjMZnzqKA   1   1      49649            0     24.1mb         24.1mb
yellow open   from-redis-2025.07.03            U1PF-URXSdeD98aso_3bGw   1   1        719            0   1000.5kb       1000.5kb
yellow open   from-redis-2025.07.10            3pJqrCOpTtaCj91inCiTow   1   1      66863            0     32.9mb         32.9mb
yellow open   from-redis-2025.07.11            SuODhIU2TPiLxHH2Rmd1nA   1   1      12992            0      7.1mb          7.1mb
```

### Rotazione e cancellazione automatica
Per gestire lo *storage* ed eliminare automaticamente gli indici obsoleti, è stato implementato uno script Bash che rimuove tutti gli indici `from-redis-*` più vecchi di 72 ore. Lo script calcola la data limite, la confronta con quella contenuta nel nome degli indici ed effettua la cancellazione tramite le `API REST` di Elasticsearch autenticandosi su connessione `HTTPS`.

Percorso script `/usr/local/bin/delete_old_from_redis_indices.sh`
```bash
#!/bin/bash

ES_HOST="https://192.168.56.10:9200"
ES_USER="user"
ES_PASS="password"

CUTOFF_DATE=$(date -d '3 days ago' +%Y-%m-%d)

echo "Rimuovo gli indici from-redis-* più vecchi di $CUTOFF_DATE"

INDICES=$(curl -s -u $ES_USER:$ES_PASS -k "$ES_HOST/_cat/indices/from-redis-*?h=index" | sort)

for INDEX in $INDICES; do
  #Conversione formato data da YYYY.MM.DD a YYYY-MM-DD
  IDX_DATE=$(echo $INDEX | sed -E 's/from-redis-([0-9]{4})\.([0-9]{2})\.([0-9]{2})/\1-\2-\3/')

  IDX_TS=$(date -d "$IDX_DATE" +%s 2>/dev/null)
  CUTOFF_TS=$(date -d "$CUTOFF_DATE" +%s)

  if [ -z "$IDX_TS" ]; then
    echo "Formato data non valido per indice $INDEX, salto."
    continue
  fi

  if [ $IDX_TS -lt $CUTOFF_TS ]; then
    echo "Elimino indice $INDEX (data: $IDX_DATE)"
    curl -u $ES_USER:$ES_PASS -X DELETE "$ES_HOST/$INDEX" -k
  else
    echo "Mantengo indice $INDEX (data: $IDX_DATE)"
  fi
done
```

### Test 
E' stato eseguito un primo test con retention di 24h, quindi in questo caso, gli indici piu vecchi del 2025-07-10 saranno rimossi:
```bash
root@vbox:~# sudo /usr/local/bin/delete_old_from_redis_indices.sh
Rimuovo gli indici from-redis-* più vecchi di 2025-07-10
{"acknowledged":true}Elimino indice from-redis-2025.07.01 (data: 2025-07-01)
{"acknowledged":true}Elimino indice from-redis-2025.07.02 (data: 2025-07-02)
{"acknowledged":true}Elimino indice from-redis-2025.07.03 (data: 2025-07-03)
{"acknowledged":true}Elimino indice from-redis-2025.07.10 (data: 2025-07-10)
{"acknowledged":false}Mantengo indice from-redis-2025.07.11 (data: 2025-07-11)
```
Come visibile, l'indice `from-redis-2025.07.11` non è stato cancellato perché è considerato corrente e non rientra tra quelli più vecchi della data di soglia impostata (2025-07-10).


È possibile effettuare un’ulteriore verifica elencando tutti gli indici disponibili dopo l’eliminazione:
```bash
root@vbox:~# curl -u username:password -k "https://192.168.56.10:9200/_cat/indices?v&s=index"
health status index                            uuid                   pri rep docs.count docs.deleted store.size pri.store.size
yellow open   from-redis-2025.07.11            SuODhIU2TPiLxHH2Rmd1nA   1   1      12992            0      7.1mb          7.1mb
```
Come visibile dall’output, gli indici sono stati eliminati correttamente, ad eccezione di `from-redis-2025.07.11`, che è stato mantenuto in quanto non rientra nei criteri di eliminazione (essendo relativo alla data corrente).

## Analisi Log e UX Grafica con Elasticsearch e Kibana

## Elasticsearch 

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

## Kibana

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

Generazione di una Certificate Authority (CA) privata e creazione di certificati firmati per Elasticsearch e Kibana, necessari per abilitare la comunicazione sicura tramite TLS.
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
cluster.name: my-audit-log
# ------------------------------------ Node ------------------------------------
node.name: vbox-node
# ----------------------------------- Paths ------------------------------------
path.data: /var/lib/elasticsearch
# Path to log files:
path.logs: /var/log/elasticsearch
# ---------------------------------- Network -----------------------------------
network.host: 192.168.56.10
http.port: 9200
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

## Visualizzazione Elasticsearch/Kibana

### Elasticsearch
Per una consultazione semplice e interattiva dei log archiviati, il sistema espone i dati tramite **Elasticsearch**, che vengono interrogati e visualizzati tramite **Kibana**.

Per verificare che Elasticsearch sia correttamente avviato e accessibile in **HTTPS** con autenticazione:

1. Aprire il browser e accedere all'indirizzo `https://192.168.56.10:9200`.
2. Inserire le credenziali di autenticazione.
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
Per una consultazione semplice e interattiva dei log archiviati, il sistema utilizza **Kibana** come interfaccia di visualizzazione, collegata direttamente a **Elasticsearch**. 

1. Aprire il browser e accedere all'indirizzo `https://192.168.56.10:5601/login?next=%2F`.
2. Inserire le credenziali di autenticazione.
3. Se tutto è configurato correttamente (TLS e certificati), sarà possibile visualizzare dashboard, log e strumenti di analisi collegati a Elasticsearch.
<!--  
## Visualizzazione dashboard

## Dashboard Discover

La dashboard Discover di Kibana consente di esplorare i dati indicizzati in Elasticsearch in tempo reale. È lo strumento principale per visualizzare i log e i documenti ricevuti, ordinati cronologicamente. Attraverso l’interfaccia è possibile effettuare ricerche, applicare filtri e analizzare i dati tramite query personalizzate. Ogni documento può essere visualizzato sia in formato JSON che in forma tabellare, facilitando l'ispezione delle singole voci. Discover è particolarmente utile per il monitoraggio, la verifica dei log in ingresso e per individuare rapidamente eventi rilevanti.

Di seguito, un esempio reale dell’interfaccia Discover in uso:

<div align="center" style="border:1px solid #ccc; padding:10px; display: inline-block;"> 
  <img src="https://github.com/user-attachments/assets/a9aaa176-db37-4f84-aa42-147515be21e0" alt="image" /> 
</div>

## Dashboard custom

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
-->
## Kibana Dashboard Export via Elasticsearch Query
Query **HTTP GET** che utilizza la Search API di Elasticsearch per estrarre la dashboard personalizzata con il titolo "Audit-Logs" dall’indice `.kibana`. La ricerca filtra i documenti di tipo `dashboard` e seleziona quelli il cui titolo corrisponde esattamente al valore specificato. Questo metodo consente di esportare la configurazione della dashboard per backup o migrazione.

```bash
GET .kibana/_search
{
  "query":{
    "bool": {
      "must": [
        { "term": { "type": "dashboard"} },
        { "match_phrase": { "dashboard.title": "Audit-Logs"} }
      ]
    }
  },
  "size": 1
}
```

## Configurazione dei servizi con systemd

Per orchestrare l'intero sistema di raccolta, archiviazione e visualizzazione dei log, vengono impiegate unità systemd che automatizzano l'esecuzione degli script, la gestione del database immutabile immuDB e dei componenti di visualizzazione.

## redis.service

Percorso: `/etc/systemd/system/redis.service`

Servizio systemd che gestisce l'avvio di `redis-server` utilizzando il file di configurazione `/etc/redis/redis.conf`, con tipo notify per integrazione corretta con systemd.
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

Percorso: `/etc/systemd/system/immudb.service`

Servizio systemd che gestisce l'avvio di `immudb`, il database immutabile dove vengono scritti i log. Configurato tramite il file TOML specificato nel percorso `/etc/immudb/immudb.toml`.

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

Percorso: `/etc/systemd/system/logstash.service `

Servizio systemd che gestisce l'avvio di `Logstash` con configurazione in `/etc/logstash`, eseguito con privilegi limitati dall’utente e gruppo logstash. Garantisce il riavvio automatico in caso di fallimento, imposta priorità CPU bassa (nice=19) e un limite massimo di file aperti pari a 16384 per gestire grandi carichi di lavoro.

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

## elasticsearch.service

Percorso: `/lib/systemd/system/elasticsearch.service`

Servizio systemd che gestisce l'avvio di `Elasticsearch`, utilizzando il binario systemd-entrypoint, che supporta le notifiche a systemd (Type=notify) per un'integrazione corretta con il sistema di init.

La configurazione principale del servizio si trova in `/etc/elasticsearch`. Il servizio viene eseguito con l'utente dedicato elasticsearch per motivi di sicurezza e isolamento dei privilegi.

Sono definiti limiti di sistema elevati (come LimitNOFILE=65535, LimitNPROC=4096, memoria e file illimitati) per garantire performance e stabilità. L'avvio del nodo può richiedere tempo: systemd è configurato per attendere fino a 900 secondi (TimeoutStartSec=900) prima di considerarlo fallito.

I log iniziali vengono inviati a journalctl tramite StandardOutput=journal, ma Elasticsearch mantiene anche i propri file di log in `/var/log/elasticsearch`.

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

## kibana.service

Percorso: `/etc/systemd/system/kibana.service `

Servizio systemd che gestisce l'avvio di `Kibana` con configurazione in `/etc/kibana`, fornisce l’interfaccia web per visualizzare, analizzare e interrogare i dati presenti in Elasticsearch. Questo file systemd definisce l'avvio automatico di Kibana come processo in background, configurandone utente, percorso di esecuzione, variabili d’ambiente e log. È essenziale per rendere Kibana disponibile agli utenti tramite browser.

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

## queue_consumer.service

Percorso: `/etc/systemd/system/queue_consumer.service`

Servizio systemd associato allo script `queue_consumer.py`. Viene eseguito periodicamente per la lettura e il consumo continuo dei log dalla coda `redis-queue-immudb`, con successiva scrittura su immuDB.

⚠️ Assicurarsi che venv sia correttamente creato nella nuova directory `/home/vboxuser/my-venv`.

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

## delete-old-redis.service
Percorso: `/etc/systemd/system/delete-old-redis.service`

Servizio systemd associato allo script `delete_old_from_redis_indices.sh` ,che ha il compito di eliminare automaticamente gli indici Elasticsearch che corrispondono al pattern `from-redis-*` e che risultano più vecchi di 24 ore.

```bash
 [Unit]
Description=Elimina gli indici from-redis-* più vecchi di una certa data (impostato a 72h)
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/delete_old_from_redis_indices.sh
User=root

[Install]
WantedBy=multi-user.target
```

## Debug
Per monitorare il corretto funzionamento dei servizi, è possibile consultare i log nei seguenti percorsi o comandi:

• **redis**: modalità statica ``/var/log/redis/redis-server.log`` |  modalità dinamica ``journalctl -u redis-server.service -f``

• **immudb**: modalità statica ``/var/lib/immudb/immulog/immudb.log`` |  modalità dinamica ``journalctl -u immudb.service -f``

• **logstash**: modalità statica ``/var/log/logstash/logstash-plain.log`` |  modalità dinamica ``journalctl -u logstash.service -f``

• **elasticsearch**: modalità statica ``/var/log/elasticsearch/elasticsearch.log`` |  modalità dinamica ``journalctl -u elasticsearch.service -f``

• **kibana**: modalità statica ``/var/log/kibana/kibana.log`` |  modalità dinamica ``journalctl -u kibana.service -f``

• **queue_consumer.service**: modalità dinamica ``journalctl -u queue_consumer.service -f``

• **delete-old-redis.service**: modalità dinamica ``journalctl -u delete-old-redis.service -f``













