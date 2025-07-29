# Analisi dati 

## Introduzione
In questa sezione viene descritto il processo di verifica dell’invio e della corretta ricezione dei dati reali estratti dai file di log esportati, per consentire un’analisi precisa e affidabile su informazioni significative.

In particolare, vengono analizzati:

• **Security_log_DC33.evtx**, contenente eventi di sicurezza registrati tra il `14-07-2025` e il `15-07-2025`;

• **System_log_DC33.evtx**, contenente eventi di sistema registrati tra il `05-05-2025` e il `15-07-2025`.

⚠️ Si precisa che in questa sezione **non verrà descritto nuovamente il funzionamento complessivo del sistema di raccolta e gestione dei log**, in quanto già trattato nella prima parte del file **README.md**.
È quindi assunto che il processo **end-to-end** — dall’acquisizione tramite **Winlogbeat**, al trasferimento verso **Logstash**, alla duplicazione su **code Redis** (`redis-queue-immudb` e `redis-queue-elastic`), alla **consumazione dei log** verso **immudb**, nonché **l’indicizzazione e visualizzazione tramite Elasticsearch e Kibana** — è correttamente configurato e operativo.

## Invio log da file .evtx a Logstash con Winlogbeat
L’esempio mostra come Winlogbeat invii i file `.evtx` a Logstash su `192.168.56.10:5044`, permettendo di verificare la corretta ricezione degli eventi.

L’esempio mostra il processo mediante il quale Winlogbeat invia i file `.evtx` a Logstash, in ascolto all’indirizzo `192.168.56.10:5044`. Questo permette di verificare la corretta ricezione degli eventi di log e, successivamente, di effettuare un’analisi dettagliata e dei dati acquisiti, utilizzando sia l’interfaccia grafica di Elasticsearch sia script appositamente sviluppati.

## Configurazione Winlogbeat (`winlogbeat_security.yml`)

File di configurazione per l’invio dei log di audit di sicurezza.

```yaml
evtx_path: &evtx_path "C:\\Users\\vboxuser\\Desktop\\Security_log_DC33.evtx"

winlogbeat.event_logs:
  - name: *evtx_path
    no_more_events: stop

output.logstash:
  hosts: ["192.168.56.10:5044"]

logging.level: info
```

## Configurazione Winlogbeat (`winlogbeat_system.yml`)

File di configurazione per l’invio dei log di audit di sistema.

```yaml
evtx_path: &evtx_path "C:\\Users\\vboxuser\\Desktop\\Sistem_log_DC33.evtx"

winlogbeat.event_logs:
  - name: *evtx_path
    no_more_events: stop

output.logstash:
  hosts: ["192.168.56.10:5044"]

logging.level: info
```
• `evtx_path`: percorso del file .evtx esportato da Windows.

• `no_more_events: stop`: fa terminare Winlogbeat quando tutti gli eventi del file sono stati elaborati.

• `output.logstash`: indirizzo del nodo Logstash destinatario.

## Esecuzione
Da powershell, nella cartella Winlogbeat:

```powershell
PS C:\WINDOWS\system32> cd "$env:USERPROFILE\Desktop\Winlogbeat_712x"

PS C:\WINDOWS\system32> cd Winlogbeat

PS C:\Users\vboxuser\Desktop\Winlogbeat_712x\Winlogbeat> .\winlogbeat.exe -e -c .\winlogbeat.yml -E EVTX_FILE="C:\Users\vboxuser\Desktop\Security_log_DC33.evtx"
```
• Winlogbeat legge il file di log `.evtx` specificato tramite l’opzione `-E EVTX_FILE`.

• I dati contenuti nel file vengono inviati a Logstash, come definito nella configurazione `winlogbeat_system.yml` e `winlogbeat_security.yml`.

• L'opzione `-e` abilita la stampa dei log su console.


## Risultato

Analizzando l'estratto del log in modalità INFO:

```powershell
2025-07-28T10:00:22.795+0200    INFO    [winlogbeat]    beater/eventlogger.go:124    Stop processing. {"id": "C:\\Users\\vboxuser\\Desktop\\Security_log_DC33.evtx"}
2025-07-28T10:00:22.843+0200    INFO    [monitoring]    log/log.go:192  Total metrics {"monitoring": {"metrics": {"beat":{"cpu":{"system":{"ticks":168125,"time":{"ms":168125}},"total":
{"ticks":246781,"time":{"ms":246781},"value":246781},"user":{"ticks":78656,"time":{"ms":78656}}},"handles":{"open":191},"info":{"ephemeral_id":"0ba24868-d932-4e62-a47a-
fcc527df985a","uptime":{"ms":423969},"version":"7.17.7"},"memstats":{"gc_next":26663464,"memory_alloc":19619952,"memory_sys":63246984,"memory_total":8963080976,"rss":62148608},"runtime":
{"goroutines":19}},"libbeat":{"config":{"module":{"running":0,"starts":0,"stops":0},"reloads":0,"scans":0},"output":{"events":
{"acked":185827,"active":0,"batches":336,"dropped":0,"duplicates":0,"failed":0,"toomany":0,"total":185827},"read":{"bytes":2022,"errors":0},"type":"logstash","write":
{"bytes":48944305,"errors":0}},"pipeline":{"clients":0,"events":{"active":0,"dropped":0,"failed":0,"filtered":0,"published":185827,"retry":200,"total":185827},"queue":
{"acked":185827,"max_events":4096}}},"system":{"cpu":{"cores":2}}}}}

2025-07-28T10:00:22.846+0200    INFO    [monitoring]    log/log.go:193  Uptime: 7m3.9965317s
2025-07-28T10:00:22.847+0200    INFO    [monitoring]    log/log.go:160  Stopping metrics logging.
2025-07-28T10:00:22.848+0200    INFO    instance/beat.go:461    winlogbeat stopped.
```
Si può verificare che Winlogbeat ha:

• letto tutti gli eventi dal file `Security_log_DC33.evtx`,

• inviato 185.827 eventi a Logstash (numero corrispondente esattamente agli eventi presenti nel file),

• terminato l'esecuzione senza errori.

La conferma che tutti gli eventi sono stati letti è evidenziata dalla riga:

```powershell
events":{"active":0,"dropped":0,"failed":0,"filtered":0,"published":185827,"retry":200,"total":185827}
```

La conferma del completamento della lettura è evidenziata dalla riga:

```powershell
Stop processing. {"id": "C:\\Users\\vboxuser\\Desktop\\Security_log_DC33.evtx"}
```

## Analisi

Dopo aver verificato in Elasticsearch la corretta ricezione e indicizzazione dei dati, si è proceduto con l’analisi dei log.

In primo luogo, sono stati analizzati i log relativi al file di sistema `Security_log_DC33.evtx`. Poiché gli eventi coprivano un periodo di circa **tre mesi**, i dati sono stati suddivisi per mese al fine di consentire una rappresentazione grafica più chiara e un’analisi temporale più efficace.

Un aspetto fondamentale dei log analizzati è la presenza di campi chiave associati a ciascun evento:

• **Livello**: indica la gravità o la natura dell’evento (Information, Verbose, Warning, Error and Critical).

• **Data e ora**: timestamp di quando si è verificato l’evento;

• **Origine**: il componente o il sistema che ha generato l’evento;

• **ID evento**: un identificativo univoco che rappresenta il tipo specifico di evento;

• **Categoria attività**: la classificazione funzionale dell’evento (ad esempio sicurezza, sistema, applicazione).

--

<div align="center" style="border:1px solid #ccc; padding:10px; display: inline-block;"> 
  <img width="665" height="110" alt="image" src="https://github.com/user-attachments/assets/138ef7f4-841b-4f31-a7cb-98791ac69740" />
</div>

--

Nel file `Security_log_DC33.evtx` sono presenti principalmente tre livelli di evento: 

• **Information**: Indica un evento normale e di successo, come l'avvio di un'applicazione o un accesso riuscito. Questo livello fornisce informazioni utili sullo stato del sistema e delle sue componenti, ma non indica necessariamente un problema.

• **Warning**: Indica un problema che potrebbe causare problemi futuri. Questo livello avvisa di situazioni che potrebbero portare a errori o malfunzionamenti se non corrette.

• **Error**: Indica un problema che impedisce il completamento di un'attività. Questo livello segnala un malfunzionamento che richiede attenzione e può portare a conseguenze più gravi se non risolto.







