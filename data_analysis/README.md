# Analisi dati 

## Introduzione
In questa sezione viene illustrato il processo di verifica del corretto invio e della ricezione dei dati significativi provenienti da file di log esportati. 

In particolare, vengono utilizzati:

• **Security_log_DC33.evtx**, contenente eventi di sicurezza registrati tra il 14-07-2025 alle 22:43:58 e il 15-07-2025 alle 10:12:49;

• **System_log_DC33.evtx**, contenente eventi di sistema registrati tra il 05-05-2025 e il 15-07-2025.

L’esempio mostra come Winlogbeat invii i file `.evtx` a Logstash su `192.168.56.10:5044`, permettendo di verificare la corretta ricezione degli eventi.

⚠️ Si precisa che in questa sezione **non verrà descritto nuovamente il funzionamento complessivo del sistema di raccolta e gestione dei log**, in quanto già trattato nella prima parte del file **README.md**.
È quindi assunto che il processo **end-to-end** — dall’acquisizione tramite **Winlogbeat**, al trasferimento verso **Logstash**, alla duplicazione su **code Redis** (`redis-queue-immudb` e `redis-queue-elastic`), alla **consumazione dei log** verso **immudb**, nonché **l’indicizzazione e visualizzazione tramite Logstash, Elasticsearch e Kibana** — sia correttamente configurato e operativo.

Di conseguenza, questa sezione si concentra esclusivamente sull’**analisi statistica** dei dati estratti dai file `.evtx`. In particolare, vengono esaminati aspetti quali la **frequenza** e la **distribuzione percentuale** degli eventi, la **classificazione dei log** per livello (*Information, Warning, Error*), la **catalogazione per tipologia e ID d'evento** e la rappresentazione grafica dei risultati, per fornire una visione chiara e immediata dei dati contenuti nei log esportati.

## Invio log da file .evtx a Logstash con Winlogbeat

## Configurazione Winlogbeat (`winlogbeat_security.yml`)

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
Da povershell, nella cartella Winlogbeat:

```powershell
PS C:\WINDOWS\system32> cd "$env:USERPROFILE\Desktop\Winlogbeat_712x"

PS C:\WINDOWS\system32> cd Winlogbeat

PS C:\Users\vboxuser\Desktop\Winlogbeat_712x\Winlogbeat> .\winlogbeat.exe -e -c .\winlogbeat.yml -E EVTX_FILE="C:\Users\vboxuser\Desktop\Security_log_DC33.evtx"
```
• L'opzione `-e` abilita la stampa dei log su console.

• `-E EVTX_FILE=...` consente di forzare il percorso del file `.evtx`.

## Risultato

Analizzando l'estratto del log di INFO:
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
E' possibile verificare che Winlogbeat ha:

• letto tutti gli eventi dal file `Security_log_DC33.evtx`,

• inviato 185.827 eventi a Logstash (questo è corretto proprio perchè il file `Security_log_DC33.evtx` conteneva esattamente 185.827 logs),

• terminato l'esecuzione senza errori.

La conferma della lettura di tutti i logs è evidenziata dalla riga:
```powershell
events":{"active":0,"dropped":0,"failed":0,"filtered":0,"published":185827,"retry":200,"total":185827}
```

La conferma del completamento è evidenziata dalla riga:
```powershell
Stop processing. {"id": "C:\\Users\\vboxuser\\Desktop\\Security_log_DC33.evtx"}
```

## Analisi dei logs



