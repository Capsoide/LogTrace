# Invio log da un file .evtx a Logstash con Winlogbeat

Questo esempio mostra come inviare i log dei file **Security_log_DC33.evtx** e **System_log_DC33.evtx** di Windows a **Logstash** utilizzando **Winlogbeat**.  
In particolare, Winlogbeat legge i file `.evtx` esportati e li invia all'istanza Logstash in ascolto su `192.168.56.10:5044`.

L'obiettivo è verificare la corretta configurazione, il corretto invio e la corretta ricezione di tutti gli eventi contenuti nei file `.evtx`.

---

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
PS C:\Users\vboxuser\Desktop\Winlogbeat_712x\Winlogbeat> .\winlogbeat.exe -e -c .\winlogbeat.yml -E EVTX_FILE="C:\Users\vboxuser\Desktop\Security_log_DC33.evtx"
```
• L'opzione `-e` abilita la stampa dei log su console.

• `-E EVTX_FILE=...` consente di forzare il percorso del file `.evtx`.

## Risultato

Analizzando l'estratto del log di INFO:
```powershell
2025-07-28T10:00:22.795+0200    INFO    [winlogbeat]    beater/eventlogger.go:124    Stop processing. {"id": "C:\\Users\\vboxuser\\Desktop\\Security_log_DC33.evtx"}
2025-07-28T10:00:22.843+0200    INFO    [monitoring]    log/log.go:192  Total metrics {"monitoring": {"metrics": {"beat":{"cpu":{"system":{"ticks":168125,"time":{"ms":168125}},"total":{"ticks":246781,"time":{"ms":246781},"value":246781},"user":{"ticks":78656,"time":{"ms":78656}}},"handles":{"open":191},"info":{"ephemeral_id":"0ba24868-d932-4e62-a47a-fcc527df985a","uptime":{"ms":423969},"version":"7.17.7"},"memstats":{"gc_next":26663464,"memory_alloc":19619952,"memory_sys":63246984,"memory_total":8963080976,"rss":62148608},"runtime":{"goroutines":19}},"libbeat":{"config":{"module":{"running":0,"starts":0,"stops":0},"reloads":0,"scans":0},"output":{"events":{"acked":185827,"active":0,"batches":336,"dropped":0,"duplicates":0,"failed":0,"toomany":0,"total":185827},"read":{"bytes":2022,"errors":0},"type":"logstash","write":{"bytes":48944305,"errors":0}},"pipeline":{"clients":0,"events":{"active":0,"dropped":0,"failed":0,"filtered":0,"published":185827,"retry":200,"total":185827},"queue":{"acked":185827,"max_events":4096}}},"system":{"cpu":{"cores":2}}}}}
2025-07-28T10:00:22.846+0200    INFO    [monitoring]    log/log.go:193  Uptime: 7m3.9965317s
2025-07-28T10:00:22.847+0200    INFO    [monitoring]    log/log.go:160  Stopping metrics logging.
2025-07-28T10:00:22.848+0200    INFO    instance/beat.go:461    winlogbeat stopped.
```
E' possibile verificare che Winlobeat ha:
• letto tutti gli eventi dal file `Security_log_DC33.evtx`,

• inviato 185.827 eventi a Logstash (questo è corretto proprio perchè il file `Security_log_DC33.evtx` conteneva esattamente 185.827 logs),

• terminato l'esecuzione senza errori.

La conferma del completamente è evidenziata dalla riga:
```powershell
Stop processing. {"id": "C:\\Users\\vboxuser\\Desktop\\Security_log_DC33.evtx"}

```
