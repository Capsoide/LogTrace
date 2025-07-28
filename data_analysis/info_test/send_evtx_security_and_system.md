# Invio log Windows Security e System a Logstash con Winlogbeat

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
