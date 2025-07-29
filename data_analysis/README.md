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


### Risultato

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

##

<div align="center" style="border:1px solid #ccc; padding:30px; display: inline-block;"> 
  <img width="785" height="220" alt="image" src="https://github.com/user-attachments/assets/138ef7f4-841b-4f31-a7cb-98791ac69740" />
</div>

##

Nel file `Security_log_DC33.evtx` sono presenti principalmente tre livelli di evento: 

• **Information**: Indica un evento normale e di successo, come l'avvio di un'applicazione o un accesso riuscito. Questo livello fornisce informazioni utili sullo stato del sistema e delle sue componenti, ma non indica necessariamente un problema.

• **Warning**: Indica un problema che potrebbe causare problemi futuri. Questo livello avvisa di situazioni che potrebbero portare a errori o malfunzionamenti se non corrette.

• **Error**: Indica un problema che impedisce il completamento di un'attività. Questo livello segnala un malfunzionamento che richiede attenzione e può portare a conseguenze più gravi se non risolto.

## Catalogazione dei dati

L’analisi dei log di sistema è stata condotta seguendo una metodologia rigorosa basata sulla catalogazione dei dati, resa possibile attraverso l’utilizzo di script in PowerShell sviluppati per automatizzare il processo di estrazione, conteggio e organizzazione degli eventi, successivamente analizzati e rappresentati graficamente in Microsoft Excel.

## system_logs_journal_percentage.ps1

Percorso: `data_analysis/script_4_analysis/system_logs_journal_percentage.ps1`

``` powershell

# Installare il modulo ImportExcel con il comando: Install-Module -Name ImportExcel -Force


# Percorso del file di log .evtx da analizzare
$logFile = "C:\Users\vboxuser\Desktop\System_log_DC33.evtx"

# Intervallo temporale che segue il formato "YYYY-MM-DD"
$startDate = Get-Date "2025-05-05"
$endDate = (Get-Date "2025-05-31").AddDays(1).AddSeconds(-1) # Aggiungo 1 giorno e sottraggo 1 secondo alla data di fine per includere tutto il giorno finale

# Percorso del file Excel di output
$outputXlsx = "C:\Users\vboxuser\Desktop\percentuali_eventi.xlsx"

# Array per accumulare i dati da esportare
$excelData = @()  

# Carica tutti gli eventi dal file EVTX e filtra solo quelli compresi nell'intervallo di date
$eventi = Get-WinEvent -Path $logFile | Where-Object {
    $_.TimeCreated -ge $startDate -and $_.TimeCreated -le $endDate
}

# Ciclo sui giorni dell'intervallo
for ($date = $startDate.Date; $date -le $endDate.Date; $date = $date.AddDays(1)) {
    # Estrae gli eventi della giornata corrente
    $giornoEventi = $eventi | Where-Object { $_.TimeCreated.Date -eq $date }

    # Se non ci sono eventi per quel giorno, passa al giorno successivo
    if ($giornoEventi.Count -eq 0) { continue }

    $totaleGiornaliero = $giornoEventi.Count	# Numero totale eventi della giornata

    # Conta eventi per livello (4=Information, 3=Warning, 2=Error)
    $conteggiLivello = @{
        Information = ($giornoEventi | Where-Object { $_.Level -eq 4 }).Count
        Warning     = ($giornoEventi | Where-Object { $_.Level -eq 3 }).Count
        Error       = ($giornoEventi | Where-Object { $_.Level -eq 2 }).Count
    }

    # Calcola le percentuali per ogni livello
    $percInformation = [math]::Round(($conteggiLivello.Information / $totaleGiornaliero) * 100, 2)
    $percWarning = [math]::Round(($conteggiLivello.Warning / $totaleGiornaliero) * 100, 2)
    $percError = [math]::Round(($conteggiLivello.Error / $totaleGiornaliero) * 100, 2)

    # Output
    Write-Host "n=== $($date.ToString("yyyy-MM-dd")) ==="
    Write-Host ("Information: {0} eventi ({1}%)" -f $conteggiLivello.Information, $percInformation)
    Write-Host ("Warning    : {0} eventi ({1}%)" -f $conteggiLivello.Warning, $percWarning)
    Write-Host ("Error      : {0} eventi ({1}%)" -f $conteggiLivello.Error, $percError)

    # Aggiungi i dati all'array per Excel
    $excelData += [PSCustomObject]@{
        Data                 = $date.ToString("yyyy-MM-dd")
        Totale_Eventi        = $totaleGiornaliero
        Information_Count    = $conteggiLivello.Information
        Information_Perc     = $percInformation
        Warning_Count        = $conteggiLivello.Warning
        Warning_Perc         = $percWarning
        Error_Count          = $conteggiLivello.Error
        Error_Perc           = $percError
    }
}

# Esporta in Excel
$excelData | Export-Excel -Path $outputXlsx -AutoSize -AutoFilter -BoldTopRow -FreezeTopRow

# Messaggio di fine generazione
Write-Host "nReport Excel salvato in: $outputXlsx"

```
Lo script analizza un file di log eventi Windows in formato .evtx filtrando gli eventi in un intervallo di date definito dall’utente (`$startDate` e `$endDate`). 

Per ogni giorno dell’intervallo: calcola il numero totale di eventi, determina la distribuzione per livello di severità (Information, Warning, Error), calcola le percentuali di ciascun livello rispetto al totale giornaliero.

I risultati vengono mostrati a video in forma tabellare e salvati in un report Excel (.xlsx) contenente, per ogni giorno, i conteggi e le percentuali di eventi per livello.

### Output

``` powershell
 === 2025-05-05 ===
 Information: 795 eventi (89,73%)
 Warning    :  41 eventi (4,63%)
 Error      :  50 eventi (5,64%)

  === 2025-05-06 ===
 Information: 769 eventi (89,52%)
 Warning    :  40 eventi (4,66%)
 Error      :  50 eventi (5,82%)

  === 2025-05-07 ===
 Information: 853 eventi (89,98%)
 Warning    :  41 eventi (4,32%)
 Error      :  54 eventi (5,70%)
            .
            .
            .
```

## system_logs_information_warning_error.ps1

Percorso: `data_analysis/script_4_analysis/system_logs_information_warning_error.ps1`

``` powershell

# Installare il modulo ImportExcel con il comando: Install-Module -Name ImportExcel -Force

# Percorso del file di log .evtx
$logFile = "C:\Users\vboxuser\Desktop\System_log_DC33.evtx"

# Intervallo temporale che segue il formato "YYYY-MM-DD"
$startDate = Get-Date "2025-05-05"
$endDate = (Get-Date "2025-05-31").AddDays(1).AddSeconds(-1) # Aggiungo 1 giorno e sottraggo 1 secondo alla data di fine per includere tutto il giorno finale

# Percorso del file Excel di output
$outputXlsx = "C:\Users\vboxuser\Desktop\report_eventi.xlsx"

# Array per accumulare i dati da esportare
$excelData = @()  

# Carica tutti gli eventi dal file EVTX e filtra solo quelli compresi nell'intervallo di date
$eventi = Get-WinEvent -Path $logFile | Where-Object {
    $_.TimeCreated -ge $startDate -and $_.TimeCreated -le $endDate
}

# Ciclo sui giorni dell'intervallo
for ($date = $startDate.Date; $date -le $endDate.Date; $date = $date.AddDays(1)) {
    # Estrae gli eventi della giornata corrente
    $giornoEventi = $eventi | Where-Object { $_.TimeCreated.Date -eq $date }

    # Se non ci sono eventi per quel giorno, passa al giorno successivo
    if ($giornoEventi.Count -eq 0) { continue }

    # Output intestazione con data corrente
    Write-Host "`n=== $($date.ToString("yyyy-MM-dd")) ==="

    # Livelli per ogni evento (4 = Information, 3 = Warning, 2 = Error)
    foreach ($level in @(4, 3, 2)) {
        switch ($level) {
            4 { $levelName = "Information" }
            3 { $levelName = "Warning" }
            2 { $levelName = "Error" }
        }

        # Filtra gli eventi del giorno corrente per livello
        $eventiPerLivello = $giornoEventi | Where-Object { $_.Level -eq $level }

        # Se non ci sono eventi di questo livello, stampa un messaggio e continua
        if ($eventiPerLivello.Count -eq 0) {
            Write-Host "${levelName}: Nessun evento"
            continue
        }

        # Raggruppa gli eventi per ID, contando le occorrenze, e ordina in base al numero di eventi in modo discendente
        $grouped = $eventiPerLivello | Group-Object Id | Sort-Object Count -Descending

        # Output 
        Write-Host "${levelName}:"
        foreach ($g in $grouped) {
            Write-Host ("  ID {0,-6} : {1,5}" -f $g.Name, $g.Count)

            # Aggiungi i dati all'array per Excel
            $excelData += [PSCustomObject]@{
                Data      = $date.ToString("yyyy-MM-dd") # Giorno dell'evento
                Livello   = $levelName                   # Livello (information, Warning, Error)
                EventID   = $g.Name                      # ID evento
                Conteggio = $g.Count                     # Occorrenze ID in un determinato giorno
            }
        }
    }
}

# Esporta in Excel
$excelData | Export-Excel -Path $outputXlsx -AutoSize -AutoFilter -BoldTopRow -FreezeTopRow

# Messaggio di fine generazione
Write-Host "`nReport Excel salvato in: $outputXlsx"
```

Lo script analizza un file di log eventi di Windows in formato .evtx, applicando un filtro su un intervallo di date definito dall’utente nel codice (`$startDate` e `$endDate`).  

Gli eventi filtrati vengono raggruppati per: giorno di occorrenza, livello (Information, Warning, Error), ID evento.

Per ciascun giorno nell’intervallo, lo script calcola il numero di occorrenze per ogni ID evento e produce un output a console strutturato per livello e salvati in un report Excel (.xlsx)

### Output
```powershell
 === 2025-07-01 ===
 Information:
   ID 7036   :   432
   ID 14554  :   363
   ID 33     :    10
   ...
 Warning:
   ID 140    :    39
   ID 50     :     5
   ...
 Error:
   ID 5805   :    12
   ID 5723   :    11
   ...
```

## Dati

I risultati, esportati in un report Excel, hanno costituito la base per successive analisi grafiche. Da tali dati sono stati prodotti schemi e rappresentazioni grafiche che hanno permesso di evidenziare l’andamento giornaliero degli eventi e di identificare eventuali anomalie o picchi significativi.

##

La tabella seguente riassume la distribuzione complessiva degli eventi estratti dal file di log analizzato, distinguendoli in base al livello di gravità. 

I dati rappresentano il totale degli eventi registrati nell’intero intervallo temporale considerato, compreso tra `2025-05-05` – `2025-07-15`.

|               | Information Level | Error Level | Warning Level |
|---------------|-------------------|-------------|---------------|
|Total Count    | 55345             | 4994        | 2186          |
|Total %        | 88,517%           | 7,987%      | 3,496         |

##

Dalla fase di elaborazione è emerso che:

• la maggior parte degli eventi appartiene al livello **Information**, con un totale di **55345** eventi, pari all' **88,517%** del totale;

• gli eventi di livello **Error** sono **4994**, pari al **7,987%** del totale;

• gli eventi di livello **Warning** sono **2186**, pari al  **3,496%** del totale.

##

Questa distribuzione evidenzia come la maggior parte dei log raccolti rappresenti informazioni di routine, con una percentuale relativamente contenuta di eventi che segnalano errori o condizioni potenzialmente problematiche.

<div align="center" style="border:1px solid #ccc; padding:30px; display: inline-block;"> 
  <img width="685" height="420" alt="image" src="https://github.com/user-attachments/assets/784b7167-1e2a-41a8-8cef-f1d7dc209a00" />
</div>

##








