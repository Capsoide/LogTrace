# Interpretazione dei log: System_log_DC33.evtx e Security_log_DC33.evtx

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

# Analisi dati

## Introduzione

Questa sezione è dedicata all’analisi di due file di log generati da un sistema Windows: `System_log_DC33.evtx`, che raccoglie i log di sistema, e `Security_log_DC33.evtx`, che contiene i log di sicurezza.

I **log di sistema** raccolgono informazioni relative al funzionamento generale del sistema operativo e dei componenti hardware e software. Tali log documentano eventi come l’avvio e l’arresto dei servizi, errori critici, warning e altre notifiche emesse dai driver o dal kernel. Sono fondamentali per **diagnosticare malfunzionamenti** e **monitorare la stabilità del sistema**.

I **log di sicurezza**, invece, registrano eventi relativi alla sicurezza informatica, come i tentativi di accesso (riusciti o falliti), le modifiche ai privilegi utente, le operazioni di accesso ai file protetti, le policy applicate e le attività legate all’autenticazione. Questi log sono cruciali per il **rilevamento di comportamenti sospetti**, per la **verifica della conformità** e per **l’analisi forense**.

Per favorire una lettura più immediata e una maggiore efficacia interpretativa, i dati analizzati saranno rappresentati graficamente mediante line plot, in orientamento sia verticale che orizzontale. Tali rappresentazioni consentono di evidenziare con chiarezza l’andamento temporale degli eventi, l’occorrenza di anomalie e la distribuzione dei fenomeni rilevati nei log.

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

# System Logs

Nel file `System_log_DC33.evtx` sono presenti principalmente tre livelli di evento: 

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

I risultati, prodotti sia come output in console sia in un report Excel generato tramite il modulo `ImportExcel`, hanno costituito la base per le analisi grafiche successive. Tali elaborazioni hanno consentito di rappresentare l’andamento giornaliero e mensile degli eventi, individuando possibili anomalie o picchi di attività.

##

I seguenti dati mostrano la distribuzione complessiva degli eventi estratti dal file di log analizzato, distinguendoli in base al **livello di gravità**. 

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

## Eventi giornalieri per categoria

Questa distribuzione evidenzia come la maggior parte dei log raccolti rappresenti informazioni di routine, con una percentuale relativamente contenuta di eventi che segnalano errori o condizioni potenzialmente problematiche.

<div align="center" style="border:1px solid #ccc; padding:30px; display: inline-block;"> 
  <img width="685" height="420" alt="image" src="https://github.com/user-attachments/assets/784b7167-1e2a-41a8-8cef-f1d7dc209a00" />
</div>

##

## Report mensili

### Maggio

I dati riportano le occorrenze giornaliere degli eventi di sistema, distinti per livello di gravità (Information, Warning, Error), corredati dalla percentuale relativa rispetto al totale degli eventi registrati per ciascuna giornata nel periodo considerato, dal `05/05/2025` al `05/31/2025`.

| Data       | Totale Eventi | Information Count | Information %  | Warning Count | Warning %  | Error Count | Error %  |
|------------|---------------|-------------------|----------------|---------------|------------|-------------|----------|
| 05/05/2025 | 886           | 795               | 89,73%         | 41            | 4,63%      | 50          | 5,64%    |
| 06/05/2025 | 859           | 769               | 89,52%         | 40            | 4,66%      | 50          | 5,82%    |
| 07/05/2025 | 948           | 853               | 89,98%         | 41            | 4,32%      | 54          | 5,70%    |
| 08/05/2025 | 892           | 776               | 87,00%         | 46            | 5,15%      | 70          | 7,85%    |
| 09/05/2025 | 814           | 720               | 88,45%         | 2             | 0,25%      | 92          | 11,30%   |
| 10/05/2025 | 665           | 561               | 84,36%         | 0             | -          | 104         | 15,64%   |
| 11/05/2025 | 703           | 598               | 85,07%         | 1             | 0,14%      | 104         | 14,79%   |
| 12/05/2025 | 895           | 804               | 89,84%         | 2             | 0,22%      | 89          | 9,94%    |
| 13/05/2025 | 993           | 810               | 81,57%         | 82            | 8,26%      | 101         | 10,17%   |
| 14/05/2025 | 974           | 856               | 87,89%         | 42            | 4,31%      | 76          | 7,80%    |
| 15/05/2025 | 1138          | 944               | 82,95%         | 42            | 3,69%      | 152         | 13,36%   |
| 16/05/2025 | 992           | 882               | 88,91%         | 41            | 4,13%      | 69          | 6,96%    |
| 17/05/2025 | 772           | 691               | 89,51%         | 1             | 0,13%      | 80          | 10,36%   |
| 18/05/2025 | 748           | 672               | 89,84%         | 0             | -          | 76          | 10,16%   |
| 19/05/2025 | 976           | 854               | 87,50%         | 47            | 4,82%      | 75          | 7,68%    |
| 20/05/2025 | 1039          | 925               | 89,02%         | 41            | 3,95%      | 73          | 7,03%    |
| 21/05/2025 | 1004          | 876               | 87,26%         | 40            | 3,98%      | 88          | 8,76%    |
| 22/05/2025 | 1016          | 867               | 85,33%         | 41            | 4,04%      | 108         | 10,63%   |
| 23/05/2025 | 901           | 755               | 83,80%         | 41            | 4,55%      | 105         | 11,65%   |
| 24/05/2025 | 843           | 732               | 86,83%         | 1             | 0,12%      | 110         | 13,05%   |
| 25/05/2025 | 726           | 621               | 85,53%         | 1             | 0,14%      | 104         | 14,33%   |
| 26/05/2025 | 1032          | 849               | 82,27%         | 78            | 7,56%      | 105         | 10,17%   |
| 27/05/2025 | 1061          | 915               | 86,24%         | 40            | 3,77%      | 106         | 9,99%    |
| 28/05/2025 | 1036          | 909               | 87,74%         | 40            | 3,86%      | 87          | 8,40%    |
| 29/05/2025 | 1040          | 909               | 87,40%         | 61            | 5,87%      | 70          | 6,73%    |
| 30/05/2025 | 1007          | 886               | 87,98%         | 48            | 4,77%      | 73          | 7,25%    |
| 31/05/2025 | 795           | 744               | 93,58%         | 1             | 0,13%      | 50          | 6,29%    |

##

<div align="center" style="border:1px solid #ccc; padding:30px; display: inline-block;"> 
  <img width="2209" height="999" alt="image" src="https://github.com/user-attachments/assets/e9de7a94-8514-4f46-a65b-a50e4c22eff9" />
</div>

##


Da questi dati si evince che:

• La maggior parte degli eventi registrati quotidianamente rientra nella categoria **Information**, con **percentuali generalmente comprese tra l'82% e il 94%**, indicando che **la maggior parte dei log sono di natura informativa e presumibilmente non critica**.

• Gli eventi di tipo **Warning** risultano **generalmente bassi**, spesso **sotto il 5%**, ma con **qualche picco significativo in alcune giornate** (ad esempio il 13/05/2025 e il 26/05/2025) dove superano il **10%**, segnalando possibili situazioni da monitorare.

• Gli eventi di tipo **Error** mostrano **percentuali variabili**, spesso **tra il 6% e il 16%**, con alcuni giorni (come il 10, 11, 15 e 25 maggio) in cui gli errori sono più rilevanti in termini relativi e assoluti, suggerendo la presenza di anomalie o problemi più seri in quei giorni.

In generale, il volume totale degli eventi giornalieri oscilla tra circa **700 e oltre 1100 al giorno**, senza un trend di crescita o decrescita costante, ma con variazioni che **potrebbero riflettere la normale attività del sistema o eventi specifici di rilievo**.


### Conteggio giornaliero degli eventi di sistema

Di seguito è mostrata una rappresentazione grafica dei conteggi giornalieri degli eventi di sistema raccolti durante il periodo di maggio 2025, realizzata con un grafico di tipo **plot line** su **scala logaritmica**. L’asse verticale indica il numero di occorrenze,  quello orizzontale rappresenta i singoli giorni del mese. Le linee corrispondono ai più ricorenti Event ID per ciascun tipo: 

• **Information**: `7036` e `14554`; 

• **Warning**: `150` e `50`; 

• **Error**: `1058`, `5805` e `5723`. 


##

<div align="center" style="border:1px solid #ccc; padding:30px; display: inline-block;"> 
  <img width="1512" height="676" alt="image" src="https://github.com/user-attachments/assets/67468d83-002e-423c-8697-05ee4c4c2f59" />
</div>

Le interruzioni nelle linee indicano i giorni in cui un determinato Event ID non è stato registrato, permettendo così di evidenziare chiaramente differenze di frequenza e variazioni nel tempo.

##

### Andamento

- Gli eventi di tipo **Information** (ID 7036 e 14554) sono i **più frequenti**, mediamente tra 250 e 450 eventi al giorno.

- Gli eventi di tipo **Warning** (ID 140 e 50) hanno un **andamento intermittente**:

  - Nei giorni: 9–12 maggio, 17–18 maggio, 24–25 maggio, 31 maggio, **non si registrano Warning**.

  - In altri giorni variano da 4 a 65 eventi, con picchi il 13/05 (65) e il 26/05 (62).

- Gli eventi di tipo **Error** (ID 1058, 5723, 5805) **mostrano oscillazioni**:

  - **ID 1058** (Group Policy processing error) è il **più frequente**, da 26 a 86 eventi al giorno, con picchi il 22/05 e 24/05 (86).

  - **ID 5723** (problemi di trust con il dominio) e **ID 5805** (machine account non trovato nel dominio) **sono costanti**, tipicamente 10–12 eventi/giorno.


Si osserva un **pattern evidente**, ovvero che nei giorni in cui mancano i Warning, come ad esempio dal 9 al 12 maggio e tra il 24 e il 25 maggio, si registra un aumento marcato degli Error 1058. Inoltre, in alcune giornate specifiche (13, 26 e 29 maggio) si manifestano picchi contemporanei sia di Warning sia di Errori, suggerendo la possibilità di disservizi o modifiche infrastrutturali.

### Giugno

I dati riportano le occorrenze giornaliere degli eventi di sistema, distinti per livello di gravità (Information, Warning, Error), corredati dalla percentuale relativa rispetto al totale degli eventi registrati per ciascuna giornata nel periodo considerato, dal `06/01/2025` al `06/30/2025`.

| Data       | Totale Eventi  | Information Count  | Information %  | Warning Count  | Warning %    | Error Count   | Error %    |
|------------|----------------|--------------------|----------------|----------------|--------------|---------------|------------|
| 01/06/2025 | 762            | 714                | 93,70%         | 1              | 0,13%        | 47            | 6,17%      |
| 02/06/2025 | 864            | 772                | 89,35%         | 41             | 4,75%        | 51            | 5,90%      |
| 03/06/2025 | 996            | 892                | 89,55%         | 41             | 4,12%        | 63            | 6,33%      |
| 04/06/2025 | 923            | 825                | 89,38%         | 40             | 4,33%        | 58            | 6,29%      |
| 05/06/2025 | 1028           | 908                | 88,33%         | 39             | 3,79%        | 81            | 7,88%      |
| 06/06/2025 | 1046           | 931                | 89,01%         | 40             | 3,82%        | 75            | 7,17%      |
| 07/06/2025 | 812            | 705                | 86,83%         | 1              | 0,12%        | 106           | 13,05%     |
| 08/06/2025 | 750            | 645                | 86,00%         | 0              | -            | 105           | 14,00%     |
| 09/06/2025 | 1008           | 858                | 85,12%         | 54             | 5,36%        | 96            | 9,52%      |
| 10/06/2025 | 958            | 809                | 84,45%         | 42             | 4,38%        | 107           | 11,17%     |
| 11/06/2025 | 921            | 782                | 84,91%         | 43             | 4,67%        | 96            | 10,42%     |
| 12/06/2025 | 852            | 725                | 85,09%         | 39             | 4,58%        | 88            | 10,33%     |
| 13/06/2025 | 943            | 798                | 84,62%         | 41             | 4,35%        | 104           | 11,03%     |
| 14/06/2025 | 744            | 639                | 85,89%         | 1              | 0,13%        | 104           | 13,98%     |
| 15/06/2025 | 714            | 603                | 84,45%         | 1              | 0,14%        | 110           | 15,41%     |
| 16/06/2025 | 932            | 815                | 87,45%         | 41             | 4,40%        | 76            | 8,15%      |
| 17/06/2025 | 906            | 783                | 86,42%         | 42             | 4,64%        | 81            | 8,94%      |
| 18/06/2025 | 872            | 743                | 85,21%         | 42             | 4,82%        | 87            | 9,97%      |
| 19/06/2025 | 962            | 738                | 76,72%         | 41             | 4,26%        | 183           | 19,02%     |
| 20/06/2025 | 902            | 775                | 85,92%         | 40             | 4,43%        | 87            | 9,65%      |
| 21/06/2025 | 727            | 646                | 88,86%         | 1              | 0,14%        | 80            | 11,00%     |
| 22/06/2025 | 695            | 616                | 88,64%         | 1              | 0,14%        | 78            | 11,22%     |
| 23/06/2025 | 923            | 811                | 87,87%         | 41             | 4,44%        | 71            | 7,69%      |
| 24/06/2025 | 926            | 820                | 88,55%         | 40             | 4,32%        | 66            | 7,13%      |
| 25/06/2025 | 904            | 796                | 88,05%         | 41             | 4,54%        | 67            | 7,41%      |
| 26/06/2025 | 887            | 770                | 86,81%         | 50             | 5,64%        | 67            | 7,55%      |
| 27/06/2025 | 804            | 739                | 91,92%         | 42             | 5,22%        | 23            | 2,86%      |
| 28/06/2025 | 592            | 571                | 96,45%         | 0              | -            | 21            | 3,55%      |
| 29/06/2025 | 693            | 669                | 96,54%         | 1              | 0,14%        | 23            | 3,32%      |
| 30/06/2025 | 847            | 781                | 92,21%         | 40             | 4,72%        | 26            | 3,07%      |


##

<div align="center" style="border:1px solid #ccc; padding:30px; display: inline-block;"> 
  <img width="2209" height="999" alt="image" src="https://github.com/user-attachments/assets/dbdbe513-3528-4b76-9fae-22f4f8d2282d" />
</div>

##


Da questi dati si evince che:

• La maggior parte degli eventi registrati quotidianamente rientra nella categoria **Information**, con **percentuali generalmente comprese tra l'85% e il 96%**, indicando che **la maggior parte dei log** **sono di natura informativa e presumibilmente non critica**.

• Gli eventi di tipo **Warning** risultano **generalmente bassi**, spesso al di sotto del **5%**, con alcune eccezioni che raggiungono o superano tale soglia (ad esempio il **09/06**, **26/06** e il **27/06**, dove si registrano rispettivamente **5,36%** ,**5,64%** e **5,22%**). In altri casi, come l’**08/06** o il **28/06**, non vengono segnalati warning rilevanti.

• Gli eventi di tipo **Error** mostrano una **variabilità più marcata**, oscillando generalmente tra il **6%** e il **15%**, con alcuni picchi evidenti:

  - **15/06**: 15,41% di errori;

  - **14/06**: 13,98%;

  - **08/06**: 14,0%;

  - **07/06**: 13,05%;

  - **19/06**: 19,02%, il valore più alto del mese, suggerendo la presenza di una **anomalia** o **criticità significativa** in quella giornata.

In generale, il volume totale degli eventi giornalieri oscilla tra circa **590 e oltre 1040 eventi al giorno**, senza un trend di crescita o decrescita costante, ma con variazioni che **potrebbero riflettere la normale attività del sistema o eventi specifici di rilievo**.


### Conteggio giornaliero degli eventi di sistema

Di seguito è mostrata una rappresentazione grafica dei conteggi giornalieri degli eventi di sistema raccolti durante il periodo di maggio 2025, realizzata con un grafico di tipo **plot line** su **scala logaritmica**. L’asse verticale indica il numero di occorrenze,  quello orizzontale rappresenta i singoli giorni del mese. Le linee corrispondono ai più ricorenti Event ID per ciascun tipo: 

• **Information**: `7036` e `14554`; 

• **Warning**: `150` e `50`; 

• **Error**: `1058`, `5805` e `5723`. 


##

<div align="center" style="border:1px solid #ccc; padding:30px; display: inline-block;"> 
  <img width="1512" height="676" alt="image" src="https://github.com/user-attachments/assets/67468d83-002e-423c-8697-05ee4c4c2f59" />
</div>

Le interruzioni nelle linee indicano i giorni in cui un determinato Event ID non è stato registrato, permettendo così di evidenziare chiaramente differenze di frequenza e variazioni nel tempo.

##

### Andamento

- Gli eventi di tipo **Information** (ID 7036 e 14554) sono i **più frequenti**, mediamente tra 250 e 450 eventi al giorno.

- Gli eventi di tipo **Warning** (ID 140 e 50) hanno un **andamento intermittente**:

  - Nei giorni: 9–12 maggio, 17–18 maggio, 24–25 maggio, 31 maggio, **non si registrano Warning**.

  - In altri giorni variano da 4 a 65 eventi, con picchi il 13/05 (65) e il 26/05 (62).

- Gli eventi di tipo **Error** (ID 1058, 5723, 5805) **mostrano oscillazioni**:

  - **ID 1058** (Group Policy processing error) è il **più frequente**, da 26 a 86 eventi al giorno, con picchi il 22/05 e 24/05 (86).

  - **ID 5723** (problemi di trust con il dominio) e **ID 5805** (machine account non trovato nel dominio) **sono costanti**, tipicamente 10–12 eventi/giorno.


Si osserva un **pattern evidente**, ovvero che nei giorni in cui mancano i Warning, come ad esempio dal 9 al 12 maggio e tra il 24 e il 25 maggio, si registra un aumento marcato degli Error 1058. Inoltre, in alcune giornate specifiche (13, 26 e 29 maggio) si manifestano picchi contemporanei sia di Warning sia di Errori, suggerendo la possibilità di disservizi o modifiche infrastrutturali.





