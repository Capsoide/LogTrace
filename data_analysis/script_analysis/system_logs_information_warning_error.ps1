<#

Lo script analizza un file di log eventi di Windows in formato .evtx, applicando un filtro su un intervallo di date definito dall’utente nel codice ($startDate e $endDate).  

Gli eventi filtrati vengono raggruppati per: giorno di occorrenza, livello (Information, Warning, Error), ID evento.

Per ciascun giorno nell’intervallo, lo script calcola il numero di occorrenze per ogni ID evento e produce un output a console strutturato per livello e salvati in un report Excel (.xlsx)

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

#>

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
