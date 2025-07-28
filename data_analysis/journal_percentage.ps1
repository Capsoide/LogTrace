# Lo script analizza un file di log eventi Windows in formato .evtx filtrando gli eventi in un intervallo di date definito dall’utente ($startDate e $endDate). 

# Per ogni giorno dell’intervallo: calcola il numero totale di eventi, determina la distribuzione per livello di severità (Information, Warning, Error) ,calcola le percentuali di ciascun livello rispetto al totale giornaliero.

#I risultati vengono mostrati a video in forma tabellare e salvati in un report Excel (.xlsx) contenente, per ogni giorno, i conteggi e le percentuali di eventi per livello.

#Esempio di output:
#
# === 2025-05-05 ===
# Information: 432 eventi (82,15%)
# Warning    :  39 eventi (7,42%)
# Error      :  55 eventi (10,43%)


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
    Write-Host "`n=== $($date.ToString("yyyy-MM-dd")) ==="
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
Write-Host "`nReport Excel salvato in: $outputXlsx"
