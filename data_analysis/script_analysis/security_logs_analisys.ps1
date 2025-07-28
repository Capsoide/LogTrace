<#

Lo script analizza un file di log eventi di Windows in formato .evtx, calcolando per ciascun Event ID il numero totale di occorrenze, la relativa percentuale sul totale degli eventi raggruppandoli per Event ID.

Funzionamento:
- Verifica l'esistenza del file EVTX specificato.
- Elabora tutti gli eventi presenti nel file.
- Conta le occorrenze di ciascun Event ID.
- Calcola la percentuale di ogni Event ID rispetto al totale, con una precisione di quattro cifre decimali.
- Stampa a console un riepilogo ordinato per Event ID e la percentuale di incidenza sul totale.

Esempio di output:

Riepilogo Eventi per Event ID:
Event ID 4624 : 61872 eventi (33,1477 %)
Event ID 4634 : 61645 eventi (33,1627 %)
Event ID 4648 : 33008 eventi (17,7628 %)
        ...

Elaborazione completata. Totale eventi: 186174

#>

# Percorso del file di log .evtx
$logFile = "C:\Users\vboxuser\Desktop\Security_log_DC33.evtx"

# Verifica se il file esiste
if (-not (Test-Path $logFile)) {
    Write-Host "File EVTX non trovato: $logFile"
    return
} else {
    Write-Host "File EVTX trovato: $logFile"
}

Write-Host "Elaborazione eventi in corso..."

# Hashtable per contare gli eventi per Event ID
$eventCounts = @{}

# Contatore totale degli eventi elaborati
$totalEvents = 0

# Legge tutti gli eventi dal file EVTX
Get-WinEvent -Path $logFile | ForEach-Object {
    $evento = $_

    # Salta eventi senza ID
    if (-not $evento.Id) { return }

    $eventId = $evento.Id

    # Incrementa il contatore totale eventi
    $totalEvents++

    # Ogni 5000 eventi mostra stringa debug in output
    if ($totalEvents % 5000 -eq 0) {
        Write-Host "Eventi processati finora: $totalEvents"
    }

    # Se l'ID non è ancora nel dizionario, inizializzalo
    if (-not $eventCounts.ContainsKey($eventId)) {
        $eventCounts[$eventId] = 0
    }

    # Incrementa il contatore per questo Event ID
    $eventCounts[$eventId]++
}

# Se non sono stati trovati eventi, stop esecuzione
if ($totalEvents -eq 0) {
    Write-Host "Nessun evento trovato nel file."
    return
}

# Stampa riepilogo ordinato per Event ID
Write-Host "`nRiepilogo Eventi per Event ID:"
foreach ($id in $eventCounts.Keys | Sort-Object) {
    $count = $eventCounts[$id]
    # Calcola la percentuale a 4 cifre dopo la virgola
    $percent = [math]::Round(($count / $totalEvents) * 100, 4)
    Write-Host "Event ID $id : $count eventi ($percent`%)"
}

# Output totale eventi
Write-Host "`nElaborazione completata. Totale eventi: $totalEvents"
