# ============================================================
# Export-ADLogs.ps1
# Convertit les logs AD (.evtx ou journaux live) en CSV/JSON
# Compatible avec AD Log Analyzer (ad-log-analyzer.html)
# ============================================================
# USAGE :
#   .\Export-ADLogs.ps1
#   .\Export-ADLogs.ps1 -Source "C:\logs\Security.evtx" -MaxEvents 10000
#   .\Export-ADLogs.ps1 -Format JSON -OutputPath "C:\export\logs.json"
# ============================================================

param(
    [string]$Source      = "Security",       # Nom du journal OU chemin .evtx
    [string]$OutputPath  = "",               # Chemin de sortie (auto si vide)
    [int]   $MaxEvents   = 5000,             # Nombre max d'événements
    [string]$Format      = "CSV",            # CSV ou JSON
    [string]$StartTime   = "",               # Filtre début  ex: "2025-01-01"
    [string]$EndTime     = "",               # Filtre fin    ex: "2025-12-31"
    [int[]] $EventIDs    = @(                # EventIDs à capturer (vide = tous)
        4624, 4625, 4634, 4648, 4672,
        4720, 4722, 4723, 4724, 4725, 4726,
        4728, 4729, 4732, 4733, 4738, 4740,
        4756, 4768, 4769, 4771, 4776, 4799,
        4660, 4663, 4946, 5140, 5145, 7045
    )
)

# ── Couleurs console ──────────────────────────────────────
function Write-Step  { param($m) Write-Host "  → $m" -ForegroundColor Cyan }
function Write-OK    { param($m) Write-Host "  ✓ $m" -ForegroundColor Green }
function Write-Warn  { param($m) Write-Host "  ⚠ $m" -ForegroundColor Yellow }
function Write-Fail  { param($m) Write-Host "  ✗ $m" -ForegroundColor Red }

Write-Host ""
Write-Host "╔══════════════════════════════════════════╗" -ForegroundColor DarkCyan
Write-Host "║       AD Log Exporter  v1.0              ║" -ForegroundColor DarkCyan
Write-Host "║  Pour AD Log Analyzer (fichier .html)    ║" -ForegroundColor DarkCyan
Write-Host "╚══════════════════════════════════════════╝" -ForegroundColor DarkCyan
Write-Host ""

# ── Droits administrateur ────────────────────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warn "Non exécuté en tant qu'Administrateur."
    Write-Warn "Certains journaux peuvent être inaccessibles."
    Write-Host ""
}

# ── Chemin de sortie auto ────────────────────────────────
if (-not $OutputPath) {
    $ext = $Format.ToUpper() -eq "JSON" ? "json" : "csv"
    $ts  = Get-Date -Format "yyyyMMdd_HHmmss"
    $OutputPath = "$env:USERPROFILE\Desktop\AD_Logs_$ts.$ext"
}

# ── Construction du filtre XPath ─────────────────────────
Write-Step "Construction du filtre d'événements..."

$filterHash = @{ LogName = $Source }

# Source .evtx ou journal live
$isEvtx = $Source -like "*.evtx"
if ($isEvtx) {
    if (-not (Test-Path $Source)) {
        Write-Fail "Fichier introuvable : $Source"
        exit 1
    }
    $filterHash = @{ Path = $Source }
    Write-Step "Source : fichier EVTX → $Source"
} else {
    Write-Step "Source : journal live → $Source"
}

# Filtre sur les EventIDs
if ($EventIDs.Count -gt 0) {
    $filterHash["Id"] = $EventIDs
}

# Filtre temporel
if ($StartTime) {
    $filterHash["StartTime"] = [datetime]$StartTime
}
if ($EndTime) {
    $filterHash["EndTime"] = [datetime]$EndTime
}

Write-OK "Filtre configuré : $($EventIDs.Count) EventIDs surveillés"

# ── Extraction des événements ────────────────────────────
Write-Step "Extraction en cours (max $MaxEvents événements)..."

try {
    $rawEvents = Get-WinEvent -FilterHashtable $filterHash -MaxEvents $MaxEvents -ErrorAction Stop
    Write-OK "$($rawEvents.Count) événements récupérés"
} catch [System.Exception] {
    if ($_.Exception.Message -like "*No events*" -or $_.Exception.HResult -eq -2147024773) {
        Write-Warn "Aucun événement trouvé pour ce filtre."
        $rawEvents = @()
    } else {
        Write-Fail "Erreur lors de la lecture : $($_.Exception.Message)"
        exit 1
    }
}

if ($rawEvents.Count -eq 0) {
    Write-Warn "Aucune donnée à exporter."
    exit 0
}

# ── Mapping EventID → Description ───────────────────────
$eventLabels = @{
    4624 = "Connexion réussie"
    4625 = "Échec de connexion"
    4634 = "Déconnexion"
    4648 = "Connexion credentials explicites"
    4672 = "Privilèges spéciaux assignés"
    4688 = "Processus créé"
    4720 = "Compte utilisateur créé"
    4722 = "Compte utilisateur activé"
    4723 = "Tentative changement mot de passe"
    4724 = "Réinitialisation mot de passe"
    4725 = "Compte utilisateur désactivé"
    4726 = "Compte utilisateur supprimé"
    4728 = "Membre ajouté groupe sécurité global"
    4729 = "Membre retiré groupe sécurité global"
    4732 = "Membre ajouté groupe Administrators"
    4733 = "Membre retiré groupe Administrators"
    4738 = "Compte utilisateur modifié"
    4740 = "Compte utilisateur verrouillé"
    4756 = "Membre ajouté groupe universel"
    4760 = "Groupe sécurité universel modifié"
    4768 = "Ticket Kerberos TGT demandé"
    4769 = "Ticket Kerberos service demandé"
    4771 = "Échec pré-auth Kerberos"
    4776 = "Authentification NTLM (DC)"
    4799 = "Groupe local énuméré"
    4946 = "Règle pare-feu ajoutée"
    4660 = "Objet supprimé"
    4663 = "Accès objet tenté"
    5140 = "Partage réseau accédé"
    5145 = "Accès partage réseau vérifié"
    5156 = "Connexion réseau autorisée"
    7045 = "Service système installé"
}

$severityMap = @{
    4625 = "critical"; 4740 = "critical"; 4732 = "critical"
    4726 = "critical"; 4771 = "critical"; 7045 = "critical"
    4660 = "critical"
    4648 = "warning";  4672 = "warning";  4720 = "warning"
    4722 = "warning";  4723 = "warning";  4724 = "warning"
    4725 = "warning";  4728 = "warning";  4729 = "warning"
    4733 = "warning";  4738 = "warning";  4756 = "warning"
    4769 = "warning";  4799 = "warning";  4946 = "warning"
    4663 = "warning";  5145 = "warning"
}

# ── Parse XML de chaque événement ────────────────────────
Write-Step "Analyse et structuration des événements..."

$parsed = $rawEvents | ForEach-Object {
    $ev  = $_
    $xml = [xml]$ev.ToXml()
    $sys = $xml.Event.System

    # Extraction champs EventData
    $data = @{}
    if ($xml.Event.EventData -and $xml.Event.EventData.Data) {
        foreach ($d in $xml.Event.EventData.Data) {
            if ($d.Name) { $data[$d.Name] = $d.'#text' }
        }
    }

    # Résolution utilisateur
    $user = $data["SubjectUserName"]
    if (-not $user -or $user -eq "-") { $user = $data["TargetUserName"] }
    if (-not $user -or $user -eq "-") { $user = $data["SAMAccountName"] }
    if (-not $user -or $user -eq "-") { $user = $ev.UserId?.Value ?? "N/A" }

    # Machine source
    $computer = $data["WorkstationName"]
    if (-not $computer -or $computer -eq "-") { $computer = $data["IpAddress"] }
    if (-not $computer -or $computer -eq "-") { $computer = $sys.Computer }

    # Domaine
    $domain = $data["SubjectDomainName"]
    if (-not $domain -or $domain -eq "-") { $domain = $data["TargetDomainName"] }

    $eid  = [int]$sys.EventID
    $sev  = if ($severityMap.ContainsKey($eid)) { $severityMap[$eid] } else { "info" }
    $lbl  = if ($eventLabels.ContainsKey($eid))  { $eventLabels[$eid]  } else { "Événement $eid" }

    # Message concis
    $msg = "$lbl"
    if ($user -and $user -ne "N/A" -and $user -ne "-") { $msg += " — Compte: $user" }
    if ($data["TargetUserName"] -and $data["TargetUserName"] -ne $user -and $data["TargetUserName"] -ne "-") {
        $msg += " → $($data['TargetUserName'])"
    }
    if ($computer -and $computer -ne $sys.Computer -and $computer -ne "-") { $msg += " sur $computer" }
    if ($data["LogonType"]) { $msg += " (Type: $($data['LogonType']))" }
    if ($data["Status"])    { $msg += " [Status: $($data['Status'])]" }

    [PSCustomObject]@{
        TimeCreated     = $ev.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
        EventID         = $eid
        EventLabel      = $lbl
        Severity        = $sev
        SubjectUserName = $user
        TargetUserName  = $data["TargetUserName"] ?? ""
        Domain          = $domain ?? ""
        Computer        = $sys.Computer
        WorkstationName = $computer
        IpAddress       = $data["IpAddress"] ?? ""
        LogonType       = $data["LogonType"] ?? ""
        Status          = $data["Status"] ?? ""
        Channel         = $sys.Channel
        Message         = $msg
        # Champs accès objets
        ObjectName      = $data["ObjectName"] ?? ""
        ObjectType      = $data["ObjectType"] ?? ""
        AccessMask      = $data["AccessMask"] ?? ""
        # Champs groupes
        MemberName      = $data["MemberName"] ?? ""
        GroupName       = $data["TargetUserName"] ?? $data["GroupName"] ?? ""
    }
}

Write-OK "$($parsed.Count) événements structurés"

# ── Export ───────────────────────────────────────────────
Write-Step "Export en $Format → $OutputPath"

try {
    if ($Format.ToUpper() -eq "JSON") {
        $parsed | ConvertTo-Json -Depth 3 | Out-File -FilePath $OutputPath -Encoding UTF8
    } else {
        $parsed | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 -Delimiter ";"
    }
    Write-OK "Fichier créé : $OutputPath"
} catch {
    Write-Fail "Erreur d'écriture : $($_.Exception.Message)"
    exit 1
}

# ── Résumé rapide ────────────────────────────────────────
Write-Host ""
Write-Host "  ── Résumé ──────────────────────────────" -ForegroundColor DarkGray
$parsed | Group-Object Severity | ForEach-Object {
    $color = switch ($_.Name) { "critical" { "Red" } "warning" { "Yellow" } default { "Cyan" } }
    Write-Host ("  {0,-12} : {1,5} événements" -f $_.Name.ToUpper(), $_.Count) -ForegroundColor $color
}

$top5Fail = $parsed | Where-Object { $_.EventID -eq 4625 } |
    Group-Object SubjectUserName | Sort-Object Count -Descending | Select-Object -First 5
if ($top5Fail) {
    Write-Host ""
    Write-Host "  ── Top échecs de connexion ─────────────" -ForegroundColor DarkGray
    $top5Fail | ForEach-Object {
        Write-Host ("  {0,-20} : {1,4} échecs" -f $_.Name, $_.Count) -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "  Importez maintenant '$OutputPath'" -ForegroundColor Green
Write-Host "  dans AD Log Analyzer (ad-log-analyzer.html)" -ForegroundColor Green
Write-Host ""
