#Requires -Version 5.1
<#
.SYNOPSIS
    Durcissement de sécurité de Windows 11 Famille, en un seul lancement et sans paramètre.

.DESCRIPTION
    Réduit la surface d'attaque face aux techniques offensives répertoriées dans MITRE ATT&CK
    (accès initial, exécution, persistance, élévation de privilèges, vol d'identifiants,
    mouvement latéral, évasion de défense, exfiltration), d'après les CIS Benchmarks Windows 11,
    les recommandations de l'ANSSI et les Microsoft Security Baselines.

    Applications préservées (détectées automatiquement, aucun chemin codé en dur) :
      - Microsoft Edge, Microsoft Edge Update et le runtime WebView2 ;
      - Battle.net, Blizzard Agent, World of Warcraft, Heroes of the Storm, CurseForge, WowUp ;
      - Claude : claude.ai dans Edge et l'application Claude Desktop.

    Sécurité de l'opération (automatique) :
      - point de restauration système avant toute modification ;
      - sauvegarde de chaque réglage modifié dans un fichier JSON horodaté ;
      - script d'annulation généré automatiquement (double-clic) ;
      - idempotent : il peut être relancé sans effet de bord.

    Où sont les fichiers produits (rapport, journal, sauvegardes, annulation) ?
      Dans « C:\Program Files\Durcissement-Sauvegarde », ouvert par le raccourci
      « Durcissement-Sauvegarde » créé sur le Bureau. Pourquoi pas directement sur le Bureau :
        1. l'accès contrôlé aux dossiers, activé par ce script, interdit à PowerShell
           d'écrire sur le Bureau ;
        2. seul un administrateur peut modifier ce dossier : un programme malveillant ne peut
           donc pas trafiquer le script d'annulation, qui s'exécute en administrateur.

.NOTES
    Lancement : double-clic sur Lancer-Durcissement.bat, placé dans le même dossier.
    Compatible Windows PowerShell 5.1 (inclus dans Windows 11). Encodage : UTF-8 avec BOM.
    Si vous modifiez ce fichier, enregistrez-le en « UTF-8 avec BOM » pour garder les accents.
#>

# =====================================================================
#  RÉGLAGES MODIFIABLES (facultatif : le script fonctionne sans y toucher)
# =====================================================================

# Exécutables à autoriser en plus (accès contrôlé aux dossiers + exclusion des règles ASR).
# Chemin complet ; le joker * peut remplacer un dossier entier (par exemple un dossier de version).
# Exemple : 'C:\Program Files\MonJeu\*\MonJeu.exe'
$AppsSupplementaires = @(
)

# Services réseau inutiles que le script désactive.
$ServicesADesactiver = @(
    @{ Nom = 'RemoteRegistry'; Libelle = 'Registre à distance';                   Attack = 'T1012, T1112' }
    @{ Nom = 'RemoteAccess';   Libelle = 'Routage et accès distant';               Attack = 'T1021' }
    @{ Nom = 'SNMPTRAP';       Libelle = 'Interruption SNMP';                      Attack = 'T1046' }
    @{ Nom = 'simptcp';        Libelle = 'Services TCP/IP simples (si installés)'; Attack = 'T1046' }
)

# Liste blanche protégée : ces services ne sont JAMAIS désactivés, même s'ils sont ajoutés ci-dessus.
# (Les services dont le nom évoque Blizzard, Battle.net, Anthropic ou Claude sont aussi protégés.)
$ServicesProteges = @(
    'Dnscache', 'Dhcp', 'NlaSvc', 'netprofm', 'nsi', 'Wcmsvc', 'RasMan', 'WlanSvc', 'LanmanWorkstation',
    'BITS', 'wuauserv', 'UsoSvc', 'WaaSMedicSvc', 'CryptSvc', 'TrustedInstaller',
    'edgeupdate', 'edgeupdatem', 'MicrosoftEdgeElevationService',
    'Audiosrv', 'AudioEndpointBuilder',
    'WinDefend', 'WdNisSvc', 'mpssvc', 'BFE', 'SecurityHealthService', 'wscsvc',
    'EventLog', 'Schedule', 'Winmgmt', 'RpcSs', 'RpcEptMapper', 'DcomLaunch', 'TokenBroker', 'ProfSvc'
)

# =====================================================================
#  DÉMARRAGE : mode de langage, droits administrateur, PowerShell 5.1 64 bits
# =====================================================================

if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
    Write-Host ''
    Write-Host ('PowerShell fonctionne ici en mode restreint ({0}).' -f $ExecutionContext.SessionState.LanguageMode) -ForegroundColor Red
    Write-Host 'Cela arrive quand Smart App Control ou une stratégie de contrôle des applications est active.' -ForegroundColor Red
    Write-Host 'Le script ne peut pas fonctionner dans ce mode. Aucune modification n''a été faite.' -ForegroundColor Red
    Read-Host 'Appuyez sur Entrée pour fermer'
    exit 1
}

$estAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$bonMoteur = ($PSVersionTable.PSEdition -eq 'Desktop') -and ([Environment]::Is64BitProcess -or -not [Environment]::Is64BitOperatingSystem)

if (-not ($estAdmin -and $bonMoteur)) {
    if ($args -contains '-Relance') {
        Write-Host 'Impossible d''obtenir les droits administrateur dans Windows PowerShell 64 bits.' -ForegroundColor Red
        Write-Host 'Faites un clic droit sur Lancer-Durcissement.bat > Exécuter en tant qu''administrateur.' -ForegroundColor Red
        Read-Host 'Appuyez sur Entrée pour fermer'
        exit 1
    }
    if (-not $PSCommandPath) {
        Write-Host 'Lancez ce script par un double-clic sur Lancer-Durcissement.bat.' -ForegroundColor Red
        Read-Host 'Appuyez sur Entrée pour fermer'
        exit 1
    }
    # Relance dans Windows PowerShell 5.1 64 bits, en administrateur. La stratégie d'exécution
    # n'est contournée que pour ce processus (-ExecutionPolicy Bypass) : rien n'est modifié dans Windows.
    $moteur = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
        $moteur = Join-Path $env:SystemRoot 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    }
    $argumentsRelance = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -Relance' -f $PSCommandPath
    try {
        Write-Host 'Demande des droits administrateur (fenêtre de contrôle de compte d''utilisateur)...' -ForegroundColor Cyan
        Start-Process -FilePath $moteur -ArgumentList $argumentsRelance -Verb RunAs -ErrorAction Stop
    } catch {
        Write-Host 'Les droits administrateur ont été refusés : aucune modification n''a été faite.' -ForegroundColor Yellow
        Read-Host 'Appuyez sur Entrée pour fermer'
        exit 1
    }
    exit 0
}

$ErrorActionPreference = 'Stop'
try { $Host.UI.RawUI.WindowTitle = 'Durcissement de sécurité — Windows 11' } catch { }

# =====================================================================
#  DONNÉES DE RÉFÉRENCE
# =====================================================================

# Règles ASR (identifiants vérifiés dans la documentation Microsoft « ASR rules reference »).
# Blocage partout, sauf les règles qui peuvent gêner jeux, launchers et applications Electron : Audit.
# La règle « Webshell pour serveurs » est volontairement absente (Exchange Server uniquement).
$ReglesAsr = @(
    @{ Id = '56a863a9-875e-4185-98a7-b882c64b5ce5'; Mode = 'Block'; Attack = 'T1068, T1562.001';         Libelle = 'Bloquer les pilotes signés vulnérables (BYOVD)';                      Impact = 'Anciens outils de surveillance matérielle (pilote WinRing0 ou RTCore) refusés à l''installation' }
    @{ Id = '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'; Mode = 'Block'; Attack = 'T1003.001';                Libelle = 'Bloquer le vol d''identifiants dans LSASS';                          Impact = 'Aucun' }
    @{ Id = 'e6db77e5-3df2-4cf1-b95a-636979351e5b'; Mode = 'Block'; Attack = 'T1546.003';                Libelle = 'Bloquer la persistance par abonnement WMI';                          Impact = 'Aucun pour un usage domestique' }
    @{ Id = 'd4f940ab-401b-4efc-aadc-ad5f3c50688a'; Mode = 'Block'; Attack = 'T1566.001, T1204.002';     Libelle = 'Empêcher Office de créer des processus enfants';                      Impact = 'Certains compléments ou macros Office' }
    @{ Id = '3b576869-a4ec-4529-8536-b80a7769e899'; Mode = 'Block'; Attack = 'T1204.002';                Libelle = 'Empêcher Office de créer du contenu exécutable';                     Impact = 'Aucun en usage normal' }
    @{ Id = '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84'; Mode = 'Block'; Attack = 'T1055';                    Libelle = 'Empêcher Office d''injecter du code dans d''autres processus';        Impact = 'Aucun' }
    @{ Id = '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b'; Mode = 'Block'; Attack = 'T1106, T1059.005';         Libelle = 'Bloquer les appels d''API Win32 depuis les macros Office';            Impact = 'Macros Office avancées (rare)' }
    @{ Id = '26190899-1602-49e8-8b27-eb1d0a1ce869'; Mode = 'Block'; Attack = 'T1566.001';                Libelle = 'Empêcher Outlook de créer des processus enfants';                     Impact = 'Aucun' }
    @{ Id = 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550'; Mode = 'Block'; Attack = 'T1566.001';                Libelle = 'Bloquer le contenu exécutable reçu par e-mail ou webmail';           Impact = 'Exécutables, scripts et archives reçus par e-mail bloqués' }
    @{ Id = '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c'; Mode = 'Block'; Attack = 'T1203, T1204.002';         Libelle = 'Empêcher Adobe Reader de créer des processus enfants';                Impact = 'Aucun' }
    @{ Id = '5beb7efe-fd9a-4556-801d-275e5ffc04cc'; Mode = 'Block'; Attack = 'T1027, T1059.001';         Libelle = 'Bloquer les scripts potentiellement obscurcis';                       Impact = 'Rares scripts légitimes compactés' }
    @{ Id = 'd3e037e1-3eb8-44c8-a917-57927947596d'; Mode = 'Block'; Attack = 'T1059.005, T1059.007, T1105'; Libelle = 'Empêcher JavaScript et VBScript de lancer du contenu téléchargé'; Impact = 'Aucun' }
    @{ Id = 'd1e49aac-8f56-4280-b9ba-993a6d77406c'; Mode = 'Block'; Attack = 'T1047, T1569.002';         Libelle = 'Bloquer les processus lancés via PsExec et WMI';                      Impact = 'Certains utilitaires constructeur (HP, Dell, Lenovo)' }
    @{ Id = '33ddedf1-c6e0-47cb-833e-de6133960387'; Mode = 'Block'; Attack = 'T1562.009';                Libelle = 'Bloquer le redémarrage en mode sans échec par commande';             Impact = 'Le mode sans échec reste accessible par l''environnement de récupération' }
    @{ Id = 'c1db55ab-c21a-4637-bb3f-a12568109d35'; Mode = 'Block'; Attack = 'T1486';                    Libelle = 'Protection avancée contre les rançongiciels';                         Impact = 'Programme inconnu et non signé parfois bloqué' }
    @{ Id = '01443614-cd74-433a-b99e-2ecdc07bfc25'; Mode = 'Audit'; Attack = 'T1204.002';                Libelle = 'Exécutables peu répandus, récents ou non approuvés (prévalence)';    Impact = 'Audit seulement : protège les correctifs de jeux, les addons et les mises à jour Electron' }
    @{ Id = 'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4'; Mode = 'Audit'; Attack = 'T1091';                    Libelle = 'Processus non signés lancés depuis une clé USB';                      Impact = 'Audit seulement' }
    @{ Id = 'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb'; Mode = 'Audit'; Attack = 'T1036.003';                Libelle = 'Outils système copiés ou usurpés';                                    Impact = 'Audit seulement : la règle peut confondre un programme installé hors des dossiers habituels' }
)

# Réglages de Microsoft Defender Antivirus. « Ordre » va du plus faible au plus fort :
# un réglage déjà plus strict que la cible n'est jamais affaibli.
$PreferencesDefender = @(
    @{ Nom = 'DisableRealtimeMonitoring';     Code = $false; NomValeur = $false;            Mesure = 'Protection en temps réel';                        Attack = 'T1562.001' }
    @{ Nom = 'DisableBehaviorMonitoring';     Code = $false; NomValeur = $false;            Mesure = 'Surveillance des comportements';                  Attack = 'T1562.001' }
    @{ Nom = 'DisableIOAVProtection';         Code = $false; NomValeur = $false;            Mesure = 'Analyse des téléchargements et pièces jointes';   Attack = 'T1204.002' }
    @{ Nom = 'DisableScriptScanning';         Code = $false; NomValeur = $false;            Mesure = 'Analyse des scripts (AMSI)';                      Attack = 'T1059' }
    @{ Nom = 'DisableBlockAtFirstSeen';       Code = $false; NomValeur = $false;            Mesure = 'Blocage dès la première détection';               Attack = 'T1204.002' }
    @{ Nom = 'DisableRemovableDriveScanning'; Code = $false; NomValeur = $false;            Mesure = 'Analyse des clés USB';                            Attack = 'T1091' }
    @{ Nom = 'MAPSReporting';                 Code = 2;      NomValeur = 'Advanced';        Mesure = 'Protection fournie par le cloud (MAPS avancé)';   Attack = 'T1204.002'; Ordre = @(0, 1, 2) }
    @{ Nom = 'SubmitSamplesConsent';          Code = 1;      NomValeur = 'SendSafeSamples'; Mesure = 'Envoi automatique des échantillons sûrs';         Attack = 'T1204.002'; Ordre = @(0, 2, 1, 3) }
    @{ Nom = 'CloudBlockLevel';               Code = 2;      NomValeur = 'High';            Mesure = 'Niveau de protection cloud : élevé';              Attack = 'T1204.002'; Ordre = @(0, 1, 2, 4, 6); Impact = 'Un fichier inconnu peut être retenu quelques secondes pour analyse' }
    @{ Nom = 'CloudExtendedTimeout';          Code = 50;     NomValeur = 50;                Mesure = 'Délai d''analyse cloud prolongé (50 s)';          Attack = 'T1204.002'; Impact = 'Premier lancement d''un fichier inconnu parfois plus lent' }
    @{ Nom = 'PUAProtection';                 Code = 1;      NomValeur = 'Enabled';         Mesure = 'Blocage des applications potentiellement indésirables (PUA)'; Attack = 'T1204.002'; Ordre = @(0, 2, 1) }
    @{ Nom = 'EnableNetworkProtection';       Code = 1;      NomValeur = 'Enabled';         Mesure = 'Protection réseau (domaines malveillants bloqués dans toutes les applications)'; Attack = 'T1566.002, T1071.001, T1189'; Ordre = @(0, 2, 1); Impact = 'Sites malveillants bloqués aussi hors d''Edge (Battle.net, Claude Desktop...)' }
)

$NomsValeursDefender = @{
    'PUAProtection'                = @{ '0' = 'désactivé'; '1' = 'activé'; '2' = 'audit' }
    'MAPSReporting'                = @{ '0' = 'désactivé'; '1' = 'de base'; '2' = 'avancé' }
    'CloudBlockLevel'              = @{ '0' = 'par défaut'; '1' = 'modéré'; '2' = 'élevé'; '4' = 'élevé plus'; '6' = 'tolérance zéro' }
    'SubmitSamplesConsent'         = @{ '0' = 'toujours demander'; '1' = 'échantillons sûrs'; '2' = 'jamais'; '3' = 'tous les échantillons' }
    'EnableNetworkProtection'      = @{ '0' = 'désactivé'; '1' = 'activé'; '2' = 'audit' }
    'EnableControlledFolderAccess' = @{ '0' = 'désactivé'; '1' = 'activé'; '2' = 'audit'; '3' = 'blocage disque seul'; '4' = 'audit disque seul' }
}

# Sous-catégories d'audit avancé (GUID : indépendants de la langue de Windows).
# Valeur : 1 = succès, 2 = échec, 3 = succès et échec. Un réglage existant n'est jamais réduit.
$SousCategoriesAudit = @(
    @{ Guid = '{0CCE923F-69AE-11D9-BED3-505054503030}'; Valeur = 3; Libelle = 'Validation des informations d''identification' }
    @{ Guid = '{0CCE9215-69AE-11D9-BED3-505054503030}'; Valeur = 3; Libelle = 'Ouverture de session' }
    @{ Guid = '{0CCE9216-69AE-11D9-BED3-505054503030}'; Valeur = 1; Libelle = 'Fermeture de session' }
    @{ Guid = '{0CCE9217-69AE-11D9-BED3-505054503030}'; Valeur = 2; Libelle = 'Verrouillage de compte' }
    @{ Guid = '{0CCE921B-69AE-11D9-BED3-505054503030}'; Valeur = 1; Libelle = 'Ouverture de session spéciale' }
    @{ Guid = '{0CCE921C-69AE-11D9-BED3-505054503030}'; Valeur = 3; Libelle = 'Autres événements d''ouverture et de fermeture de session' }
    @{ Guid = '{0CCE922B-69AE-11D9-BED3-505054503030}'; Valeur = 1; Libelle = 'Création de processus' }
    @{ Guid = '{0CCE9235-69AE-11D9-BED3-505054503030}'; Valeur = 3; Libelle = 'Gestion des comptes d''utilisateur' }
    @{ Guid = '{0CCE9237-69AE-11D9-BED3-505054503030}'; Valeur = 1; Libelle = 'Gestion des groupes de sécurité' }
    @{ Guid = '{0CCE922F-69AE-11D9-BED3-505054503030}'; Valeur = 1; Libelle = 'Modification de la stratégie d''audit' }
    @{ Guid = '{0CCE9230-69AE-11D9-BED3-505054503030}'; Valeur = 1; Libelle = 'Modification de la stratégie d''authentification' }
    @{ Guid = '{0CCE9228-69AE-11D9-BED3-505054503030}'; Valeur = 3; Libelle = 'Utilisation de privilèges sensibles' }
    @{ Guid = '{0CCE9210-69AE-11D9-BED3-505054503030}'; Valeur = 1; Libelle = 'Modification de l''état de la sécurité' }
    @{ Guid = '{0CCE9211-69AE-11D9-BED3-505054503030}'; Valeur = 1; Libelle = 'Extension système de sécurité' }
    @{ Guid = '{0CCE9212-69AE-11D9-BED3-505054503030}'; Valeur = 3; Libelle = 'Intégrité du système' }
    @{ Guid = '{0CCE9227-69AE-11D9-BED3-505054503030}'; Valeur = 3; Libelle = 'Autres événements d''accès aux objets (tâches planifiées)' }
)

# Taille minimale des journaux (Ko). Un journal plus grand n'est jamais réduit.
$JournauxEvenements = @(
    @{ Nom = 'Security';                                        Ko = 196608 }
    @{ Nom = 'System';                                          Ko = 32768 }
    @{ Nom = 'Application';                                     Ko = 32768 }
    @{ Nom = 'Windows PowerShell';                              Ko = 32768 }
    @{ Nom = 'Microsoft-Windows-PowerShell/Operational';        Ko = 131072 }
    @{ Nom = 'Microsoft-Windows-Windows Defender/Operational';  Ko = 32768 }
    @{ Nom = 'Microsoft-Windows-TaskScheduler/Operational';     Ko = 32768; Activer = $true }
)

# Sites testés en fin de script (DNS + HTTPS sur le port 443).
$SitesTest = @('www.microsoft.com', 'claude.ai', 'api.anthropic.com', 'eu.battle.net')

$TitresEtapes = @(
    'Préparation : sauvegarde, point de restauration, applications',
    '1/12  Microsoft Defender',
    '2/12  Protection contre les falsifications',
    '3/12  Pare-feu',
    '4/12  Protocoles anciens et risqués',
    '5/12  Identifiants',
    '6/12  Exécution de scripts',
    '7/12  Persistance (audit seul, aucune suppression)',
    '8/12  Élévation de privilèges',
    '9/12  Protections contre l''exploitation',
    '10/12 Journalisation',
    '11/12 Services',
    '12/12 Mises à jour',
    'Vérification finale'
)

# =====================================================================
#  OUTILS : affichage, journal, résultats
# =====================================================================

$LibellesStatut = @{ 'OK' = 'OK'; 'IGNORE' = 'IGNORÉ'; 'INFO' = 'INFO'; 'ALERTE' = 'ALERTE'; 'ECHEC' = 'ÉCHEC' }
$CouleursStatut = @{ 'OK' = 'Green'; 'IGNORE' = 'DarkGray'; 'INFO' = 'Gray'; 'ALERTE' = 'Yellow'; 'ECHEC' = 'Red' }
$LibellesEvaluation = @{ 'SUSPECT' = 'Suspect'; 'A_VERIFIER' = 'À vérifier'; 'CONNUE' = 'Connue'; 'OK' = 'OK' }

function Write-Journal {
    param([string]$Texte)
    $script:Journal.Add(('{0}  {1}' -f (Get-Date).ToString('HH:mm:ss'), $Texte))
}

function Write-Ligne {
    param([string]$Statut, [string]$Texte)
    $libelle = $LibellesStatut[$Statut]
    if (-not $libelle) { $libelle = $Statut }
    $couleur = $CouleursStatut[$Statut]
    if (-not $couleur) { $couleur = 'Gray' }
    Write-Host ('  [{0}]' -f $libelle).PadRight(12) -ForegroundColor $couleur -NoNewline
    Write-Host $Texte
    Write-Journal ('[{0}] {1}' -f $libelle, $Texte)
}

function Write-Patience {
    param([string]$Texte)
    Write-Host ('  ... {0}' -f $Texte) -ForegroundColor DarkGray
    Write-Journal ('... {0}' -f $Texte)
}

function Add-Resultat {
    param(
        [string]$Categorie,
        [string]$Mesure,
        [string]$Attack = '',
        [string]$Avant = '',
        [string]$Apres = '',
        [ValidateSet('OK', 'IGNORE', 'INFO', 'ALERTE', 'ECHEC')][string]$Statut,
        [string]$Detail = '',
        [string]$Impact = ''
    )
    $script:Resultats.Add([pscustomobject]@{
            Categorie = $Categorie
            Mesure    = $Mesure
            Attack    = $Attack
            Avant     = $Avant
            Apres     = $Apres
            Statut    = $Statut
            Detail    = $Detail
            Impact    = $Impact
        })
    $texte = $Mesure
    if ($Detail) { $texte = '{0} — {1}' -f $Mesure, $Detail }
    Write-Ligne -Statut $Statut -Texte $texte
}

function Invoke-Etape {
    # Exécute une étape : chaque action a son propre try/catch, une erreur n'arrête jamais le script.
    param([string]$Titre, [scriptblock[]]$Actions)
    $script:NumeroEtape++
    $pourcent = [int](($script:NumeroEtape - 1) * 100 / $TitresEtapes.Count)
    Write-Progress -Activity 'Durcissement de Windows' -Status $Titre -PercentComplete $pourcent
    Write-Host ''
    Write-Host ('── {0} ' -f $Titre).PadRight(74, '─') -ForegroundColor Cyan
    Write-Journal ('=== {0} ===' -f $Titre)
    foreach ($action in $Actions) {
        try {
            $null = & $action
        } catch {
            Add-Resultat -Categorie $Titre -Mesure 'Erreur inattendue dans cette étape' -Statut 'ECHEC' -Detail $_.Exception.Message
        }
    }
    Save-Sauvegarde
}

function Invoke-Protege {
    # Exécute une sous-mesure : une erreur est consignée sans interrompre les mesures suivantes.
    param([string]$PCategorie, [string]$PMesure, [scriptblock]$PAction)
    try {
        $null = & $PAction
    } catch {
        Add-Resultat -Categorie $PCategorie -Mesure $PMesure -Statut 'ECHEC' -Detail $_.Exception.Message
    }
}

function Invoke-Natif {
    # Lance un programme Windows (sc.exe, auditpol.exe...) et renvoie son code de sortie et son texte.
    param([string]$Fichier, [string[]]$Arguments)
    $ErrorActionPreference = 'Continue'
    $sortie = & $Fichier @Arguments 2>&1 | ForEach-Object { [string]$_ }
    [pscustomobject]@{ Code = $LASTEXITCODE; Sortie = (($sortie | Out-String).Trim()) }
}

function ConvertTo-TexteValeur {
    param($Valeur)
    if ($null -eq $Valeur) { return 'absent' }
    if ($Valeur -is [byte[]]) { return ('{0} octet(s)' -f $Valeur.Length) }
    if ($Valeur -is [array]) { return (@($Valeur) -join ' | ') }
    return [string]$Valeur
}

function Format-Html {
    param([string]$Texte)
    return [System.Net.WebUtility]::HtmlEncode($Texte)
}

function Get-Empreinte {
    param([string]$Texte)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $octets = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Texte.ToLowerInvariant())) } finally { $sha.Dispose() }
    return ((@($octets[0..3]) | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Get-NomFichier {
    # Nom du fichier d'un chemin Windows (« C:\x\a.exe » -> « a.exe »).
    param([string]$Chemin)
    if (-not $Chemin) { return '' }
    return ($Chemin -split '\\')[-1]
}

# =====================================================================
#  OUTILS : sauvegarde et registre
# =====================================================================

function Add-Sauvegarde {
    # Mémorise l'état d'origine d'un réglage (une seule fois par réglage et par exécution).
    param([hashtable]$Element, [string]$Cle)
    if ($Cle) {
        if ($script:DejaSauvegarde.Contains($Cle)) { return }
        [void]$script:DejaSauvegarde.Add($Cle)
    }
    $script:Sauvegarde.Add($Element)
}

function Save-Sauvegarde {
    if (-not $script:FichierSauvegarde) { return }
    try {
        $objet = [ordered]@{
            Version     = 1
            Date        = $script:Debut.ToString('yyyy-MM-dd HH:mm:ss')
            Ordinateur  = $env:COMPUTERNAME
            Utilisateur = $script:Utilisateur.Nom
            Sid         = $script:Utilisateur.Sid
            Elements    = $script:Sauvegarde.ToArray()
        }
        $json = ConvertTo-Json -InputObject $objet -Depth 8
        [System.IO.File]::WriteAllText($script:FichierSauvegarde, $json, $script:Utf8Bom)
    } catch {
        Write-Ligne -Statut 'ECHEC' -Texte ('Écriture de la sauvegarde impossible : {0}' -f $_.Exception.Message)
    }
}

function Set-ValeurRegistre {
    # Écrit une valeur de registre après avoir sauvegardé l'ancienne. Ne fait rien si elle est déjà correcte.
    param(
        [Parameter(Mandatory = $true)][string]$Chemin,
        [Parameter(Mandatory = $true)][string]$Nom,
        [Parameter(Mandatory = $true)]$Valeur,
        [string]$Type = 'DWord'
    )
    $clesCreees = @()
    if (-not (Test-Path -LiteralPath $Chemin)) {
        $manquantes = New-Object System.Collections.Generic.List[string]
        $p = $Chemin
        while ($p -and -not (Test-Path -LiteralPath $p)) {
            $manquantes.Insert(0, $p)
            $p = Split-Path -Path $p -Parent
        }
        foreach ($k in $manquantes) { New-Item -Path $k -Force | Out-Null }
        $clesCreees = $manquantes.ToArray()
    }
    $cle = Get-Item -LiteralPath $Chemin
    $existait = @($cle.GetValueNames()) -contains $Nom
    $ancienne = $null
    $ancienType = $null
    if ($existait) {
        $ancienne = $cle.GetValue($Nom, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $ancienType = $cle.GetValueKind($Nom).ToString()
    }
    $identique = $false
    if ($existait -and $ancienType -eq $Type) {
        if ($Type -eq 'DWord' -or $Type -eq 'QWord') { $identique = ([int64]$ancienne -eq [int64]$Valeur) }
        elseif ($Type -eq 'MultiString') { $identique = ((@($ancienne) -join "`n") -eq (@($Valeur) -join "`n")) }
        else { $identique = ([string]$ancienne -eq [string]$Valeur) }
    }
    $resultat = [pscustomobject]@{ Change = $false; Avant = (ConvertTo-TexteValeur $ancienne); Apres = (ConvertTo-TexteValeur $Valeur) }
    if ($identique) { return $resultat }

    $copie = $ancienne
    if ($ancienne -is [byte[]]) { $copie = @($ancienne | ForEach-Object { [int]$_ }) }
    Add-Sauvegarde -Cle ('REG|{0}|{1}' -f $Chemin, $Nom) -Element @{
        Type       = 'Registre'
        Chemin     = $Chemin
        Nom        = $Nom
        Existait   = $existait
        Valeur     = $copie
        TypeValeur = $ancienType
        ClesCreees = $clesCreees
    }
    New-ItemProperty -LiteralPath $Chemin -Name $Nom -Value $Valeur -PropertyType $Type -Force | Out-Null
    $resultat.Change = $true
    return $resultat
}

function Invoke-MesureRegistre {
    # Applique un groupe de valeurs de registre et produit UNE ligne de résultat.
    param(
        [string]$Categorie,
        [string]$Mesure,
        [string]$Attack,
        [string]$Impact = '',
        [object[]]$Valeurs,
        [switch]$Redemarrage
    )
    $avant = New-Object System.Collections.Generic.List[string]
    $apres = New-Object System.Collections.Generic.List[string]
    $changes = 0
    $erreurs = @()
    foreach ($v in $Valeurs) {
        $type = 'DWord'
        if ($v.Type) { $type = $v.Type }
        try {
            $r = Set-ValeurRegistre -Chemin $v.Chemin -Nom $v.Nom -Valeur $v.Valeur -Type $type
            $avant.Add(('{0}={1}' -f $v.Nom, $r.Avant))
            $apres.Add(('{0}={1}' -f $v.Nom, $r.Apres))
            if ($r.Change) { $changes++ }
        } catch {
            $erreurs += ('{0} : {1}' -f $v.Nom, $_.Exception.Message)
        }
    }
    $texteAvant = (@($avant | Select-Object -Unique) -join '; ')
    $texteApres = (@($apres | Select-Object -Unique) -join '; ')
    if ($changes -gt 0 -and $Redemarrage) { $script:RedemarrageRequis = $true }
    if ($erreurs.Count -gt 0) {
        Add-Resultat -Categorie $Categorie -Mesure $Mesure -Attack $Attack -Avant $texteAvant -Apres $texteApres -Statut 'ECHEC' -Detail ($erreurs -join ' / ') -Impact $Impact
    } elseif ($changes -gt 0) {
        $detail = 'appliqué'
        if ($Redemarrage) { $detail = 'appliqué (effectif après redémarrage)' }
        Add-Resultat -Categorie $Categorie -Mesure $Mesure -Attack $Attack -Avant $texteAvant -Apres $texteApres -Statut 'OK' -Detail $detail -Impact $Impact
    } else {
        Add-Resultat -Categorie $Categorie -Mesure $Mesure -Attack $Attack -Avant $texteAvant -Apres $texteApres -Statut 'OK' -Detail 'déjà en place' -Impact $Impact
    }
}

# =====================================================================
#  OUTILS : services et fonctionnalités Windows
# =====================================================================

function Get-EtatService {
    param([string]$Nom)
    $svc = Get-CimInstance -ClassName Win32_Service -Filter ("Name='{0}'" -f $Nom) -ErrorAction SilentlyContinue
    if (-not $svc) { return $null }
    $start = $null
    $delai = $null
    try {
        $p = Get-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $Nom) -ErrorAction Stop
        if ($p.PSObject.Properties['Start']) { $start = [int]$p.Start }
        if ($p.PSObject.Properties['DelayedAutostart']) { $delai = [int]$p.DelayedAutostart }
    } catch { }
    [pscustomobject]@{
        Nom     = $Nom
        Libelle = [string]$svc.DisplayName
        Mode    = [string]$svc.StartMode
        EnCours = ([string]$svc.State -eq 'Running')
        Start   = $start
        Delai   = $delai
    }
}

function Set-ServiceDesactive {
    param([string]$Nom, [string]$Categorie, [string]$Mesure, [string]$Attack, [string]$Impact = '')
    try {
        $etat = Get-EtatService -Nom $Nom
        if (-not $etat) {
            Add-Resultat -Categorie $Categorie -Mesure $Mesure -Attack $Attack -Statut 'IGNORE' -Detail 'service absent de cette machine' -Impact $Impact
            return
        }
        if (($ServicesProteges -contains $Nom) -or ($etat.Libelle -match '(?i)blizzard|battle\.net|anthropic|claude')) {
            Add-Resultat -Categorie $Categorie -Mesure $Mesure -Attack $Attack -Statut 'ALERTE' -Detail 'service de la liste blanche protégée : non modifié' -Impact $Impact
            return
        }
        if ($etat.Mode -eq 'Disabled' -and -not $etat.EnCours) {
            Add-Resultat -Categorie $Categorie -Mesure $Mesure -Attack $Attack -Avant 'désactivé' -Apres 'désactivé' -Statut 'OK' -Detail 'déjà en place' -Impact $Impact
            return
        }
        Add-Sauvegarde -Cle ('SVC|' + $Nom) -Element @{ Type = 'Service'; Nom = $Nom; Start = $etat.Start; Delai = $etat.Delai; EnCours = $etat.EnCours }
        $r = Invoke-Natif -Fichier 'sc.exe' -Arguments @('config', $Nom, 'start=', 'disabled')
        if ($r.Code -ne 0) { throw ('sc.exe : {0}' -f $r.Sortie) }
        if ($etat.EnCours) { Stop-Service -Name $Nom -Force -ErrorAction SilentlyContinue }
        Add-Resultat -Categorie $Categorie -Mesure $Mesure -Attack $Attack -Avant $etat.Mode -Apres 'Disabled' -Statut 'OK' -Detail 'désactivé' -Impact $Impact
    } catch {
        Add-Resultat -Categorie $Categorie -Mesure $Mesure -Attack $Attack -Statut 'ECHEC' -Detail $_.Exception.Message -Impact $Impact
    }
}

function Disable-Fonctionnalite {
    param([string]$Nom, [string]$Categorie, [string]$Mesure, [string]$Attack, [string]$Impact = '')
    try {
        $f = $null
        try { $f = Get-WindowsOptionalFeature -Online -FeatureName $Nom -ErrorAction Stop } catch { $f = $null }
        if (-not $f) {
            Add-Resultat -Categorie $Categorie -Mesure $Mesure -Attack $Attack -Statut 'IGNORE' -Detail 'absent de cette version de Windows (rien à désactiver)' -Impact $Impact
            return
        }
        $etat = [string]$f.State
        if ($etat -notmatch '^Enable') {
            Add-Resultat -Categorie $Categorie -Mesure $Mesure -Attack $Attack -Avant $etat -Apres $etat -Statut 'OK' -Detail 'déjà désactivé' -Impact $Impact
            return
        }
        Add-Sauvegarde -Cle ('FEAT|' + $Nom) -Element @{ Type = 'Fonctionnalite'; Nom = $Nom; Etat = 'Enabled' }
        Write-Patience ('désactivation de la fonctionnalité {0}' -f $Nom)
        $r = Disable-WindowsOptionalFeature -Online -FeatureName $Nom -NoRestart -ErrorAction Stop -WarningAction SilentlyContinue
        if ($r -and $r.RestartNeeded) { $script:RedemarrageRequis = $true }
        Add-Resultat -Categorie $Categorie -Mesure $Mesure -Attack $Attack -Avant $etat -Apres 'Disabled' -Statut 'OK' -Detail 'désactivé' -Impact $Impact
    } catch {
        Add-Resultat -Categorie $Categorie -Mesure $Mesure -Attack $Attack -Statut 'ECHEC' -Detail $_.Exception.Message -Impact $Impact
    }
}

# =====================================================================
#  CONTEXTE : système, utilisateur réellement connecté
# =====================================================================

function Get-InfosSysteme {
    $cv = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $build = 0
    [void][int]::TryParse([string]$cv.CurrentBuild, [ref]$build)
    $ubr = 0
    if ($cv.PSObject.Properties['UBR']) { $ubr = [int]$cv.UBR }
    $edition = [string]$cv.EditionID
    $version = ''
    if ($cv.PSObject.Properties['DisplayVersion']) { $version = [string]$cv.DisplayVersion }
    $famille = ($edition -like 'Core*')
    $nomOs = 'Windows 11'
    if ($build -lt 22000) { $nomOs = 'Windows 10' }
    $libelleEdition = $edition
    if ($famille) { $libelleEdition = 'Famille' } elseif ($edition -like 'Professional*') { $libelleEdition = 'Pro' }
    [pscustomobject]@{
        Build     = $build
        Ubr       = $ubr
        Edition   = $edition
        Famille   = $famille
        Windows11 = ($build -ge 22000)
        Libelle   = ('{0} {1} {2}' -f $nomOs, $libelleEdition, $version).Trim()
    }
}

function Get-ContexteUtilisateur {
    # Identifie l'utilisateur réellement connecté (propriétaire d'explorer.exe dans cette session),
    # et non le compte administrateur utilisé pour l'élévation, puis lit SA ruche HKEY_USERS\<SID>.
    $sid = $null
    try {
        $session = (Get-Process -Id $PID).SessionId
        $explorers = @(Get-CimInstance -ClassName Win32_Process -Filter "Name='explorer.exe'" -ErrorAction Stop |
                Where-Object { $_.SessionId -eq $session })
        foreach ($p in $explorers) {
            $proprietaire = Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid -ErrorAction Stop
            if ($proprietaire.Sid) { $sid = [string]$proprietaire.Sid; break }
        }
    } catch { $sid = $null }
    if (-not $sid) { $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value }

    $nom = $sid
    try { $nom = (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value } catch { }

    $profil = $null
    try { $profil = [string](Get-ItemProperty -LiteralPath ('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $sid) -ErrorAction Stop).ProfileImagePath } catch { }
    if (-not $profil) { $profil = $env:USERPROFILE }
    $profil = [Environment]::ExpandEnvironmentVariables($profil)

    $ruche = 'Registry::HKEY_USERS\' + $sid
    if (-not (Test-Path -LiteralPath $ruche)) { $ruche = $null }

    # Dossiers de l'utilisateur (le Bureau peut être redirigé vers OneDrive).
    $dossiers = @{ 'Desktop' = $null; 'Local AppData' = $null; 'AppData' = $null; 'Startup' = $null }
    if ($ruche) {
        try {
            $cle = Get-Item -LiteralPath ($ruche + '\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders') -ErrorAction Stop
            foreach ($n in @($dossiers.Keys)) {
                $brut = $cle.GetValue($n, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                if ($brut) {
                    $chemin = ([string]$brut) -ireplace '%USERPROFILE%', $profil.Replace('$', '$$')
                    $dossiers[$n] = [Environment]::ExpandEnvironmentVariables($chemin)
                }
            }
        } catch { }
    }
    if (-not $dossiers['Desktop']) { $dossiers['Desktop'] = Join-Path $profil 'Desktop' }
    if (-not $dossiers['Local AppData']) { $dossiers['Local AppData'] = Join-Path $profil 'AppData\Local' }
    if (-not $dossiers['AppData']) { $dossiers['AppData'] = Join-Path $profil 'AppData\Roaming' }
    if (-not $dossiers['Startup']) { $dossiers['Startup'] = Join-Path $dossiers['AppData'] 'Microsoft\Windows\Start Menu\Programs\Startup' }

    [pscustomobject]@{
        Sid          = $sid
        Nom          = $nom
        Profil       = $profil
        Ruche        = $ruche
        Bureau       = $dossiers['Desktop']
        LocalAppData = $dossiers['Local AppData']
        AppData      = $dossiers['AppData']
        Demarrage    = $dossiers['Startup']
    }
}

# =====================================================================
#  ÉCRAN D'ACCUEIL
# =====================================================================

function Show-Accueil {
    try { Clear-Host } catch { }
    $ligne = '=' * 74
    Write-Host $ligne -ForegroundColor Cyan
    Write-Host '  DURCISSEMENT DE SÉCURITÉ — WINDOWS 11 FAMILLE' -ForegroundColor Cyan
    Write-Host $ligne -ForegroundColor Cyan
    Write-Host ('  Ordinateur : {0}   |   {1} (build {2}.{3})' -f $env:COMPUTERNAME, $script:Systeme.Libelle, $script:Systeme.Build, $script:Systeme.Ubr)
    Write-Host ('  Compte protégé : {0}' -f $script:Utilisateur.Nom)
    Write-Host ''
    Write-Host '  Ce script va, en une seule fois :' -ForegroundColor White
    Write-Host '    1. créer un point de restauration et sauvegarder chaque réglage modifié ;'
    Write-Host '    2. renforcer Microsoft Defender (cloud, anti-rançongiciel, règles ASR) ;'
    Write-Host '    3. renforcer le pare-feu et couper les protocoles anciens (SMBv1, LLMNR, NetBIOS...) ;'
    Write-Host '    4. protéger les mots de passe en mémoire (LSA, WDigest, NTLM) ;'
    Write-Host '    5. relever le contrôle de compte (UAC) et bloquer l''exécution automatique ;'
    Write-Host '    6. activer la journalisation de sécurité ;'
    Write-Host '    7. contrôler les programmes au démarrage, les services et les mises à jour ;'
    Write-Host '    8. vérifier que Edge, Battle.net (WoW, HotS) et Claude fonctionnent toujours.'
    Write-Host ''
    Write-Host '  Durée estimée : 3 à 10 minutes. Un redémarrage sera sans doute proposé à la fin.'
    Write-Host '  Annulation possible ensuite : Bureau > Durcissement-Sauvegarde > Annuler-Durcissement.bat'
    if (-not $script:Systeme.Windows11) {
        Write-Host ''
        Write-Host '  Attention : Windows 10 détecté. Le script fonctionne, mais il a été conçu pour Windows 11.' -ForegroundColor Yellow
    } elseif (-not $script:Systeme.Famille) {
        Write-Host ''
        Write-Host ('  Remarque : édition « {0} » détectée. Toutes les mesures restent compatibles.' -f $script:Systeme.Edition) -ForegroundColor Yellow
    }
    Write-Host ''
    Write-Host '  Appuyez sur Entrée pour continuer, ou fermez la fenêtre pour annuler.' -ForegroundColor Yellow
    [void](Read-Host)
}

# =====================================================================
#  PRÉPARATION : dossier, annulation, raccourci, point de restauration
# =====================================================================

function Initialize-Dossier {
    # Dossier modifiable uniquement par un administrateur (héritage des droits de Program Files)
    # et non protégé par l'accès contrôlé aux dossiers.
    $script:Dossier = Join-Path $env:ProgramFiles 'Durcissement-Sauvegarde'
    if (-not (Test-Path -LiteralPath $script:Dossier -PathType Container)) {
        New-Item -ItemType Directory -Path $script:Dossier -Force | Out-Null
    }
    $script:FichierSauvegarde = Join-Path $script:Dossier ('Sauvegarde-{0}.json' -f $script:Horodatage)
    $script:FichierJournal = Join-Path $script:Dossier ('Journal-{0}.log' -f $script:Horodatage)
    $script:FichierRapport = Join-Path $script:Dossier ('Rapport-{0}.html' -f $script:Horodatage)
    Save-Sauvegarde
    if (-not (Test-Path -LiteralPath $script:FichierSauvegarde)) { throw 'le fichier de sauvegarde n''a pas pu être créé' }
}

function Export-ScriptAnnulation {
    # Écrit (ou met à jour) Annuler-Durcissement.ps1 et son lanceur, AVANT toute modification.
    $ps1 = Join-Path $script:Dossier 'Annuler-Durcissement.ps1'
    $bat = Join-Path $script:Dossier 'Annuler-Durcissement.bat'
    [System.IO.File]::WriteAllText($ps1, $CodeAnnulation, $script:Utf8Bom)
    $lignesBat = @(
        '@echo off',
        'setlocal',
        'title Annulation du durcissement Windows',
        'rem Restaure les reglages d''origine sauvegardes par Durcissement-Windows.ps1.',
        'set "SCRIPT=%~dp0Annuler-Durcissement.ps1"',
        'if not exist "%SCRIPT%" (',
        '    echo Fichier introuvable : Annuler-Durcissement.ps1',
        '    pause',
        '    exit /b 1',
        ')',
        '"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%"',
        'endlocal'
    )
    [System.IO.File]::WriteAllText($bat, (($lignesBat -join "`r`n") + "`r`n"), (New-Object System.Text.ASCIIEncoding))
}

function New-RaccourciBureau {
    $lnk = Join-Path $script:Utilisateur.Bureau 'Durcissement-Sauvegarde.lnk'
    if (Test-Path -LiteralPath $lnk) {
        Write-Ligne -Statut 'OK' -Texte 'Raccourci « Durcissement-Sauvegarde » déjà présent sur le Bureau'
        return
    }
    try {
        # Créé avant l'activation de l'accès contrôlé aux dossiers, qui protège le Bureau.
        $wsh = New-Object -ComObject WScript.Shell
        $raccourci = $wsh.CreateShortcut($lnk)
        $raccourci.TargetPath = $script:Dossier
        $raccourci.Description = 'Rapports, sauvegardes et annulation du durcissement de Windows'
        $raccourci.Save()
        Write-Ligne -Statut 'OK' -Texte 'Raccourci « Durcissement-Sauvegarde » créé sur le Bureau'
    } catch {
        Write-Ligne -Statut 'ALERTE' -Texte ('Raccourci sur le Bureau impossible. Dossier : {0}' -f $script:Dossier)
    }
}

function Test-ProtectionSystemeActive {
    # $true / $false si l'information est lisible, $null sinon.
    try {
        $v = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SPP\Clients' -ErrorAction Stop).'{09F7EDC5-294E-4180-AF6A-FB0E6A0E9513}'
        $lettre = $env:SystemDrive.TrimEnd(':')
        return [bool](@($v) -match ('\({0}%3A\)' -f $lettre))
    } catch { return $null }
}

function New-PointRestauration {
    $cat = 'Préparation'
    $cleSR = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
    $frequenceExistait = $false
    $ancienneFrequence = $null
    try {
        $avant = Test-ProtectionSystemeActive
        try { Enable-ComputerRestore -Drive ('{0}\' -f $env:SystemDrive) -ErrorAction Stop } catch { }
        if ($avant -eq $false) {
            # Laissée active volontairement : la désactiver effacerait le point de restauration créé.
            Add-Resultat -Categorie $cat -Mesure 'Protection du système activée sur le disque système' -Statut 'INFO' -Detail 'nécessaire au point de restauration ; laissée active (la désactiver effacerait les points de restauration)'
        }
        if (-not (Test-Path -LiteralPath $cleSR)) { New-Item -Path $cleSR -Force | Out-Null }
        $k = Get-Item -LiteralPath $cleSR
        $frequenceExistait = @($k.GetValueNames()) -contains 'SystemRestorePointCreationFrequency'
        if ($frequenceExistait) { $ancienneFrequence = $k.GetValue('SystemRestorePointCreationFrequency') }
        # Lève temporairement la limite « un point par 24 h » (rétablie juste après).
        New-ItemProperty -LiteralPath $cleSR -Name 'SystemRestorePointCreationFrequency' -Value 0 -PropertyType DWord -Force | Out-Null
        Write-Patience 'création du point de restauration (jusqu''à 2 minutes)'
        Checkpoint-Computer -Description 'Avant durcissement Windows' -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop -WarningAction SilentlyContinue
        $dernier = Get-ComputerRestorePoint -ErrorAction SilentlyContinue | Sort-Object -Property SequenceNumber | Select-Object -Last 1
        $confirme = $false
        if ($dernier) {
            Add-Type -AssemblyName System.Management
            $date = [System.Management.ManagementDateTimeConverter]::ToDateTime($dernier.CreationTime)
            $confirme = ($date -gt $script:Debut.AddMinutes(-10))
        }
        if ($confirme) {
            Add-Resultat -Categorie $cat -Mesure 'Point de restauration système' -Statut 'OK' -Detail 'créé : « Avant durcissement Windows »'
        } else {
            Add-Resultat -Categorie $cat -Mesure 'Point de restauration système' -Statut 'ALERTE' -Detail 'création non confirmée — la sauvegarde propre au script reste disponible'
        }
    } catch {
        Add-Resultat -Categorie $cat -Mesure 'Point de restauration système' -Statut 'ALERTE' -Detail ('impossible ({0}) — la sauvegarde propre au script reste disponible' -f $_.Exception.Message)
    } finally {
        try {
            if ($frequenceExistait) {
                New-ItemProperty -LiteralPath $cleSR -Name 'SystemRestorePointCreationFrequency' -Value $ancienneFrequence -PropertyType DWord -Force | Out-Null
            } elseif (Test-Path -LiteralPath $cleSR) {
                Remove-ItemProperty -LiteralPath $cleSR -Name 'SystemRestorePointCreationFrequency' -ErrorAction SilentlyContinue
            }
        } catch { }
    }
}

# =====================================================================
#  DÉTECTION DES APPLICATIONS À PRÉSERVER (aucun chemin codé en dur)
# =====================================================================

function Get-CheminExecutable {
    # Extrait le chemin du programme d'une ligne de commande (« "C:\x\a.exe" -arg », « a.exe,0 »...).
    param([string]$Commande)
    if (-not $Commande) { return $null }
    $c = [Environment]::ExpandEnvironmentVariables($Commande.Trim())
    $candidat = $null
    if ($c.StartsWith('"')) {
        $fin = $c.IndexOf('"', 1)
        if ($fin -gt 1) { $candidat = $c.Substring(1, $fin - 1) }
    } else {
        $m = [regex]::Match($c, '^(.+?\.(exe|com|bat|cmd|vbs|vbe|js|jse|wsf|wsh|ps1|scr|pif|hta|dll|cpl|msi))(?=$|[\s,"])', 'IgnoreCase')
        if ($m.Success) { $candidat = $m.Groups[1].Value } else { $candidat = ($c -split '\s+')[0] }
    }
    if (-not $candidat) { return $null }
    $candidat = $candidat.Trim()
    $m2 = [regex]::Match($candidat, '^(.+\.(exe|dll|ico))\s*,\s*-?\d+$', 'IgnoreCase')
    if ($m2.Success) { $candidat = $m2.Groups[1].Value }
    if ($candidat -match '^\\(\?\?|\\\?)\\') { $candidat = $candidat.Substring(4) }
    $windows = $env:SystemRoot.TrimEnd('\')
    if ($candidat -match '^(?i)\\SystemRoot\\') { $candidat = $windows + $candidat.Substring(11) }
    if ($candidat -match '^(?i)system32\\') { $candidat = $windows + '\' + $candidat }
    if ($candidat -notmatch '^([A-Za-z]:\\|\\\\)') {
        # Nom sans chemin (« rundll32.exe ... ») : programme de Windows.
        $systeme = $windows + '\System32\' + $candidat
        if (Test-Path -LiteralPath $systeme -PathType Leaf) { return $systeme }
        if (Test-Path -LiteralPath ($systeme + '.exe') -PathType Leaf) { return ($systeme + '.exe') }
    }
    return $candidat
}

function Get-EntreesDesinstallation {
    $chemins = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    if ($script:Utilisateur.Ruche) {
        $chemins += ($script:Utilisateur.Ruche + '\Software\Microsoft\Windows\CurrentVersion\Uninstall\*')
    }
    $entrees = New-Object System.Collections.Generic.List[object]
    foreach ($c in $chemins) {
        foreach ($e in @(Get-ItemProperty -Path $c -ErrorAction SilentlyContinue)) {
            if ($e.PSObject.Properties['DisplayName'] -and $e.DisplayName) { $entrees.Add($e) }
        }
    }
    return $entrees.ToArray()
}

function Get-DossierDepuisEntree {
    param($Entree)
    foreach ($prop in 'InstallLocation', 'InstallPath', 'InstallDir') {
        if ($Entree.PSObject.Properties[$prop] -and $Entree.$prop) {
            $d = ([string]$Entree.$prop).Trim().Trim('"').TrimEnd('\')
            if ($d -and (Test-Path -LiteralPath $d -PathType Container)) { return $d }
        }
    }
    if ($Entree.PSObject.Properties['DisplayIcon'] -and $Entree.DisplayIcon) {
        $exe = Get-CheminExecutable -Commande ([string]$Entree.DisplayIcon)
        if ($exe -and (Test-Path -LiteralPath $exe -PathType Leaf)) { return (Split-Path -Path $exe -Parent) }
    }
    return $null
}

function Get-DossiersApplication {
    param([object[]]$Entrees, [string]$Motif, [string[]]$Replis)
    $liste = New-Object System.Collections.Generic.List[string]
    foreach ($e in $Entrees) {
        if ([string]$e.DisplayName -match $Motif) {
            $d = Get-DossierDepuisEntree -Entree $e
            if ($d) {
                # « ...\World of Warcraft\_retail_ » -> dossier racine du jeu
                if ((Split-Path -Path $d -Leaf) -match '^_[a-z_]+_$') { $d = Split-Path -Path $d -Parent }
                $liste.Add($d)
            }
        }
    }
    foreach ($r in $Replis) {
        if ($r -and (Test-Path -LiteralPath $r -PathType Container)) { $liste.Add($r.TrimEnd('\')) }
    }
    return @($liste | Sort-Object -Unique)
}

function Find-Executables {
    param([string]$Racine, [string[]]$Motifs, [int]$Profondeur)
    if (-not $Racine -or -not (Test-Path -LiteralPath $Racine -PathType Container)) { return @() }
    $trouves = New-Object System.Collections.Generic.List[string]
    foreach ($m in $Motifs) {
        foreach ($f in @(Get-ChildItem -LiteralPath $Racine -Filter $m -File -Recurse -Depth $Profondeur -ErrorAction SilentlyContinue)) {
            if ($f.Name -notmatch '(?i)unins|uninstall|setup|installer|update\.exe$') { $trouves.Add($f.FullName) }
        }
    }
    return @($trouves | Sort-Object -Unique)
}

function Get-MotifGenerique {
    # Remplace les dossiers de version (app-1.2.3, Base91418, Agent.9017...) par le joker *,
    # pour que l'autorisation survive aux mises à jour. Le nom du fichier n'est jamais remplacé.
    param([string]$Racine, [string]$Chemin)
    $base = $Racine.TrimEnd('\')
    if (-not $Chemin.StartsWith($base + '\', [StringComparison]::OrdinalIgnoreCase)) { return $Chemin }
    $segments = $Chemin.Substring($base.Length + 1).Split([char[]]@('\'))
    for ($i = 0; $i -lt $segments.Length - 1; $i++) {
        if ($segments[$i] -match '\d{3,}|\d+\.\d+') { $segments[$i] = '*' }
    }
    return ($base + '\' + ($segments -join '\'))
}

function Add-Application {
    param([string]$Application, [string]$Dossier, [string]$Executable, [bool]$Exclure, [bool]$PareFeu, [string]$Note = '')
    $motif = $Executable
    if ($Dossier -and $Executable) { $motif = Get-MotifGenerique -Racine $Dossier -Chemin $Executable }
    $script:Applications.Add([pscustomobject]@{
            Application = $Application
            Dossier     = $Dossier
            Executable  = $Executable
            Motif       = $motif
            Exclure     = $Exclure
            PareFeu     = $PareFeu
            Note        = $Note
        })
}

function Find-ApplicationsPreservees {
    $cat = 'Applications préservées'
    $pf86 = ${env:ProgramFiles(x86)}
    if (-not $pf86) { $pf86 = $env:ProgramFiles }
    $local = $script:Utilisateur.LocalAppData
    $entrees = @(Get-EntreesDesinstallation)

    $definitions = @(
        @{ Nom = 'Battle.net';          Motif = '^Battle\.net$';        Replis = @((Join-Path $pf86 'Battle.net'));                                      Exe = @('Battle.net*.exe', 'Blizzard*.exe');                Prof = 2; PareFeu = $true }
        @{ Nom = 'Blizzard Agent';      Motif = '^$';                   Replis = @((Join-Path $env:ProgramData 'Battle.net\Agent'));                     Exe = @('Agent.exe', 'Blizzard*.exe');                      Prof = 2; PareFeu = $false }
        @{ Nom = 'World of Warcraft';   Motif = '^World of Warcraft';   Replis = @((Join-Path $pf86 'World of Warcraft'));                               Exe = @('Wow*.exe', 'Blizzard*.exe');                       Prof = 2; PareFeu = $true }
        @{ Nom = 'Heroes of the Storm'; Motif = '^Heroes of the Storm'; Replis = @((Join-Path $pf86 'Heroes of the Storm'));                             Exe = @('HeroesOfTheStorm*.exe', 'HeroesSwitcher*.exe');    Prof = 3; PareFeu = $true }
        @{ Nom = 'Claude Desktop';      Motif = '^Claude$';             Replis = @((Join-Path $local 'AnthropicClaude'));                                Exe = @('claude.exe');                                      Prof = 2; PareFeu = $false }
        @{ Nom = 'CurseForge';          Motif = '^CurseForge';          Replis = @((Join-Path $local 'Programs\CurseForge Windows'));                    Exe = @('CurseForge*.exe');                                 Prof = 1; PareFeu = $false }
        @{ Nom = 'WowUp';               Motif = '^WowUp';               Replis = @((Join-Path $local 'Programs\WowUp-CF'), (Join-Path $local 'Programs\WowUp')); Exe = @('WowUp*.exe');                        Prof = 1; PareFeu = $false }
    )

    # Emplacement de World of Warcraft indiqué par Blizzard dans le registre.
    try {
        $wow = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\WOW6432Node\Blizzard Entertainment\World of Warcraft' -ErrorAction Stop
        if ($wow.PSObject.Properties['InstallPath'] -and $wow.InstallPath) {
            $p = ([string]$wow.InstallPath).TrimEnd('\')
            if ((Split-Path -Path $p -Leaf) -match '^_[a-z_]+_$') { $p = Split-Path -Path $p -Parent }
            $defWow = $definitions | Where-Object { $_.Nom -eq 'World of Warcraft' }
            $defWow.Replis += $p
        }
    } catch { }

    foreach ($def in $definitions) {
        Invoke-Protege -PCategorie $cat -PMesure $def.Nom -PAction {
            $dossiers = @(Get-DossiersApplication -Entrees $entrees -Motif $def.Motif -Replis $def.Replis)
            $nombre = 0
            foreach ($d in $dossiers) {
                foreach ($exe in @(Find-Executables -Racine $d -Motifs $def.Exe -Profondeur $def.Prof)) {
                    $pareFeu = $def.PareFeu -and ((Get-NomFichier -Chemin $exe) -match '^(?i)(Battle\.net.*|Wow.*|HeroesOfTheStorm.*)\.exe$')
                    Add-Application -Application $def.Nom -Dossier $d -Executable $exe -Exclure $true -PareFeu $pareFeu
                    $nombre++
                }
            }
            if ($nombre -gt 0) {
                Add-Resultat -Categorie $cat -Mesure $def.Nom -Statut 'INFO' -Detail ('{0} exécutable(s) détecté(s) dans {1}' -f $nombre, ($dossiers -join ' ; '))
            } else {
                Add-Resultat -Categorie $cat -Mesure $def.Nom -Statut 'INFO' -Detail 'non installé (rien à préserver)'
            }
        }
    }

    # Claude Desktop en paquet MSIX (WindowsApps), le cas échéant.
    try {
        $paquets = @(Get-AppxPackage -AllUsers -ErrorAction Stop | Where-Object { $_.Name -match '(?i)claude' -and $_.Publisher -match '(?i)anthropic' })
        foreach ($pq in $paquets) {
            $racine = Split-Path -Path ([string]$pq.InstallLocation) -Parent
            foreach ($exe in @(Find-Executables -Racine ([string]$pq.InstallLocation) -Motifs @('claude.exe') -Profondeur 3)) {
                Add-Application -Application 'Claude Desktop (MSIX)' -Dossier $racine -Executable $exe -Exclure $true -PareFeu $false
            }
        }
    } catch { }

    # Microsoft Edge, Edge Update et WebView2 : signés Microsoft, donc approuvés par défaut par Defender.
    # Aucune exclusion n'est ajoutée pour eux (elle n'apporterait rien et affaiblirait la protection).
    Invoke-Protege -PCategorie $cat -PMesure 'Microsoft Edge, Edge Update et WebView2' -PAction { Find-Edge -Pf86 $pf86 -Categorie $cat }

    # Ajouts manuels (liste en tête de script).
    foreach ($a in $AppsSupplementaires) {
        if ($a) { Add-Application -Application 'Ajout manuel' -Dossier '' -Executable ([string]$a) -Exclure $true -PareFeu $false }
    }
}

function Find-Edge {
    param([string]$Pf86, [string]$Categorie)
    $cat = $Categorie
    $pf86 = $Pf86
    $edge = $null
    try { $edge = [string](Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe' -ErrorAction Stop).'(default)' } catch { }
    if (-not $edge) { $edge = Join-Path $pf86 'Microsoft\Edge\Application\msedge.exe' }
    $edgeUpdate = $null
    try { $edgeUpdate = [string](Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate' -ErrorAction Stop).path } catch { }
    if (-not $edgeUpdate) { $edgeUpdate = Join-Path $pf86 'Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe' }
    $webView = $null
    try {
        $wv = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}' -ErrorAction Stop
        if ($wv.PSObject.Properties['location'] -and $wv.PSObject.Properties['pv']) {
            $webView = Join-Path (Join-Path ([string]$wv.location) ([string]$wv.pv)) 'msedgewebview2.exe'
        }
    } catch { }
    if (-not $webView -or -not (Test-Path -LiteralPath $webView)) {
        $webView = @(Get-ChildItem -LiteralPath (Join-Path $pf86 'Microsoft\EdgeWebView\Application') -Filter 'msedgewebview2.exe' -File -Recurse -Depth 1 -ErrorAction SilentlyContinue |
                Select-Object -First 1 -ExpandProperty FullName) | Select-Object -First 1
    }
    $trouves = @()
    foreach ($paire in @(@('Microsoft Edge', $edge), @('Microsoft Edge Update', $edgeUpdate), @('WebView2', $webView))) {
        if ($paire[1] -and (Test-Path -LiteralPath $paire[1] -PathType Leaf)) {
            Add-Application -Application $paire[0] -Dossier '' -Executable $paire[1] -Exclure $false -PareFeu $false -Note 'signé Microsoft : approuvé par défaut, aucune exclusion nécessaire'
            $trouves += $paire[0]
        }
    }
    if ($trouves.Count -gt 0) {
        Add-Resultat -Categorie $cat -Mesure 'Microsoft Edge, Edge Update et WebView2' -Statut 'INFO' -Detail ('détectés ({0}) — signés Microsoft, approuvés par défaut : aucune exclusion nécessaire' -f ($trouves -join ', '))
    } else {
        Add-Resultat -Categorie $cat -Mesure 'Microsoft Edge, Edge Update et WebView2' -Statut 'ALERTE' -Detail 'non trouvés aux emplacements habituels'
    }
}

# =====================================================================
#  1. MICROSOFT DEFENDER
# =====================================================================

function Format-ValeurDefender {
    param([string]$Nom, $Valeur)
    if ($null -eq $Valeur) { return 'non défini' }
    if ($Nom -like 'Disable*') { if ([bool]$Valeur) { return 'désactivé' } else { return 'actif' } }
    $table = $NomsValeursDefender[$Nom]
    if ($table -and $table.ContainsKey([string]$Valeur)) { return $table[[string]$Valeur] }
    return [string]$Valeur
}

function Set-PreferenceDefender {
    param(
        [string]$Nom,
        $Code,
        $NomValeur,
        [string]$Mesure,
        [string]$Attack = '',
        [object[]]$Ordre = @(),
        [string]$Impact = ''
    )
    $cat = 'Microsoft Defender'
    try {
        $actuel = (Get-MpPreference).$Nom
        $avant = Format-ValeurDefender -Nom $Nom -Valeur $actuel
        $dejaFait = ("$actuel" -eq "$Code")
        if (-not $dejaFait -and $Ordre.Count -gt 0 -and $null -ne $actuel) {
            $iActuel = [array]::IndexOf($Ordre, [int]$actuel)
            $iCible = [array]::IndexOf($Ordre, [int]$Code)
            if ($iActuel -ge 0 -and $iCible -ge 0 -and $iActuel -ge $iCible) { $dejaFait = $true }
        }
        if ($dejaFait) {
            Add-Resultat -Categorie $cat -Mesure $Mesure -Attack $Attack -Avant $avant -Apres $avant -Statut 'OK' -Detail 'déjà en place' -Impact $Impact
            return
        }
        Add-Sauvegarde -Cle ('MP|' + $Nom) -Element @{ Type = 'DefenderPreference'; Nom = $Nom; Valeur = $actuel }
        $parametres = @{ $Nom = $NomValeur }
        Set-MpPreference @parametres -ErrorAction Stop
        $nouveau = (Get-MpPreference).$Nom
        $apres = Format-ValeurDefender -Nom $Nom -Valeur $nouveau
        if ("$nouveau" -eq "$Code") {
            Add-Resultat -Categorie $cat -Mesure $Mesure -Attack $Attack -Avant $avant -Apres $apres -Statut 'OK' -Detail 'appliqué' -Impact $Impact
        } else {
            Add-Resultat -Categorie $cat -Mesure $Mesure -Attack $Attack -Avant $avant -Apres $apres -Statut 'ALERTE' -Detail 'refusé par Windows (protection contre les falsifications ou stratégie)' -Impact $Impact
        }
    } catch {
        Add-Resultat -Categorie $cat -Mesure $Mesure -Attack $Attack -Statut 'ECHEC' -Detail $_.Exception.Message -Impact $Impact
    }
}

function Set-ReglesAsr {
    $cat = 'Règles ASR'
    $pref = Get-MpPreference
    $existantes = @{}
    $ids = @()
    if ($pref.AttackSurfaceReductionRules_Ids) { $ids = @($pref.AttackSurfaceReductionRules_Ids) }
    $actions = @()
    if ($pref.AttackSurfaceReductionRules_Actions) { $actions = @($pref.AttackSurfaceReductionRules_Actions) }
    for ($i = 0; $i -lt $ids.Count; $i++) {
        if ($i -lt $actions.Count) { $existantes[([string]$ids[$i]).ToLowerInvariant()] = [int]$actions[$i] }
    }
    # Force croissante : désactivée / non configurée < audit < avertissement < blocage.
    $force = @{ 0 = 0; 5 = 0; 2 = 1; 6 = 2; 1 = 3 }
    $noms = @{ 0 = 'désactivée'; 1 = 'blocage'; 2 = 'audit'; 5 = 'non configurée'; 6 = 'avertissement' }
    $modifiees = @{}
    foreach ($r in $ReglesAsr) {
        $id = $r.Id.ToLowerInvariant()
        $cible = 1
        if ($r.Mode -eq 'Audit') { $cible = 2 }
        $avant = $null
        if ($existantes.ContainsKey($id)) { $avant = $existantes[$id] }
        $avantTexte = 'non configurée'
        if ($null -ne $avant -and $noms.ContainsKey($avant)) { $avantTexte = $noms[$avant] }
        if ($null -ne $avant -and $force.ContainsKey($avant) -and $force[$avant] -ge $force[$cible]) {
            Add-Resultat -Categorie $cat -Mesure $r.Libelle -Attack $r.Attack -Avant $avantTexte -Apres $avantTexte -Statut 'OK' -Detail 'déjà en place' -Impact $r.Impact
            continue
        }
        try {
            Add-Sauvegarde -Cle ('ASR|' + $id) -Element @{ Type = 'DefenderAsr'; Id = $id; Avant = $avant }
            $action = 'Enabled'
            if ($cible -eq 2) { $action = 'AuditMode' }
            # Règle déjà présente dans un mode plus faible : retirée puis remise dans le bon mode
            # (Add-MpPreference n'est documenté que pour ajouter, pas pour modifier).
            if ($null -ne $avant) { Remove-MpPreference -AttackSurfaceReductionRules_Ids $id -ErrorAction Stop }
            Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions $action -ErrorAction Stop
            $modifiees[$id] = $cible
            Add-Resultat -Categorie $cat -Mesure $r.Libelle -Attack $r.Attack -Avant $avantTexte -Apres $noms[$cible] -Statut 'OK' -Detail ('mode {0}' -f $noms[$cible]) -Impact $r.Impact
        } catch {
            Add-Resultat -Categorie $cat -Mesure $r.Libelle -Attack $r.Attack -Avant $avantTexte -Statut 'ECHEC' -Detail $_.Exception.Message -Impact $r.Impact
        }
    }
    # Contrôle : Windows a-t-il bien enregistré les règles modifiées ?
    if ($modifiees.Count -gt 0) {
        $pref = Get-MpPreference
        $ids = @()
        if ($pref.AttackSurfaceReductionRules_Ids) { $ids = @($pref.AttackSurfaceReductionRules_Ids) }
        $actions = @()
        if ($pref.AttackSurfaceReductionRules_Actions) { $actions = @($pref.AttackSurfaceReductionRules_Actions) }
        $lues = @{}
        for ($i = 0; $i -lt $ids.Count; $i++) {
            if ($i -lt $actions.Count) { $lues[([string]$ids[$i]).ToLowerInvariant()] = [int]$actions[$i] }
        }
        $ecarts = @($modifiees.Keys | Where-Object { -not $lues.ContainsKey($_) -or $lues[$_] -ne $modifiees[$_] })
        if ($ecarts.Count -gt 0) {
            Add-Resultat -Categorie $cat -Mesure 'Contrôle des règles ASR enregistrées' -Statut 'ALERTE' -Detail ('{0} règle(s) non prise(s) en compte par Windows' -f $ecarts.Count)
        }
    }
}

function Add-AutorisationsApplications {
    # Exclusions ASR ciblées + applications autorisées dans l'accès contrôlé aux dossiers.
    # Jamais d'exclusion antivirus complète (Add-MpPreference -ExclusionPath n'est pas utilisé).
    $cat = 'Microsoft Defender'
    $motifs = @($script:Applications | Where-Object { $_.Exclure -and $_.Motif } | ForEach-Object { $_.Motif } | Sort-Object -Unique)
    if ($motifs.Count -eq 0) {
        Add-Resultat -Categorie $cat -Mesure 'Exclusions ASR et applications autorisées' -Statut 'IGNORE' -Detail 'aucune application tierce à préserver détectée'
        return
    }
    $pref = Get-MpPreference
    $exclusions = @()
    if ($pref.AttackSurfaceReductionOnlyExclusions) { $exclusions = @($pref.AttackSurfaceReductionOnlyExclusions) }
    $autorisees = @()
    if ($pref.ControlledFolderAccessAllowedApplications) { $autorisees = @($pref.ControlledFolderAccessAllowedApplications) }
    $ajoutsAsr = 0
    $ajoutsCfa = 0
    $erreurs = @()
    foreach ($m in $motifs) {
        if ($exclusions -notcontains $m) {
            try {
                Add-Sauvegarde -Cle ('ASRX|' + $m) -Element @{ Type = 'DefenderAsrExclusion'; Chemin = $m }
                Add-MpPreference -AttackSurfaceReductionOnlyExclusions $m -ErrorAction Stop
                $ajoutsAsr++
            } catch { $erreurs += ('ASR {0} : {1}' -f $m, $_.Exception.Message) }
        }
        if ($autorisees -notcontains $m) {
            try {
                Add-Sauvegarde -Cle ('CFA|' + $m) -Element @{ Type = 'DefenderCfaApp'; Chemin = $m }
                Add-MpPreference -ControlledFolderAccessAllowedApplications $m -ErrorAction Stop
                $ajoutsCfa++
            } catch { $erreurs += ('Accès contrôlé {0} : {1}' -f $m, $_.Exception.Message) }
        }
    }
    $statut = 'OK'
    if ($erreurs.Count -gt 0) { $statut = 'ECHEC' }
    $detail = '{0} chemin(s) ajouté(s) ({1} autorisé(s) au total)' -f $ajoutsAsr, $motifs.Count
    if ($erreurs.Count -gt 0) { $detail += ' — ' + ($erreurs -join ' / ') }
    Add-Resultat -Categorie $cat -Mesure 'Exclusions ASR ciblées par exécutable (Battle.net, WoW, HotS, Claude...)' -Attack '' -Avant ('{0} exclusion(s)' -f $exclusions.Count) -Apres ('{0} exclusion(s)' -f ($exclusions.Count + $ajoutsAsr)) -Statut $statut -Detail $detail -Impact 'Les applications préservées ne sont pas bloquées par les règles ASR'
    $detail = '{0} chemin(s) ajouté(s)' -f $ajoutsCfa
    Add-Resultat -Categorie $cat -Mesure 'Applications autorisées dans l''accès contrôlé aux dossiers' -Attack '' -Avant ('{0} application(s)' -f $autorisees.Count) -Apres ('{0} application(s)' -f ($autorisees.Count + $ajoutsCfa)) -Statut $statut -Detail $detail -Impact 'HotS et Claude Desktop peuvent écrire dans Documents et sur le Bureau'
}

function Update-SignaturesDefender {
    $cat = 'Microsoft Defender'
    Write-Patience 'mise à jour des signatures antivirus (jusqu''à 3 minutes)'
    $job = Start-Job -ScriptBlock { Update-MpSignature -ErrorAction Stop }
    $fini = Wait-Job -Job $job -Timeout 180
    if (-not $fini) {
        Stop-Job -Job $job
        Remove-Job -Job $job -Force
        Add-Resultat -Categorie $cat -Mesure 'Mise à jour des signatures' -Attack 'T1204.002' -Statut 'ALERTE' -Detail 'délai dépassé : Windows Update s''en chargera'
        return
    }
    $erreur = $null
    try { Receive-Job -Job $job -ErrorAction Stop | Out-Null } catch { $erreur = $_.Exception.Message }
    Remove-Job -Job $job -Force
    $s = Get-MpComputerStatus
    $detail = 'signatures {0} du {1}' -f $s.AntivirusSignatureVersion, $s.AntivirusSignatureLastUpdated.ToString('dd/MM/yyyy HH:mm')
    if ($erreur) {
        Add-Resultat -Categorie $cat -Mesure 'Mise à jour des signatures' -Attack 'T1204.002' -Statut 'ALERTE' -Detail ('échec ({0}) — {1}' -f $erreur, $detail)
    } else {
        Add-Resultat -Categorie $cat -Mesure 'Mise à jour des signatures' -Attack 'T1204.002' -Statut 'OK' -Detail $detail
    }
}

function Set-DurcissementDefender {
    $cat = 'Microsoft Defender'
    $statut = $null
    try { $statut = Get-MpComputerStatus -ErrorAction Stop } catch { $statut = $null }
    $mode = ''
    if ($statut -and $statut.PSObject.Properties['AMRunningMode']) { $mode = [string]$statut.AMRunningMode }
    if (-not $statut -or ($mode -and $mode -ne 'Normal')) {
        # Un autre antivirus est actif : ASR, accès contrôlé et protection réseau exigent Defender actif.
        $autres = @()
        try {
            $autres = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop |
                    Where-Object { $_.displayName -notmatch 'Defender' } | ForEach-Object { [string]$_.displayName })
        } catch { }
        $detail = 'Microsoft Defender n''est pas l''antivirus actif'
        if ($mode) { $detail += (' (mode : {0})' -f $mode) }
        if ($autres.Count -gt 0) { $detail += (' — antivirus détecté : {0}' -f ($autres -join ', ')) }
        Add-Resultat -Categorie $cat -Mesure 'Mesures Microsoft Defender (antivirus, règles ASR, accès contrôlé aux dossiers)' -Attack 'T1562.001' -Statut 'IGNORE' -Detail ($detail + '. Ces protections exigent Defender actif.')
        $script:DefenderActif = $false
        return
    }
    $script:DefenderActif = $true

    # Protection en temps réel, cloud, PUA, protection réseau — T1204.002, T1562.001, T1566.002
    foreach ($p in $PreferencesDefender) { Set-PreferenceDefender @p }

    # Règles ASR — voir les ID ATT&CK dans $ReglesAsr
    Invoke-Protege -PCategorie 'Règles ASR' -PMesure 'Règles ASR' -PAction { Set-ReglesAsr }

    # Exclusions ASR et applications autorisées, AVANT d'activer l'accès contrôlé aux dossiers.
    Invoke-Protege -PCategorie $cat -PMesure 'Exclusions ASR et applications autorisées' -PAction { Add-AutorisationsApplications }

    # Accès contrôlé aux dossiers (anti-rançongiciel) — T1486
    Set-PreferenceDefender -Nom 'EnableControlledFolderAccess' -Code 1 -NomValeur 'Enabled' -Mesure 'Accès contrôlé aux dossiers (anti-rançongiciel)' -Attack 'T1486' -Ordre @(0, 4, 2, 3, 1) -Impact 'Un programme non approuvé ne peut plus écrire dans Documents, Images, Bureau... (notification Windows)'

    Invoke-Protege -PCategorie $cat -PMesure 'Mise à jour des signatures' -PAction { Update-SignaturesDefender }
}

# =====================================================================
#  2. PROTECTION CONTRE LES FALSIFICATIONS — T1562.001
# =====================================================================

function Test-ProtectionFalsification {
    $cat = 'Microsoft Defender'
    if (-not $script:DefenderActif) {
        Add-Resultat -Categorie $cat -Mesure 'Protection contre les falsifications' -Attack 'T1562.001' -Statut 'IGNORE' -Detail 'Microsoft Defender n''est pas l''antivirus actif'
        return
    }
    try {
        $s = Get-MpComputerStatus -ErrorAction Stop
        if ($s.IsTamperProtected) {
            Add-Resultat -Categorie $cat -Mesure 'Protection contre les falsifications' -Attack 'T1562.001' -Avant 'activée' -Apres 'activée' -Statut 'OK' -Detail 'activée'
        } else {
            Add-Resultat -Categorie $cat -Mesure 'Protection contre les falsifications' -Attack 'T1562.001' -Avant 'désactivée' -Apres 'désactivée' -Statut 'ALERTE' -Detail 'DÉSACTIVÉE : Sécurité Windows > Protection contre les virus et menaces > Gérer les paramètres > Protection contre les falsifications : Activé (aucun script ne peut le faire à votre place)'
        }
    } catch {
        Add-Resultat -Categorie $cat -Mesure 'Protection contre les falsifications' -Attack 'T1562.001' -Statut 'ECHEC' -Detail $_.Exception.Message
    }
}

# =====================================================================
#  3. PARE-FEU — T1021, T1210 (services distants), T1046
# =====================================================================

function New-ReglesPareFeuApplications {
    # Règles entrantes « Hardening-Allow- » : exécutables détectés, profil Privé uniquement.
    $cat = 'Pare-feu'
    $exes = @($script:Applications | Where-Object { $_.PareFeu -and $_.Executable } | ForEach-Object { $_.Executable } | Sort-Object -Unique)
    if ($exes.Count -eq 0) {
        Add-Resultat -Categorie $cat -Mesure 'Règles entrantes « Hardening-Allow- » (jeux, réseau privé)' -Statut 'IGNORE' -Detail 'aucun exécutable Battle.net, WoW ou HotS détecté'
        return
    }
    $crees = 0
    $deja = 0
    $erreurs = @()
    foreach ($exe in $exes) {
        $base = ((Get-NomFichier -Chemin $exe) -replace '(?i)\.exe$', '') -replace '[^A-Za-z0-9._-]', '_'
        $nom = 'Hardening-Allow-{0}-{1}' -f $base, (Get-Empreinte -Texte $exe)
        try {
            if (Get-NetFirewallRule -Name $nom -ErrorAction SilentlyContinue) { $deja++; continue }
            New-NetFirewallRule -Name $nom -DisplayName ('Hardening-Allow - {0}' -f (Get-NomFichier -Chemin $exe)) -Group 'Durcissement Windows' `
                -Description ('Autorise {0} en entrant, sur les réseaux privés uniquement (Durcissement-Windows.ps1).' -f $exe) `
                -Direction Inbound -Action Allow -Program $exe -Profile Private -Enabled True -ErrorAction Stop | Out-Null
            Add-Sauvegarde -Cle ('FWR|' + $nom) -Element @{ Type = 'PareFeuRegle'; Nom = $nom }
            $crees++
        } catch { $erreurs += ('{0} : {1}' -f (Get-NomFichier -Chemin $exe), $_.Exception.Message) }
    }
    $statut = 'OK'
    $detail = '{0} créée(s), {1} déjà présente(s)' -f $crees, $deja
    if ($erreurs.Count -gt 0) { $statut = 'ECHEC'; $detail += ' — ' + ($erreurs -join ' / ') }
    Add-Resultat -Categorie $cat -Mesure 'Règles entrantes « Hardening-Allow- » (jeux, réseau privé)' -Statut $statut -Detail $detail -Impact 'Battle.net, WoW et HotS joignables en entrant sur un réseau Privé seulement'
}

function Set-DurcissementPareFeu {
    $cat = 'Pare-feu'
    # Cibles : profil actif, entrant bloqué par défaut, notification, journal des paquets bloqués.
    # Le trafic sortant n'est jamais restreint.
    $cibles = [ordered]@{ Enabled = 'True'; DefaultInboundAction = 'Block'; NotifyOnListen = 'True'; LogBlocked = 'True' }
    $profils = @()
    try { $profils = @(Get-NetFirewallProfile -ErrorAction Stop) } catch {
        Add-Resultat -Categorie $cat -Mesure 'Profils du pare-feu' -Attack 'T1021, T1210' -Statut 'ECHEC' -Detail $_.Exception.Message
    }
    foreach ($profil in $profils) {
        $nom = [string]$profil.Name
        try {
            $avant = [ordered]@{
                Enabled               = [string]$profil.Enabled
                DefaultInboundAction  = [string]$profil.DefaultInboundAction
                DefaultOutboundAction = [string]$profil.DefaultOutboundAction
                NotifyOnListen        = [string]$profil.NotifyOnListen
                LogBlocked            = [string]$profil.LogBlocked
                LogAllowed            = [string]$profil.LogAllowed
                LogMaxSizeKilobytes   = [int64]$profil.LogMaxSizeKilobytes
            }
            $parametres = @{}
            foreach ($k in $cibles.Keys) { if ($avant[$k] -ne $cibles[$k]) { $parametres[$k] = $cibles[$k] } }
            if ($avant.LogMaxSizeKilobytes -lt 16384) { $parametres['LogMaxSizeKilobytes'] = 16384 }
            $texteAvant = 'actif={0} ; entrant={1} ; sortant={2} ; journal={3}' -f $avant.Enabled, $avant.DefaultInboundAction, $avant.DefaultOutboundAction, $avant.LogBlocked
            $mesure = 'Profil {0} : actif, entrant bloqué par défaut, journalisation' -f $nom
            if ($parametres.Count -eq 0) {
                Add-Resultat -Categorie $cat -Mesure $mesure -Attack 'T1021, T1210' -Avant $texteAvant -Apres $texteAvant -Statut 'OK' -Detail 'déjà en place' -Impact 'Aucun (comportement par défaut de Windows)'
                continue
            }
            Add-Sauvegarde -Cle ('FW|' + $nom) -Element @{ Type = 'PareFeuProfil'; Profil = $nom; Parametres = $avant }
            Set-NetFirewallProfile -Name $nom @parametres -ErrorAction Stop
            $texteApres = 'actif=True ; entrant=Block ; sortant={0} ; journal=True' -f $avant.DefaultOutboundAction
            Add-Resultat -Categorie $cat -Mesure $mesure -Attack 'T1021, T1210' -Avant $texteAvant -Apres $texteApres -Statut 'OK' -Detail 'appliqué' -Impact 'Aucun (comportement par défaut de Windows, journal en plus)'
            if ($avant.DefaultOutboundAction -eq 'Block') {
                Add-Resultat -Categorie $cat -Mesure ('Profil {0} : trafic sortant' -f $nom) -Statut 'ALERTE' -Detail 'le sortant est bloqué par défaut (réglage existant, non modifié) : vérifiez les règles de Battle.net et de Claude'
            }
        } catch {
            Add-Resultat -Categorie $cat -Mesure ('Profil {0}' -f $nom) -Attack 'T1021, T1210' -Statut 'ECHEC' -Detail $_.Exception.Message
        }
    }
    Invoke-Protege -PCategorie $cat -PMesure 'Règles entrantes « Hardening-Allow- »' -PAction { New-ReglesPareFeuApplications }
}

# =====================================================================
#  4. PROTOCOLES ANCIENS ET RISQUÉS
# =====================================================================

function Set-DurcissementProtocoles {
    $cat = 'Protocoles'

    # SMBv1 — T1210 (exploitation de services distants, type EternalBlue)
    Disable-Fonctionnalite -Nom 'SMB1Protocol' -Categorie $cat -Mesure 'Désactiver SMBv1' -Attack 'T1210' -Impact 'NAS ou imprimantes très anciens (SMBv1) inaccessibles'

    # LLMNR — T1557.001 (empoisonnement LLMNR/NBT-NS, outils de type Responder)
    Invoke-MesureRegistre -Categorie $cat -Mesure 'Désactiver LLMNR' -Attack 'T1557.001' -Impact 'Appareils du réseau local résolus par DNS ou mDNS uniquement' -Valeurs @(
        @{ Chemin = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'; Nom = 'EnableMulticast'; Valeur = 0 }
    )

    # NetBIOS sur TCP/IP — T1557.001 (NBT-NS), T1046
    $valeurs = @()
    foreach ($i in @(Get-ChildItem -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction SilentlyContinue)) {
        if ($i.PSChildName -like 'Tcpip_*') {
            $valeurs += @{ Chemin = ('HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\' + $i.PSChildName); Nom = 'NetbiosOptions'; Valeur = 2 }
        }
    }
    if ($valeurs.Count -gt 0) {
        Invoke-MesureRegistre -Categorie $cat -Mesure ('Désactiver NetBIOS sur TCP/IP ({0} carte(s) réseau)' -f $valeurs.Count) -Attack 'T1557.001' -Impact 'Très vieux NAS accessibles uniquement par nom NetBIOS ; une carte réseau ajoutée plus tard garde le réglage par défaut (relancez le script)' -Valeurs $valeurs -Redemarrage
    } else {
        Add-Resultat -Categorie $cat -Mesure 'Désactiver NetBIOS sur TCP/IP' -Attack 'T1557.001' -Statut 'IGNORE' -Detail 'aucune carte réseau concernée'
    }

    # WPAD (détection automatique de proxy de WinHTTP) — T1557.001
    Invoke-MesureRegistre -Categorie $cat -Mesure 'Désactiver WPAD (WinHTTP)' -Attack 'T1557.001' -Impact 'Aucun (pas de proxy automatique à la maison)' -Valeurs @(
        @{ Chemin = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp'; Nom = 'DisableWpad'; Valeur = 1 }
    )

    # PowerShell 2.0 (contournement de la journalisation et d'AMSI) — T1059.001, T1562.010
    Disable-Fonctionnalite -Nom 'MicrosoftWindowsPowerShellV2Root' -Categorie $cat -Mesure 'Désactiver PowerShell 2.0' -Attack 'T1059.001, T1562.010' -Impact 'Aucun'

    # WinRM (administration à distance) — T1021.006
    Set-ServiceDesactive -Nom 'WinRM' -Categorie $cat -Mesure 'Désactiver le service WinRM' -Attack 'T1021.006' -Impact 'PowerShell à distance indisponible (inutile à la maison)'
    Invoke-MesureRegistre -Categorie $cat -Mesure 'Durcir WinRM (pas d''authentification Basic ni Digest, pas de trafic en clair)' -Attack 'T1021.006, T1557' -Impact 'Aucun' -Valeurs @(
        @{ Chemin = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'; Nom = 'AllowBasic'; Valeur = 0 }
        @{ Chemin = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'; Nom = 'AllowUnencryptedTraffic'; Valeur = 0 }
        @{ Chemin = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'; Nom = 'AllowDigest'; Valeur = 0 }
        @{ Chemin = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'; Nom = 'AllowBasic'; Valeur = 0 }
        @{ Chemin = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'; Nom = 'AllowUnencryptedTraffic'; Valeur = 0 }
        @{ Chemin = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'; Nom = 'DisableRunAs'; Valeur = 1 }
    )

    # Assistance à distance Windows (msra) — T1021, T1219
    Invoke-MesureRegistre -Categorie $cat -Mesure 'Désactiver l''Assistance à distance Windows' -Attack 'T1021, T1219' -Impact 'Assistance à distance (msra) coupée ; l''Assistance rapide reste disponible' -Valeurs @(
        @{ Chemin = 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance'; Nom = 'fAllowToGetHelp'; Valeur = 0 }
        @{ Chemin = 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance'; Nom = 'fAllowFullControl'; Valeur = 0 }
    )
}

# =====================================================================
#  5. IDENTIFIANTS
# =====================================================================

function Set-DurcissementIdentifiants {
    $cat = 'Identifiants'
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'

    # Protection LSA (LSASS en processus protégé) — T1003.001
    $ppl = $null
    try { $ppl = (Get-ItemProperty -LiteralPath $lsa -ErrorAction Stop).RunAsPPL } catch { }
    if ($ppl -eq 1 -or $ppl -eq 2) {
        Add-Resultat -Categorie $cat -Mesure 'Protection LSA (RunAsPPL)' -Attack 'T1003.001' -Avant ('RunAsPPL={0}' -f $ppl) -Apres ('RunAsPPL={0}' -f $ppl) -Statut 'OK' -Detail 'déjà en place'
    } elseif ($script:Systeme.Build -ge 22621) {
        # Valeur 2 : activée sans verrou UEFI, donc réversible par le script d'annulation.
        Invoke-MesureRegistre -Categorie $cat -Mesure 'Protection LSA (RunAsPPL)' -Attack 'T1003.001' -Impact 'Rares pilotes ou modules de sécurité anciens incompatibles (signalés par Sécurité Windows)' -Valeurs @(
            @{ Chemin = $lsa; Nom = 'RunAsPPL'; Valeur = 2 }
        ) -Redemarrage
    } else {
        Add-Resultat -Categorie $cat -Mesure 'Protection LSA (RunAsPPL)' -Attack 'T1003.001' -Statut 'IGNORE' -Detail 'nécessite Windows 11 22H2 ou plus récent : mettez Windows à jour'
    }

    # WDigest : pas de mot de passe en clair en mémoire — T1003.001
    Invoke-MesureRegistre -Categorie $cat -Mesure 'Désactiver WDigest (mots de passe en clair en mémoire)' -Attack 'T1003.001' -Impact 'Aucun' -Valeurs @(
        @{ Chemin = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'; Nom = 'UseLogonCredential'; Valeur = 0 }
    )

    # NTLM : NTLMv2 uniquement, sécurité de session 128 bits, pas d'empreinte LM — T1557.001, T1110.002, T1550.002
    Invoke-MesureRegistre -Categorie $cat -Mesure 'Restreindre NTLM (NTLMv2 seul, session 128 bits, pas de hachage LM)' -Attack 'T1557.001, T1110.002, T1550.002' -Impact 'NAS très anciens limités à LM ou NTLMv1 inaccessibles' -Valeurs @(
        @{ Chemin = $lsa; Nom = 'LmCompatibilityLevel'; Valeur = 5 }
        @{ Chemin = $lsa; Nom = 'NoLMHash'; Valeur = 1 }
        @{ Chemin = ($lsa + '\MSV1_0'); Nom = 'NTLMMinClientSec'; Valeur = 537395200 }
        @{ Chemin = ($lsa + '\MSV1_0'); Nom = 'NTLMMinServerSec'; Valeur = 537395200 }
    )

    # Cache des identifiants : ne concerne que les comptes de domaine — T1003.005
    Add-Resultat -Categorie $cat -Mesure 'Limiter le cache des identifiants (CachedLogonsCount)' -Attack 'T1003.005' -Statut 'IGNORE' -Detail 'concerne les comptes de domaine ; un PC Famille ne peut pas rejoindre un domaine (le réduire pourrait bloquer la connexion hors ligne d''un compte Microsoft)'
}

# =====================================================================
#  6. EXÉCUTION DE SCRIPTS
# =====================================================================

function Set-DurcissementExecution {
    $cat = 'Exécution'

    # Journalisation des blocs de script PowerShell (5.1 et 7) — T1059.001
    Invoke-MesureRegistre -Categorie $cat -Mesure 'Journaliser les blocs de script PowerShell' -Attack 'T1059.001' -Impact 'Journaux un peu plus volumineux' -Valeurs @(
        @{ Chemin = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Nom = 'EnableScriptBlockLogging'; Valeur = 1 }
        @{ Chemin = 'HKLM:\SOFTWARE\Policies\Microsoft\PowerShellCore\ScriptBlockLogging'; Nom = 'EnableScriptBlockLogging'; Valeur = 1 }
    )

    # Journalisation des modules PowerShell — T1059.001
    Invoke-MesureRegistre -Categorie $cat -Mesure 'Journaliser les modules PowerShell' -Attack 'T1059.001' -Impact 'Journaux un peu plus volumineux' -Valeurs @(
        @{ Chemin = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'; Nom = 'EnableModuleLogging'; Valeur = 1 }
        @{ Chemin = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames'; Nom = '*'; Valeur = '*'; Type = 'String' }
    )

    # Hôte Windows Script (wscript/cscript : .vbs, .js) — T1059.005, T1059.007
    Invoke-MesureRegistre -Categorie $cat -Mesure 'Désactiver l''hôte Windows Script (wscript, cscript)' -Attack 'T1059.005, T1059.007' -Impact 'Les fichiers .vbs et .js ne s''exécutent plus (vieux installeurs, utilitaires constructeur)' -Valeurs @(
        @{ Chemin = 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings'; Nom = 'Enabled'; Valeur = 0 }
        @{ Chemin = 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings'; Nom = 'IgnoreUserSettings'; Valeur = 1 }
        @{ Chemin = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows Script Host\Settings'; Nom = 'Enabled'; Valeur = 0 }
        @{ Chemin = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows Script Host\Settings'; Nom = 'IgnoreUserSettings'; Valeur = 1 }
    )

    # Macros Office des fichiers venant d'Internet — T1566.001, T1204.002
    $office = (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration') -or
    (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Office\16.0\Common\InstallRoot') -or
    (Test-Path -LiteralPath 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\16.0\Common\InstallRoot')
    if (-not $office) {
        Add-Resultat -Categorie $cat -Mesure 'Bloquer les macros Office venant d''Internet' -Attack 'T1566.001, T1204.002' -Statut 'IGNORE' -Detail 'Microsoft Office non détecté'
    } elseif (-not $script:Utilisateur.Ruche) {
        Add-Resultat -Categorie $cat -Mesure 'Bloquer les macros Office venant d''Internet' -Attack 'T1566.001, T1204.002' -Statut 'IGNORE' -Detail 'profil de l''utilisateur connecté inaccessible'
    } else {
        $valeurs = @()
        foreach ($app in 'word', 'excel', 'powerpoint', 'visio', 'access') {
            $valeurs += @{ Chemin = ('{0}\Software\Policies\Microsoft\Office\16.0\{1}\Security' -f $script:Utilisateur.Ruche, $app); Nom = 'blockcontentexecutionfrominternet'; Valeur = 1 }
        }
        Invoke-MesureRegistre -Categorie $cat -Mesure 'Bloquer les macros Office venant d''Internet' -Attack 'T1566.001, T1204.002' -Impact 'Macros des fichiers Office téléchargés bloquées (déjà le défaut des versions récentes)' -Valeurs $valeurs
    }
}

# =====================================================================
#  7. PERSISTANCE (audit seul : rien n'est supprimé)
# =====================================================================

function Get-InfoSignature {
    param([string]$Fichier)
    if (-not $Fichier -or $Fichier.Contains('*') -or -not (Test-Path -LiteralPath $Fichier -PathType Leaf)) {
        return [pscustomobject]@{ Statut = 'Introuvable'; Signataire = '' }
    }
    try {
        $s = Get-AuthenticodeSignature -LiteralPath $Fichier -ErrorAction Stop
        $nom = ''
        if ($s.SignerCertificate) { $nom = $s.SignerCertificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) }
        return [pscustomobject]@{ Statut = [string]$s.Status; Signataire = [string]$nom }
    } catch {
        return [pscustomobject]@{ Statut = 'Erreur'; Signataire = '' }
    }
}

function Test-CommandeSuspecte {
    # Renvoie la règle déclenchée (niveau + raison), ou $null.
    param([string]$Commande)
    if (-not $Commande) { return $null }
    $c = $Commande.ToLowerInvariant()
    $regles = @(
        @{ Motif = '\s-e(nc|ncodedcommand|c)?\s+[a-z0-9+/=]{16,}'; Niveau = 'SUSPECT'; Raison = 'commande PowerShell encodée en Base64 (T1027)' }
        @{ Motif = 'frombase64string|\biex\b|invoke-expression|downloadstring|downloadfile|net\.webclient|invoke-webrequest|\biwr\b|start-bitstransfer'; Niveau = 'SUSPECT'; Raison = 'téléchargement ou exécution de code dynamique (T1059.001, T1105)' }
        @{ Motif = '\bmshta(\.exe)?\b|\bregsvr32(\.exe)?\b.*(/i:|scrobj)|\brundll32(\.exe)?\b.*(javascript:|https?:)'; Niveau = 'SUSPECT'; Raison = 'détournement d''un binaire Windows (LOLBin, T1218)' }
        @{ Motif = '\bcertutil(\.exe)?\b.*(-urlcache|-decode)|\bbitsadmin(\.exe)?\b.*/transfer'; Niveau = 'SUSPECT'; Raison = 'téléchargement par un outil Windows (T1105)' }
        @{ Motif = '\\appdata\\local\\temp\\|\\windows\\temp\\|\\users\\public\\|\\\$recycle\.bin|\\perflogs\\'; Niveau = 'SUSPECT'; Raison = 'lancé depuis un dossier temporaire ou public (T1036)' }
        @{ Motif = '\b(wscript|cscript)(\.exe)?\b.*\.(vbs|vbe|js|jse|wsf)\b'; Niveau = 'A_VERIFIER'; Raison = 'script Windows Script Host au démarrage (T1059.005)' }
        @{ Motif = '\s-w(indowstyle)?\s+h(idden)?\b'; Niveau = 'A_VERIFIER'; Raison = 'fenêtre PowerShell masquée (T1564.003)' }
        @{ Motif = 'https?://'; Niveau = 'A_VERIFIER'; Raison = 'adresse Internet dans la commande' }
    )
    foreach ($r in $regles) { if ($c -match $r.Motif) { return $r } }
    return $null
}

function Test-CheminNonCite {
    # Chemin de service avec espaces et sans guillemets : détournement possible (T1574.009).
    param([string]$Chemin)
    if (-not $Chemin) { return $false }
    $p = $Chemin.Trim()
    if ($p.StartsWith('"')) { return $false }
    $m = [regex]::Match($p, '^(.+?\.exe)', 'IgnoreCase')
    if (-not $m.Success) { return $false }
    return ($m.Groups[1].Value -match '\s')
}

function Add-Persistance {
    param(
        [string]$Groupe,
        [string]$Emplacement,
        [string]$Nom,
        [string]$Commande,
        [string]$Fichier,
        [string]$Evaluation = '',
        [string]$Raison = '',
        [switch]$PassThru
    )
    $sig = Get-InfoSignature -Fichier $Fichier
    if (-not $Evaluation) {
        $regle = Test-CommandeSuspecte -Commande $Commande
        if ($regle) { $Evaluation = $regle.Niveau; $Raison = $regle.Raison }
        elseif ($sig.Statut -eq 'Introuvable') { $Evaluation = 'A_VERIFIER'; $Raison = 'fichier cible introuvable (entrée orpheline ou chemin non reconnu)' }
        elseif ($sig.Statut -ne 'Valid') { $Evaluation = 'A_VERIFIER'; $Raison = ('signature : {0}' -f $sig.Statut) }
        elseif ($sig.Signataire -match '(?i)microsoft|blizzard|anthropic') { $Evaluation = 'CONNUE'; $Raison = 'éditeur reconnu (Microsoft, Blizzard ou Anthropic)' }
        else { $Evaluation = 'OK'; $Raison = 'signé par un éditeur tiers' }
    }
    $objet = [pscustomobject]@{
        Groupe      = $Groupe
        Emplacement = $Emplacement
        Nom         = $Nom
        Commande    = $Commande
        Signataire  = $sig.Signataire
        Signature   = $sig.Statut
        Evaluation  = $Evaluation
        Raison      = $Raison
    }
    $script:Persistance.Add($objet)
    if ($PassThru) { return $objet }
}

function Test-Persistance {
    $cat = 'Persistance'
    Write-Patience 'inventaire des programmes au démarrage, tâches, services et abonnements WMI'

    # Clés Run / RunOnce — T1547.001
    Invoke-Protege -PCategorie $cat -PMesure 'Inventaire des clés Run' -PAction {
        $cles = @(
            @{ Chemin = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; Libelle = 'Run (ordinateur)' }
            @{ Chemin = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'; Libelle = 'RunOnce (ordinateur)' }
            @{ Chemin = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'; Libelle = 'Run (ordinateur, 32 bits)' }
            @{ Chemin = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'; Libelle = 'RunOnce (ordinateur, 32 bits)' }
        )
        if ($script:Utilisateur.Ruche) {
            $cles += @{ Chemin = ($script:Utilisateur.Ruche + '\Software\Microsoft\Windows\CurrentVersion\Run'); Libelle = 'Run (utilisateur)' }
            $cles += @{ Chemin = ($script:Utilisateur.Ruche + '\Software\Microsoft\Windows\CurrentVersion\RunOnce'); Libelle = 'RunOnce (utilisateur)' }
        }
        foreach ($c in $cles) {
            $cle = Get-Item -LiteralPath $c.Chemin -ErrorAction SilentlyContinue
            if (-not $cle) { continue }
            foreach ($n in @($cle.GetValueNames())) {
                if (-not $n) { continue }
                $commande = [string]$cle.GetValue($n)
                Add-Persistance -Groupe 'DEMARRAGE' -Emplacement $c.Libelle -Nom $n -Commande $commande -Fichier (Get-CheminExecutable -Commande $commande)
            }
        }
    }

    # Dossiers Démarrage (utilisateur et tous les utilisateurs) — T1547.001
    Invoke-Protege -PCategorie $cat -PMesure 'Inventaire des dossiers Démarrage' -PAction {
        $wsh = $null
        try { $wsh = New-Object -ComObject WScript.Shell } catch { $wsh = $null }
        $dossiersDemarrage = @($script:Utilisateur.Demarrage, ($env:ProgramData + '\Microsoft\Windows\Start Menu\Programs\StartUp'))
        foreach ($dossierDemarrage in $dossiersDemarrage) {
            if (-not $dossierDemarrage -or -not (Test-Path -LiteralPath $dossierDemarrage)) { continue }
            foreach ($f in @(Get-ChildItem -LiteralPath $dossierDemarrage -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' })) {
                $commande = $f.FullName
                $cible = $f.FullName
                if ($f.Extension -ieq '.lnk' -and $wsh) {
                    try {
                        $l = $wsh.CreateShortcut($f.FullName)
                        $cible = [string]$l.TargetPath
                        $commande = ('"{0}" {1}' -f $l.TargetPath, $l.Arguments).Trim()
                    } catch { }
                }
                Add-Persistance -Groupe 'DEMARRAGE' -Emplacement 'Dossier Démarrage' -Nom $f.Name -Commande $commande -Fichier $cible
            }
        }
    }

    # Tâches planifiées hors Microsoft — T1053.005
    Invoke-Protege -PCategorie $cat -PMesure 'Inventaire des tâches planifiées' -PAction {
        foreach ($t in @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_ -and $_.TaskPath -notlike '\Microsoft\*' })) {
            foreach ($a in @($t.Actions)) {
                if (-not $a) { continue }
                if ($a.PSObject.Properties['Execute'] -and $a.Execute) {
                    $arguments = ''
                    if ($a.PSObject.Properties['Arguments'] -and $a.Arguments) { $arguments = [string]$a.Arguments }
                    $commande = ('"{0}" {1}' -f ([string]$a.Execute).Trim('"'), $arguments).Trim()
                    Add-Persistance -Groupe 'TACHES' -Emplacement 'Tâche planifiée' -Nom ($t.TaskPath + $t.TaskName) -Commande $commande -Fichier (Get-CheminExecutable -Commande $commande)
                } elseif ($a.PSObject.Properties['ClassId'] -and $a.ClassId) {
                    Add-Persistance -Groupe 'TACHES' -Emplacement 'Tâche planifiée (COM)' -Nom ($t.TaskPath + $t.TaskName) -Commande ('Objet COM ' + [string]$a.ClassId) -Fichier $null -Evaluation 'A_VERIFIER' -Raison 'action COM : vérifiez l''éditeur de la tâche'
                }
            }
        }
    }

    # Services hors dossier Windows — T1543.003 ; chemins sans guillemets — T1574.009
    Invoke-Protege -PCategorie $cat -PMesure 'Inventaire des services' -PAction {
        foreach ($s in @(Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue)) {
            $chemin = [string]$s.PathName
            if (-not $chemin) { continue }
            $exe = Get-CheminExecutable -Commande $chemin
            $regle = Test-CommandeSuspecte -Commande $chemin
            $windows = $exe -and $exe.StartsWith($env:SystemRoot, [StringComparison]::OrdinalIgnoreCase)
            if ($windows -and -not $regle) { continue }
            $o = Add-Persistance -Groupe 'SERVICES' -Emplacement ('Service ({0})' -f $s.StartMode) -Nom ('{0} [{1}]' -f $s.DisplayName, $s.Name) -Commande $chemin -Fichier $exe -PassThru
            if ((Test-CheminNonCite -Chemin $chemin) -and ($o.Evaluation -eq 'OK' -or $o.Evaluation -eq 'CONNUE')) {
                $o.Evaluation = 'A_VERIFIER'
                $o.Raison = 'chemin avec espaces et sans guillemets : détournement possible (T1574.009)'
            }
        }
    }

    # Abonnements aux événements WMI — T1546.003
    Invoke-Protege -PCategorie $cat -PMesure 'Inventaire des abonnements WMI' -PAction {
        foreach ($c in @(Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventConsumer' -ErrorAction Stop)) {
            if (-not $c) { continue }
            $classe = [string]$c.CimClass.CimClassName
            $texte = ''
            foreach ($p in 'CommandLineTemplate', 'ExecutablePath', 'ScriptText', 'ScriptFileName') {
                if ($c.PSObject.Properties[$p] -and $c.$p) { $texte = [string]$c.$p; break }
            }
            if ($classe -eq 'CommandLineEventConsumer' -or $classe -eq 'ActiveScriptEventConsumer') {
                Add-Persistance -Groupe 'WMI' -Emplacement ('WMI : ' + $classe) -Nom ([string]$c.Name) -Commande $texte -Fichier $null -Evaluation 'SUSPECT' -Raison 'abonnement WMI qui exécute une commande ou un script (T1546.003)'
            } else {
                Add-Persistance -Groupe 'WMI' -Emplacement ('WMI : ' + $classe) -Nom ([string]$c.Name) -Commande $texte -Fichier $null -Evaluation 'CONNUE' -Raison 'consommateur WMI standard (journalisation)'
            }
        }
    }

    # Winlogon (Shell, Userinit) — T1547.004
    Invoke-Protege -PCategorie $cat -PMesure 'Contrôle de Winlogon' -PAction {
        $wl = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction Stop
        $shell = ([string]$wl.Shell).Trim()
        $userinit = ([string]$wl.Userinit).Trim().TrimEnd(',')
        if ($shell -and $shell -ine 'explorer.exe') {
            Add-Persistance -Groupe 'SYSTEME' -Emplacement 'Winlogon : Shell' -Nom 'Shell' -Commande $shell -Fichier (Get-CheminExecutable -Commande $shell) -Evaluation 'SUSPECT' -Raison 'shell de session modifié (attendu : explorer.exe)'
        }
        $attendu = $env:SystemRoot.TrimEnd('\') + '\system32\userinit.exe'
        if ($userinit -and $userinit -ine $attendu -and $userinit -ine 'userinit.exe') {
            Add-Persistance -Groupe 'SYSTEME' -Emplacement 'Winlogon : Userinit' -Nom 'Userinit' -Commande $userinit -Fichier (Get-CheminExecutable -Commande $userinit) -Evaluation 'SUSPECT' -Raison 'programme d''ouverture de session modifié'
        }
    }

    # Débogueurs IFEO et surveillance de fin de processus — T1546.012
    Invoke-Protege -PCategorie $cat -PMesure 'Contrôle des débogueurs IFEO' -PAction {
        foreach ($k in @(Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction SilentlyContinue)) {
            $debogueur = $k.GetValue('Debugger', $null)
            if ($debogueur) {
                Add-Persistance -Groupe 'SYSTEME' -Emplacement 'Débogueur IFEO' -Nom $k.PSChildName -Commande ([string]$debogueur) -Fichier (Get-CheminExecutable -Commande ([string]$debogueur)) -Evaluation 'A_VERIFIER' -Raison 'programme lancé à la place d''un autre (T1546.012)'
            }
        }
        foreach ($k in @(Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit' -ErrorAction SilentlyContinue)) {
            $moniteur = $k.GetValue('MonitorProcess', $null)
            if ($moniteur) {
                Add-Persistance -Groupe 'SYSTEME' -Emplacement 'Surveillance de fin de processus' -Nom $k.PSChildName -Commande ([string]$moniteur) -Fichier (Get-CheminExecutable -Commande ([string]$moniteur)) -Evaluation 'A_VERIFIER' -Raison 'programme lancé à la fermeture d''un autre (T1546.012)'
            }
        }
    }

    # AppInit_DLLs — T1546.010
    Invoke-Protege -PCategorie $cat -PMesure 'Contrôle d''AppInit_DLLs' -PAction {
        foreach ($ch in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows') {
            $w = Get-ItemProperty -LiteralPath $ch -ErrorAction SilentlyContinue
            if ($w -and $w.PSObject.Properties['AppInit_DLLs'] -and ([string]$w.AppInit_DLLs).Trim() -and $w.PSObject.Properties['LoadAppInit_DLLs'] -and [int]$w.LoadAppInit_DLLs -eq 1) {
                Add-Persistance -Groupe 'SYSTEME' -Emplacement 'AppInit_DLLs' -Nom $ch -Commande ([string]$w.AppInit_DLLs) -Fichier $null -Evaluation 'SUSPECT' -Raison 'DLL injectée dans tous les programmes (T1546.010)'
            }
        }
    }

    # Synthèse par famille
    $familles = @(
        @{ Groupe = 'DEMARRAGE'; Mesure = 'Programmes lancés au démarrage (clés Run, dossiers Démarrage)'; Attack = 'T1547.001' }
        @{ Groupe = 'TACHES'; Mesure = 'Tâches planifiées hors Microsoft'; Attack = 'T1053.005' }
        @{ Groupe = 'SERVICES'; Mesure = 'Services tiers'; Attack = 'T1543.003, T1574.009' }
        @{ Groupe = 'WMI'; Mesure = 'Abonnements aux événements WMI'; Attack = 'T1546.003' }
        @{ Groupe = 'SYSTEME'; Mesure = 'Winlogon, débogueurs IFEO, AppInit_DLLs'; Attack = 'T1547.004, T1546.012, T1546.010' }
    )
    foreach ($f in $familles) {
        $entrees = @($script:Persistance | Where-Object { $_.Groupe -eq $f.Groupe })
        $suspects = @($entrees | Where-Object { $_.Evaluation -eq 'SUSPECT' }).Count
        $aVerifier = @($entrees | Where-Object { $_.Evaluation -eq 'A_VERIFIER' }).Count
        $statut = 'INFO'
        if ($suspects -gt 0) { $statut = 'ALERTE' }
        $detail = '{0} entrée(s) : {1} suspecte(s), {2} à vérifier — détail dans le rapport, rien n''a été supprimé' -f $entrees.Count, $suspects, $aVerifier
        Add-Resultat -Categorie $cat -Mesure $f.Mesure -Attack $f.Attack -Statut $statut -Detail $detail
    }
}

# =====================================================================
#  8. ÉLÉVATION DE PRIVILÈGES
# =====================================================================

function Set-DurcissementElevation {
    $cat = 'Élévation'
    $sys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'

    # UAC actif — T1548.002
    Invoke-MesureRegistre -Categorie $cat -Mesure 'Contrôle de compte d''utilisateur (UAC) actif' -Attack 'T1548.002' -Impact 'Aucun' -Valeurs @(
        @{ Chemin = $sys; Nom = 'EnableLUA'; Valeur = 1 }
    ) -Redemarrage

    # UAC au niveau maximum « Toujours m'avertir », sur le bureau sécurisé — T1548.002
    Invoke-MesureRegistre -Categorie $cat -Mesure 'UAC au niveau maximum (toujours avertir, bureau sécurisé)' -Attack 'T1548.002' -Impact 'Demandes de confirmation plus fréquentes, y compris pour certains réglages Windows' -Valeurs @(
        @{ Chemin = $sys; Nom = 'ConsentPromptBehaviorAdmin'; Valeur = 2 }
        @{ Chemin = $sys; Nom = 'ConsentPromptBehaviorUser'; Valeur = 3 }
        @{ Chemin = $sys; Nom = 'PromptOnSecureDesktop'; Valeur = 1 }
        @{ Chemin = $sys; Nom = 'FilterAdministratorToken'; Valeur = 1 }
        @{ Chemin = $sys; Nom = 'EnableInstallerDetection'; Valeur = 1 }
        @{ Chemin = $sys; Nom = 'EnableSecureUIAPaths'; Valeur = 1 }
        @{ Chemin = $sys; Nom = 'EnableVirtualization'; Valeur = 1 }
    )

    # Exécution automatique (AutoRun / AutoPlay) — T1091
    $valeurs = @(
        @{ Chemin = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Nom = 'NoDriveTypeAutoRun'; Valeur = 255 }
        @{ Chemin = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Nom = 'NoAutorun'; Valeur = 1 }
        @{ Chemin = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'; Nom = 'NoAutoplayfornonVolume'; Valeur = 1 }
    )
    if ($script:Utilisateur.Ruche) {
        $valeurs += @{ Chemin = ($script:Utilisateur.Ruche + '\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers'); Nom = 'DisableAutoplay'; Valeur = 1 }
    }
    Invoke-MesureRegistre -Categorie $cat -Mesure 'Désactiver l''exécution automatique (AutoRun, AutoPlay)' -Attack 'T1091' -Impact 'Les clés USB et les CD ne lancent plus rien automatiquement' -Valeurs $valeurs
}

# =====================================================================
#  9. PROTECTIONS CONTRE L'EXPLOITATION (vérification seule, rien de forcé)
# =====================================================================

function Test-ProtectionsExploitation {
    $cat = 'Exploitation'

    # Exploit Protection au niveau système : DEP, ASLR, CFG, SEHOP — T1203, T1068
    try {
        $m = Get-ProcessMitigation -System -ErrorAction Stop
        $etats = [ordered]@{
            'DEP'                  = [string]$m.DEP.Enable
            'ASLR ascendant'       = [string]$m.ASLR.BottomUp
            'ASLR haute entropie'  = [string]$m.ASLR.HighEntropy
            'CFG'                  = [string]$m.CFG.Enable
            'SEHOP'                = [string]$m.SEHOP.Enable
        }
        $texte = (@($etats.Keys | ForEach-Object { '{0}={1}' -f $_, $etats[$_] }) -join ' ; ')
        $coupees = @($etats.Keys | Where-Object { $etats[$_] -eq 'OFF' })
        if ($coupees.Count -gt 0) {
            Add-Resultat -Categorie $cat -Mesure 'Protection contre l''exploitation (niveau système)' -Attack 'T1203, T1068' -Avant $texte -Apres $texte -Statut 'ALERTE' -Detail ('désactivé : {0}. Sécurité Windows > Contrôle des applications et du navigateur > Paramètres de protection contre l''exploitation > valeur par défaut' -f ($coupees -join ', '))
        } else {
            Add-Resultat -Categorie $cat -Mesure 'Protection contre l''exploitation (niveau système)' -Attack 'T1203, T1068' -Avant $texte -Apres $texte -Statut 'OK' -Detail 'protections par défaut actives (NOTSET = valeur par défaut de Windows)'
        }
        Add-Resultat -Categorie $cat -Mesure 'ASLR obligatoire (Mandatory ASLR)' -Attack 'T1203' -Avant ([string]$m.ASLR.ForceRelocateImages) -Apres ([string]$m.ASLR.ForceRelocateImages) -Statut 'INFO' -Detail 'non forcé, volontairement (compatibilité des jeux et de l''anti-triche)'
    } catch {
        Add-Resultat -Categorie $cat -Mesure 'Protection contre l''exploitation (niveau système)' -Attack 'T1203, T1068' -Statut 'IGNORE' -Detail ('lecture impossible : {0}' -f $_.Exception.Message)
    }

    # Politique DEP au démarrage — T1203
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $dep = [int]$os.DataExecutionPrevention_SupportPolicy
        $nomsDep = @{ 0 = 'AlwaysOff'; 1 = 'AlwaysOn'; 2 = 'OptIn (défaut)'; 3 = 'OptOut' }
        $texte = $nomsDep[$dep]
        if ($dep -eq 0) {
            Add-Resultat -Categorie $cat -Mesure 'Prévention de l''exécution des données au démarrage' -Attack 'T1203' -Avant $texte -Apres $texte -Statut 'ALERTE' -Detail 'DEP désactivée au démarrage : en administrateur, bcdedit /set {current} nx OptIn puis redémarrer'
        } else {
            Add-Resultat -Categorie $cat -Mesure 'Prévention de l''exécution des données au démarrage' -Attack 'T1203' -Avant $texte -Apres $texte -Statut 'OK' -Detail ('politique {0}' -f $texte)
        }
    } catch { }

    # VBS / HVCI (intégrité de la mémoire) : jamais activé automatiquement — T1068, T1014
    try {
        $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop
        $hvci = @($dg.SecurityServicesRunning) -contains 2
        $compatible = @($dg.AvailableSecurityProperties) -contains 1
        if ($hvci) {
            Add-Resultat -Categorie $cat -Mesure 'Intégrité de la mémoire (HVCI)' -Attack 'T1068, T1014' -Avant 'active' -Apres 'active' -Statut 'OK' -Detail 'active'
        } elseif ($compatible) {
            Add-Resultat -Categorie $cat -Mesure 'Intégrité de la mémoire (HVCI)' -Attack 'T1068, T1014' -Avant 'inactive' -Apres 'inactive' -Statut 'INFO' -Detail 'matériel compatible, non activée volontairement. Pour l''activer : Sécurité Windows > Sécurité de l''appareil > Isolation du noyau > Intégrité de la mémoire. Impact possible : quelques % de performances en jeu, pilotes anciens refusés'
        } else {
            Add-Resultat -Categorie $cat -Mesure 'Intégrité de la mémoire (HVCI)' -Attack 'T1068, T1014' -Avant 'inactive' -Apres 'inactive' -Statut 'INFO' -Detail 'virtualisation indisponible (désactivée dans l''UEFI ou matériel non compatible)'
        }
    } catch {
        Add-Resultat -Categorie $cat -Mesure 'Intégrité de la mémoire (HVCI)' -Attack 'T1068, T1014' -Statut 'IGNORE' -Detail 'information indisponible'
    }

    # Liste de blocage des pilotes vulnérables (active par défaut sur Windows 11) — T1068
    try {
        $ci = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' -ErrorAction SilentlyContinue
        if ($ci -and $ci.PSObject.Properties['VulnerableDriverBlocklistEnable'] -and [int]$ci.VulnerableDriverBlocklistEnable -eq 0) {
            Add-Resultat -Categorie $cat -Mesure 'Liste de blocage des pilotes vulnérables Microsoft' -Attack 'T1068' -Avant 'désactivée' -Apres 'désactivée' -Statut 'ALERTE' -Detail 'désactivée : Sécurité Windows > Sécurité de l''appareil > Isolation du noyau > Liste de blocage des pilotes vulnérables'
        } else {
            Add-Resultat -Categorie $cat -Mesure 'Liste de blocage des pilotes vulnérables Microsoft' -Attack 'T1068' -Avant 'active' -Apres 'active' -Statut 'OK' -Detail 'active'
        }
    } catch { }

    # Démarrage sécurisé (Secure Boot) — T1542
    try {
        $sb = Confirm-SecureBootUEFI -ErrorAction Stop
        if ($sb) {
            Add-Resultat -Categorie $cat -Mesure 'Démarrage sécurisé (Secure Boot)' -Attack 'T1542' -Statut 'OK' -Detail 'actif'
        } else {
            Add-Resultat -Categorie $cat -Mesure 'Démarrage sécurisé (Secure Boot)' -Attack 'T1542' -Statut 'ALERTE' -Detail 'désactivé dans l''UEFI : à réactiver dans les réglages du micrologiciel'
        }
    } catch {
        Add-Resultat -Categorie $cat -Mesure 'Démarrage sécurisé (Secure Boot)' -Attack 'T1542' -Statut 'INFO' -Detail 'non pris en charge (démarrage BIOS hérité) ou information indisponible'
    }

    # Smart App Control — T1204.002 (information)
    try {
        $sac = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -ErrorAction Stop
        if ($sac.PSObject.Properties['VerifiedAndReputablePolicyState']) {
            $etat = [int]$sac.VerifiedAndReputablePolicyState
            $textes = @{ 0 = 'désactivé (réactivable seulement en réinstallant Windows)'; 1 = 'actif'; 2 = 'en évaluation' }
            Add-Resultat -Categorie $cat -Mesure 'Contrôle intelligent des applications (Smart App Control)' -Attack 'T1204.002' -Statut 'INFO' -Detail $textes[$etat]
        }
    } catch { }

    # Chiffrement de l'appareil (vol de l'ordinateur) — T1005
    try {
        $vol = Get-CimInstance -Namespace 'root\CIMV2\Security\MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume -Filter ("DriveLetter='{0}'" -f $env:SystemDrive) -ErrorAction Stop
        if ($vol -and [int]$vol.ProtectionStatus -eq 1) {
            Add-Resultat -Categorie $cat -Mesure 'Chiffrement du disque système' -Attack 'T1005' -Statut 'OK' -Detail 'chiffré (chiffrement de l''appareil)'
        } elseif ($vol) {
            Add-Resultat -Categorie $cat -Mesure 'Chiffrement du disque système' -Attack 'T1005' -Statut 'INFO' -Detail 'non chiffré : Paramètres > Confidentialité et sécurité > Chiffrement de l''appareil (si proposé par votre matériel)'
        }
    } catch {
        Add-Resultat -Categorie $cat -Mesure 'Chiffrement du disque système' -Attack 'T1005' -Statut 'INFO' -Detail 'chiffrement de l''appareil non disponible sur ce matériel'
    }
}

# =====================================================================
#  10. JOURNALISATION — détection (T1078, T1098, T1136, T1053.005, T1070.001)
# =====================================================================

function Set-StrategieAudit {
    $cat = 'Journalisation'
    $mesure = 'Stratégie d''audit avancée (connexions, processus, comptes, tâches)'
    $attack = 'T1078, T1098, T1136, T1053.005'
    $fichierCsv = 'auditpol-{0}.csv' -f $script:Horodatage
    # Chemin relatif (pas d'espace) : auditpol s'exécute dans le dossier de sauvegarde.
    Push-Location -LiteralPath $script:Dossier
    try { $r = Invoke-Natif -Fichier 'auditpol.exe' -Arguments @('/backup', ('/file:{0}' -f $fichierCsv)) } finally { Pop-Location }
    $cheminCsv = Join-Path $script:Dossier $fichierCsv
    if ($r.Code -ne 0 -or -not (Test-Path -LiteralPath $cheminCsv)) {
        Add-Resultat -Categorie $cat -Mesure $mesure -Attack $attack -Statut 'ECHEC' -Detail ('sauvegarde de la stratégie impossible : {0}' -f $r.Sortie)
        return
    }
    $actuels = @{}
    $lignes = @(Get-Content -LiteralPath $cheminCsv | Select-Object -Skip 1 | Where-Object { $_.Trim() })
    foreach ($d in @($lignes | ConvertFrom-Csv -Header 'Machine', 'Cible', 'Sous', 'Guid', 'Inclusion', 'Exclusion', 'Valeur')) {
        if ([string]$d.Guid -match '^\{[0-9A-Fa-f-]+\}$') {
            $v = 0
            [void][int]::TryParse([string]$d.Valeur, [ref]$v)
            $actuels[([string]$d.Guid).ToUpperInvariant()] = $v
        }
    }
    $aFaire = @()
    foreach ($a in $SousCategoriesAudit) {
        $actuel = 0
        if ($actuels.ContainsKey($a.Guid.ToUpperInvariant())) { $actuel = $actuels[$a.Guid.ToUpperInvariant()] }
        $manque = $a.Valeur -band (-bnot $actuel)
        if ($manque -ne 0) { $aFaire += @{ Def = $a; Manque = $manque } }
    }
    if ($aFaire.Count -eq 0) {
        Remove-Item -LiteralPath $cheminCsv -Force -ErrorAction SilentlyContinue
        Add-Resultat -Categorie $cat -Mesure $mesure -Attack $attack -Statut 'OK' -Detail 'déjà en place'
        return
    }
    Add-Sauvegarde -Cle 'AUDITPOL' -Element @{ Type = 'AuditPol'; Fichier = $fichierCsv }
    $faites = @()
    $erreurs = @()
    foreach ($x in $aFaire) {
        $arguments = @('/set', ('/subcategory:{0}' -f $x.Def.Guid))
        if ($x.Manque -band 1) { $arguments += '/success:enable' }
        if ($x.Manque -band 2) { $arguments += '/failure:enable' }
        $res = Invoke-Natif -Fichier 'auditpol.exe' -Arguments $arguments
        if ($res.Code -eq 0) { $faites += $x.Def.Libelle } else { $erreurs += ('{0} : {1}' -f $x.Def.Libelle, $res.Sortie) }
    }
    if ($erreurs.Count -gt 0) {
        Add-Resultat -Categorie $cat -Mesure $mesure -Attack $attack -Apres ($faites -join ', ') -Statut 'ECHEC' -Detail ($erreurs -join ' / ')
    } else {
        Add-Resultat -Categorie $cat -Mesure $mesure -Attack $attack -Avant 'partielle' -Apres ($faites -join ', ') -Statut 'OK' -Detail ('{0} sous-catégorie(s) activée(s)' -f $faites.Count) -Impact 'Quelques centaines de Mo de journaux'
    }
}

function Set-TailleJournaux {
    $cat = 'Journalisation'
    $modifies = @()
    $deja = 0
    $erreurs = @()
    foreach ($j in $JournauxEvenements) {
        try {
            $cfg = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration ($j.Nom)
            $taille = [int64]$cfg.MaximumSizeInBytes
            $actif = [bool]$cfg.IsEnabled
            $cible = [int64]$j.Ko * 1024
            $activer = [bool]$j.Activer -and -not $actif
            if ($taille -ge $cible -and -not $activer) { $deja++; continue }
            Add-Sauvegarde -Cle ('LOG|' + $j.Nom) -Element @{ Type = 'Journal'; Nom = $j.Nom; TailleOctets = $taille; Active = $actif }
            if ($taille -lt $cible) { $cfg.MaximumSizeInBytes = $cible }
            if ($activer) { $cfg.IsEnabled = $true }
            $cfg.SaveChanges()
            $modifies += ('{0} ({1} Mo)' -f $j.Nom, [int]([math]::Max($taille, $cible) / 1MB))
        } catch { $erreurs += ('{0} : {1}' -f $j.Nom, $_.Exception.Message) }
    }
    $statut = 'OK'
    $detail = 'déjà en place'
    if ($modifies.Count -gt 0) { $detail = ('{0} journal(aux) agrandi(s) ou activé(s), {1} déjà conforme(s)' -f $modifies.Count, $deja) }
    if ($erreurs.Count -gt 0) { $statut = 'ECHEC'; $detail += ' — ' + ($erreurs -join ' / ') }
    Add-Resultat -Categorie $cat -Mesure 'Taille des journaux de sécurité, PowerShell, Defender, Planificateur' -Attack 'T1070.001' -Apres ($modifies -join ', ') -Statut $statut -Detail $detail -Impact 'Environ 500 Mo d''espace disque au maximum'
}

function Set-DurcissementJournalisation {
    $cat = 'Journalisation'
    # Ligne de commande dans l'événement de création de processus (4688) — T1059
    Invoke-MesureRegistre -Categorie $cat -Mesure 'Ligne de commande dans les événements de création de processus' -Attack 'T1059' -Impact 'Aucun' -Valeurs @(
        @{ Chemin = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'; Nom = 'ProcessCreationIncludeCmdLine_Enabled'; Valeur = 1 }
    )
    # Les sous-catégories d'audit priment sur les anciennes catégories — T1562.002
    Invoke-MesureRegistre -Categorie $cat -Mesure 'Priorité à la stratégie d''audit avancée' -Attack 'T1562.002' -Impact 'Aucun' -Valeurs @(
        @{ Chemin = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Nom = 'SCENoApplyLegacyAuditPolicy'; Valeur = 1 }
    )
    Invoke-Protege -PCategorie $cat -PMesure 'Stratégie d''audit avancée' -PAction { Set-StrategieAudit }
    Invoke-Protege -PCategorie $cat -PMesure 'Taille des journaux' -PAction { Set-TailleJournaux }
}

# =====================================================================
#  11. SERVICES — T1021, T1012, T1046
# =====================================================================

function Set-DurcissementServices {
    foreach ($s in $ServicesADesactiver) {
        Set-ServiceDesactive -Nom $s.Nom -Categorie 'Services' -Mesure ('Désactiver « {0} » ({1})' -f $s.Libelle, $s.Nom) -Attack $s.Attack -Impact 'Aucun pour un usage domestique'
    }
}

# =====================================================================
#  12. MISES À JOUR — T1190, T1203 (vulnérabilités connues)
# =====================================================================

function Test-MisesAJour {
    $cat = 'Mises à jour'

    # Service Windows Update : remis au démarrage manuel (défaut) s'il a été désactivé.
    try {
        $etat = Get-EtatService -Nom 'wuauserv'
        if ($etat -and $etat.Mode -eq 'Disabled') {
            Add-Sauvegarde -Cle 'SVC|wuauserv' -Element @{ Type = 'Service'; Nom = 'wuauserv'; Start = $etat.Start; Delai = $etat.Delai; EnCours = $etat.EnCours }
            $r = Invoke-Natif -Fichier 'sc.exe' -Arguments @('config', 'wuauserv', 'start=', 'demand')
            if ($r.Code -ne 0) { throw ('sc.exe : {0}' -f $r.Sortie) }
            Add-Resultat -Categorie $cat -Mesure 'Service Windows Update' -Attack 'T1190, T1203' -Avant 'désactivé' -Apres 'manuel (défaut)' -Statut 'OK' -Detail 'réactivé'
        } elseif ($etat) {
            Add-Resultat -Categorie $cat -Mesure 'Service Windows Update' -Attack 'T1190, T1203' -Avant $etat.Mode -Apres $etat.Mode -Statut 'OK' -Detail 'actif'
        }
    } catch {
        Add-Resultat -Categorie $cat -Mesure 'Service Windows Update' -Attack 'T1190, T1203' -Statut 'ECHEC' -Detail $_.Exception.Message
    }

    # Stratégie qui couperait les mises à jour automatiques (signalée, non modifiée).
    $au = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ErrorAction SilentlyContinue
    if ($au -and $au.PSObject.Properties['NoAutoUpdate'] -and [int]$au.NoAutoUpdate -eq 1) {
        Add-Resultat -Categorie $cat -Mesure 'Mises à jour automatiques' -Attack 'T1190, T1203' -Statut 'ALERTE' -Detail 'désactivées par une stratégie (NoAutoUpdate=1) : à vérifier'
    }

    # Mises à jour suspendues ?
    $ux = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -ErrorAction SilentlyContinue
    if ($ux -and $ux.PSObject.Properties['PauseUpdatesExpiryTime'] -and $ux.PauseUpdatesExpiryTime) {
        $fin = [datetime]::MinValue
        if ([datetime]::TryParse([string]$ux.PauseUpdatesExpiryTime, [ref]$fin) -and $fin -gt (Get-Date)) {
            Add-Resultat -Categorie $cat -Mesure 'Mises à jour suspendues' -Attack 'T1190, T1203' -Statut 'ALERTE' -Detail ('jusqu''au {0} : Paramètres > Windows Update > Reprendre les mises à jour' -f $fin.ToString('dd/MM/yyyy'))
        }
    }

    # Correctifs manquants (recherche Windows Update, 4 minutes maximum).
    $script:MisesAJour = [pscustomobject]@{ Manquantes = @(); Derniere = $null; Erreur = 'recherche non effectuée' }
    Invoke-Protege -PCategorie $cat -PMesure 'Correctifs manquants' -PAction { Test-CorrectifsManquants }

    # Signatures antivirus : âge
    if ($script:DefenderActif) {
        try {
            $s = Get-MpComputerStatus -ErrorAction Stop
            if ([int]$s.AntivirusSignatureAge -gt 3) {
                Add-Resultat -Categorie $cat -Mesure 'Âge des signatures antivirus' -Attack 'T1204.002' -Statut 'ALERTE' -Detail ('{0} jour(s)' -f $s.AntivirusSignatureAge)
            }
        } catch { }
    }
}

function Test-CorrectifsManquants {
    $cat = 'Mises à jour'
    Write-Patience 'recherche des correctifs manquants (jusqu''à 4 minutes)'
    $job = Start-Job -ScriptBlock {
        $session = New-Object -ComObject Microsoft.Update.Session
        $chercheur = $session.CreateUpdateSearcher()
        $resultat = $chercheur.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
        $titres = @()
        foreach ($u in $resultat.Updates) { $titres += [string]$u.Title }
        $derniere = $null
        try {
            $total = $chercheur.GetTotalHistoryCount()
            if ($total -gt 0) {
                foreach ($h in $chercheur.QueryHistory(0, [Math]::Min($total, 50))) {
                    if ($h.ResultCode -eq 2 -and ($null -eq $derniere -or $h.Date -gt $derniere)) { $derniere = $h.Date }
                }
            }
        } catch { }
        [pscustomobject]@{ Manquantes = $titres; Derniere = $derniere }
    }
    try {
        $fini = Wait-Job -Job $job -Timeout 240
        if (-not $fini) {
            Stop-Job -Job $job
            $script:MisesAJour.Erreur = 'délai dépassé'
            Add-Resultat -Categorie $cat -Mesure 'Correctifs manquants' -Attack 'T1190, T1203' -Statut 'ALERTE' -Detail 'recherche trop longue : vérifiez dans Paramètres > Windows Update'
            return
        }
        $sortie = Receive-Job -Job $job -ErrorAction Stop | Select-Object -Last 1
        $manquantes = @()
        if ($sortie -and $sortie.Manquantes) { $manquantes = @($sortie.Manquantes) }
        $script:MisesAJour.Manquantes = $manquantes
        $script:MisesAJour.Erreur = ''
        if ($sortie) { $script:MisesAJour.Derniere = $sortie.Derniere }
        $texteDerniere = ''
        if ($script:MisesAJour.Derniere) { $texteDerniere = (' ; dernière installation réussie : {0}' -f ([datetime]$script:MisesAJour.Derniere).ToLocalTime().ToString('dd/MM/yyyy')) }
        if ($manquantes.Count -eq 0) {
            Add-Resultat -Categorie $cat -Mesure 'Correctifs manquants' -Attack 'T1190, T1203' -Statut 'OK' -Detail ('aucun{0}' -f $texteDerniere)
        } else {
            Add-Resultat -Categorie $cat -Mesure 'Correctifs manquants' -Attack 'T1190, T1203' -Statut 'ALERTE' -Detail ('{0} mise(s) à jour en attente (liste dans le rapport) : Paramètres > Windows Update{1}' -f $manquantes.Count, $texteDerniere)
        }
    } catch {
        $script:MisesAJour.Erreur = $_.Exception.Message
        Add-Resultat -Categorie $cat -Mesure 'Correctifs manquants' -Attack 'T1190, T1203' -Statut 'ALERTE' -Detail ('recherche impossible ({0}) : vérifiez dans Paramètres > Windows Update' -f $_.Exception.Message)
    } finally {
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
    }
}

# =====================================================================
#  VÉRIFICATION FINALE
# =====================================================================

function Test-AccesHttps {
    param([string]$Hote)
    $ProgressPreference = 'SilentlyContinue'
    $dns = $false
    $https = $false
    $detail = ''
    try {
        $null = Resolve-DnsName -Name $Hote -QuickTimeout -ErrorAction Stop
        $dns = $true
    } catch { $detail = 'résolution DNS impossible' }
    if ($dns) {
        # Équivalent de Test-NetConnection -Port 443, en plus complet : la requête HTTPS vérifie
        # aussi que la protection réseau ne bloque pas le site (filtrage au niveau TLS).
        try {
            $r = Invoke-WebRequest -Uri ('https://{0}/' -f $Hote) -Method Head -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop
            $https = $true
            $detail = 'HTTPS joignable (code {0})' -f [int]$r.StatusCode
        } catch {
            $reponse = $null
            if ($_.Exception.PSObject.Properties['Response']) { $reponse = $_.Exception.Response }
            if ($reponse) {
                $https = $true
                $detail = 'HTTPS joignable (code {0})' -f [int]$reponse.StatusCode
            } else {
                $detail = 'HTTPS injoignable : {0}' -f $_.Exception.Message
            }
        }
    }
    [pscustomobject]@{ Hote = $Hote; Dns = $dns; Https = $https; Detail = $detail }
}

function Test-Compatibilite {
    $cat = 'Vérification finale'
    $nomsEvenements = @{
        1121 = 'Règle ASR : blocage'
        1122 = 'Règle ASR : audit'
        1123 = 'Accès contrôlé aux dossiers : blocage'
        1124 = 'Accès contrôlé aux dossiers : audit'
        1125 = 'Protection réseau : audit'
        1126 = 'Protection réseau : blocage'
    }
    $evenements = @()
    try {
        $evenements = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 1121, 1122, 1123, 1124, 1125, 1126; StartTime = (Get-Date).AddDays(-7) } -MaxEvents 500 -ErrorAction Stop)
    } catch { $evenements = @() }
    $detections = @()
    try { $detections = @(Get-MpThreatDetection -ErrorAction Stop) } catch { $detections = @() }

    # 1. Exécutables détectés : présents, pas bloqués ces 7 derniers jours, pas mis en quarantaine
    Invoke-Protege -PCategorie $cat -PMesure 'Contrôle des applications préservées' -PAction {
        foreach ($g in @($script:Applications | Group-Object -Property Application)) {
            $exes = @($g.Group | Where-Object { $_.Executable })
            $presents = @($exes | Where-Object {
                    if ($_.Executable.Contains('*')) { Test-Path -Path $_.Executable } else { Test-Path -LiteralPath $_.Executable -PathType Leaf }
                })
            $noms = @($exes | ForEach-Object { Get-NomFichier -Chemin $_.Executable } | Where-Object { $_ -and -not $_.Contains('*') } | Sort-Object -Unique)
            $blocages = 0
            $audits = 0
            foreach ($ev in $evenements) {
                $message = [string]$ev.Message
                foreach ($n in $noms) {
                    if ($message.IndexOf($n, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                        if ($ev.Id -eq 1121 -or $ev.Id -eq 1123 -or $ev.Id -eq 1126) { $blocages++ } else { $audits++ }
                        break
                    }
                }
            }
            $dossiers = @($g.Group | Where-Object { $_.Dossier } | ForEach-Object { $_.Dossier } | Sort-Object -Unique)
            $quarantaines = 0
            foreach ($d in $detections) {
                $ressources = (@($d.Resources) -join ' ')
                foreach ($dos in $dossiers) {
                    if ($ressources.IndexOf($dos, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $quarantaines++; break }
                }
            }
            $detail = '{0}/{1} exécutable(s) présent(s) ; 7 derniers jours : {2} blocage(s), {3} audit(s)' -f $presents.Count, $exes.Count, $blocages, $audits
            if ($quarantaines -gt 0) { $detail += (' ; {0} détection(s) antivirus dans son dossier (Historique de protection)' -f $quarantaines) }
            $statut = 'OK'
            if ($presents.Count -lt $exes.Count -or $blocages -gt 0 -or $quarantaines -gt 0) { $statut = 'ALERTE' }
            Add-Resultat -Categorie $cat -Mesure ('Application : {0}' -f $g.Name) -Statut $statut -Detail $detail
            $script:Compatibilite.Add([pscustomobject]@{ Test = ('Application : ' + $g.Name); Statut = $statut; Detail = $detail })
        }
    }

    # 2. Autorisations effectivement présentes dans Defender
    if ($script:DefenderActif) {
        try {
            $pref = Get-MpPreference
            $attendus = @($script:Applications | Where-Object { $_.Exclure -and $_.Motif } | ForEach-Object { $_.Motif } | Sort-Object -Unique)
            $asr = @()
            if ($pref.AttackSurfaceReductionOnlyExclusions) { $asr = @($pref.AttackSurfaceReductionOnlyExclusions) }
            $cfa = @()
            if ($pref.ControlledFolderAccessAllowedApplications) { $cfa = @($pref.ControlledFolderAccessAllowedApplications) }
            $manquants = @($attendus | Where-Object { ($asr -notcontains $_) -or ($cfa -notcontains $_) })
            $statut = 'OK'
            $detail = '{0} chemin(s) autorisé(s) dans les règles ASR et l''accès contrôlé aux dossiers' -f $attendus.Count
            if ($manquants.Count -gt 0) { $statut = 'ALERTE'; $detail = '{0} autorisation(s) absente(s) : {1}' -f $manquants.Count, ($manquants -join ' ; ') }
            Add-Resultat -Categorie $cat -Mesure 'Autorisations des applications préservées' -Statut $statut -Detail $detail
            $script:Compatibilite.Add([pscustomobject]@{ Test = 'Autorisations Defender'; Statut = $statut; Detail = $detail })
        } catch { }
    }

    # 3. DNS + HTTPS (port 443)
    foreach ($h in $SitesTest) {
        $r = Test-AccesHttps -Hote $h
        $statut = 'OK'
        if (-not $r.Https) { $statut = 'ALERTE' }
        Add-Resultat -Categorie $cat -Mesure ('Connexion à {0}' -f $h) -Statut $statut -Detail $r.Detail
        $script:Compatibilite.Add([pscustomobject]@{ Test = ('DNS + HTTPS : ' + $h); Statut = $statut; Detail = $r.Detail })
    }

    # 4. Blocages Defender récents, toutes applications (pour le dépannage)
    $recents = @($evenements | Where-Object { $_.Id -eq 1121 -or $_.Id -eq 1123 -or $_.Id -eq 1126 } | Select-Object -First 25)
    $script:EvenementsRecents = @($recents | ForEach-Object {
            $message = ([string]$_.Message) -replace '\s+', ' '
            if ($message.Length -gt 420) { $message = $message.Substring(0, 420) + '…' }
            [pscustomobject]@{ Date = $_.TimeCreated; Type = $nomsEvenements[$_.Id]; Message = $message }
        })
    $statut = 'INFO'
    $detail = 'aucun blocage ASR, accès contrôlé ou protection réseau ces 7 derniers jours'
    if ($recents.Count -gt 0) { $detail = '{0} blocage(s) ces 7 derniers jours (détail dans le rapport)' -f $recents.Count }
    Add-Resultat -Categorie $cat -Mesure 'Blocages Defender récents (toutes applications)' -Statut $statut -Detail $detail
}

# =====================================================================
#  RAPPORT HTML, JOURNAL ET RÉSUMÉ
# =====================================================================

$CssRapport = @'
:root{--fond:#f4f5f7;--surface:#fff;--texte:#1b1f24;--doux:#59636e;--bord:#d8dde3;--accent:#1d4f91;--entete:#14325c;
--ok:#1a7f37;--ok-fond:#e6f4ea;--alerte:#8a5a00;--alerte-fond:#fff4d6;--echec:#c62828;--echec-fond:#fdecea;
--ignore:#6b7280;--ignore-fond:#eef0f3;--info:#0b5cad;--info-fond:#e8f1fb}
@media (prefers-color-scheme:dark){:root{--fond:#0f1318;--surface:#171c22;--texte:#e6e9ee;--doux:#9aa4b1;--bord:#2c343e;
--accent:#7aa7e6;--entete:#0b1a2e;--ok:#56d17a;--ok-fond:#13261a;--alerte:#f0c75e;--alerte-fond:#2b2412;--echec:#ff7b72;
--echec-fond:#2d1515;--ignore:#9aa4b1;--ignore-fond:#1e242c;--info:#79b8ff;--info-fond:#13223a}}
*{box-sizing:border-box}
body{margin:0;background:var(--fond);color:var(--texte);font:14px/1.5 "Segoe UI",system-ui,-apple-system,sans-serif}
.enveloppe{max-width:1280px;margin:0 auto;padding:0 24px}
header{background:var(--entete);color:#fff;padding:28px 0 24px}
header h1{margin:4px 0 6px;font-size:26px;font-weight:600}
.surtitre{margin:0;font-size:12px;letter-spacing:.08em;text-transform:uppercase;opacity:.75}
.meta{margin:0;opacity:.85}
main{padding:8px 0 48px}
h2{font-size:18px;font-weight:600;margin:36px 0 12px;padding-bottom:6px;border-bottom:1px solid var(--bord)}
p.aide{color:var(--doux);margin:-4px 0 12px}
.cartes{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-top:24px}
.carte{background:var(--surface);border:1px solid var(--bord);border-top:4px solid var(--c);border-radius:10px;padding:14px 16px}
.carte b{display:block;font-size:28px;line-height:1.1;color:var(--c)}
.carte span{color:var(--doux)}
.carte.ok{--c:var(--ok)}.carte.alerte{--c:var(--alerte)}.carte.echec{--c:var(--echec)}.carte.ignore{--c:var(--ignore)}
.bandeau{margin:16px 0 0;padding:12px 16px;border-radius:8px;background:var(--alerte-fond);color:var(--alerte);font-weight:600}
.tableau{overflow-x:auto;border:1px solid var(--bord);border-radius:10px;background:var(--surface)}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{padding:7px 10px;text-align:left;vertical-align:top;border-bottom:1px solid var(--bord)}
th{position:sticky;top:0;background:var(--surface);color:var(--doux);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
tr:last-child td{border-bottom:none}
td.mono,code{font-family:Consolas,"Cascadia Mono",monospace;font-size:12px;overflow-wrap:anywhere}
td.etroit{white-space:nowrap}
td.mesure{min-width:200px}td.valeur{min-width:130px}td.attack{min-width:96px}td.attack a{white-space:nowrap}
.pastille{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;font-weight:700;letter-spacing:.03em;white-space:nowrap}
.pastille.ok{color:var(--ok);background:var(--ok-fond)}.pastille.alerte{color:var(--alerte);background:var(--alerte-fond)}
.pastille.echec{color:var(--echec);background:var(--echec-fond)}.pastille.ignore{color:var(--ignore);background:var(--ignore-fond)}
.pastille.info{color:var(--info);background:var(--info-fond)}
tr.categorie td{background:var(--fond);font-weight:600;color:var(--accent)}
ul.points{list-style:none;padding:0;margin:0;display:grid;gap:8px}
ul.points li{background:var(--surface);border:1px solid var(--bord);border-radius:8px;padding:10px 12px}
.encadre{background:var(--surface);border:1px solid var(--bord);border-left:4px solid var(--accent);border-radius:8px;padding:12px 18px;margin-bottom:12px}
.encadre ol,.encadre ul{margin:6px 0;padding-left:20px}.encadre li{margin:4px 0}
a{color:var(--accent)}
.vide{color:var(--doux);font-style:italic}
footer{color:var(--doux);font-size:12px;padding:8px 0 40px}
'@

function ConvertTo-LienAttack {
    param([string]$Ids)
    if (-not $Ids) { return '—' }
    $liens = foreach ($id in ($Ids -split '\s*,\s*')) {
        if ($id -match '^T(\d{4})(?:\.(\d{3}))?$') {
            $url = 'https://attack.mitre.org/techniques/T' + $Matches[1] + '/'
            if ($Matches[2]) { $url += $Matches[2] + '/' }
            '<a href="{0}">{1}</a>' -f $url, $id
        } elseif ($id) {
            Format-Html $id
        }
    }
    return (@($liens) -join ', ')
}

function Get-PastilleHtml {
    param([string]$Statut)
    $classes = @{ 'OK' = 'ok'; 'IGNORE' = 'ignore'; 'INFO' = 'info'; 'ALERTE' = 'alerte'; 'ECHEC' = 'echec' }
    $classe = $classes[$Statut]
    if (-not $classe) { $classe = 'info' }
    $libelle = $LibellesStatut[$Statut]
    if (-not $libelle) { $libelle = $Statut }
    return ('<span class="pastille {0}">{1}</span>' -f $classe, (Format-Html $libelle))
}

function Export-Rapport {
    try {
        $compte = @{}
        foreach ($s in 'OK', 'ALERTE', 'ECHEC', 'IGNORE', 'INFO') { $compte[$s] = @($script:Resultats | Where-Object { $_.Statut -eq $s }).Count }
        $duree = (Get-Date) - $script:Debut
        $sb = New-Object System.Text.StringBuilder

        [void]$sb.AppendLine('<!DOCTYPE html>')
        [void]$sb.AppendLine('<html lang="fr">')
        [void]$sb.AppendLine('<head>')
        [void]$sb.AppendLine('<meta charset="utf-8">')
        [void]$sb.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1">')
        [void]$sb.AppendLine(('<title>Rapport de durcissement — {0}</title>' -f (Format-Html $env:COMPUTERNAME)))
        [void]$sb.AppendLine('<style>')
        [void]$sb.AppendLine($CssRapport)
        [void]$sb.AppendLine('</style>')
        [void]$sb.AppendLine('</head>')
        [void]$sb.AppendLine('<body>')

        # En-tête
        [void]$sb.AppendLine('<header><div class="enveloppe">')
        [void]$sb.AppendLine('<p class="surtitre">Rapport de durcissement Windows</p>')
        [void]$sb.AppendLine(('<h1>{0}</h1>' -f (Format-Html $env:COMPUTERNAME)))
        [void]$sb.AppendLine(('<p class="meta">{0} · {1} (build {2}.{3}) · compte protégé : {4} · durée : {5} min {6:00} s</p>' -f (Format-Html $script:Debut.ToString('dd/MM/yyyy HH:mm')), (Format-Html $script:Systeme.Libelle), $script:Systeme.Build, $script:Systeme.Ubr, (Format-Html $script:Utilisateur.Nom), [int][math]::Floor($duree.TotalMinutes), $duree.Seconds))
        [void]$sb.AppendLine('</div></header>')
        [void]$sb.AppendLine('<main><div class="enveloppe">')

        # Synthèse
        [void]$sb.AppendLine('<section class="cartes">')
        [void]$sb.AppendLine(('<div class="carte ok"><b>{0}</b><span>mesures appliquées ou déjà en place</span></div>' -f $compte['OK']))
        [void]$sb.AppendLine(('<div class="carte alerte"><b>{0}</b><span>points à vérifier</span></div>' -f $compte['ALERTE']))
        [void]$sb.AppendLine(('<div class="carte echec"><b>{0}</b><span>échecs</span></div>' -f $compte['ECHEC']))
        [void]$sb.AppendLine(('<div class="carte ignore"><b>{0}</b><span>non applicables</span></div>' -f $compte['IGNORE']))
        [void]$sb.AppendLine('</section>')
        if ($script:RedemarrageRequis) {
            [void]$sb.AppendLine('<p class="bandeau">Redémarrez l''ordinateur pour terminer : certaines protections ne s''activent qu''au démarrage.</p>')
        }

        # Points à vérifier
        [void]$sb.AppendLine('<h2>Points à vérifier</h2>')
        $points = @($script:Resultats | Where-Object { $_.Statut -eq 'ALERTE' -or $_.Statut -eq 'ECHEC' })
        if ($points.Count -eq 0) {
            [void]$sb.AppendLine('<p class="vide">Rien à signaler.</p>')
        } else {
            [void]$sb.AppendLine('<ul class="points">')
            foreach ($p in $points) {
                [void]$sb.AppendLine(('<li>{0} <b>{1}</b> — {2}</li>' -f (Get-PastilleHtml $p.Statut), (Format-Html $p.Mesure), (Format-Html $p.Detail)))
            }
            [void]$sb.AppendLine('</ul>')
        }

        # Mesures
        [void]$sb.AppendLine('<h2>Mesures</h2>')
        [void]$sb.AppendLine('<p class="aide">Chaque mesure indique la technique MITRE ATT&amp;CK contrée, l''état avant et après, et l''impact possible au quotidien.</p>')
        [void]$sb.AppendLine('<div class="tableau"><table>')
        [void]$sb.AppendLine('<tr><th>Mesure</th><th>ATT&amp;CK</th><th>Avant</th><th>Après</th><th>Statut</th><th>Détail</th><th>Impact possible</th></tr>')
        $categorie = $null
        foreach ($r in $script:Resultats) {
            if ($r.Categorie -ne $categorie) {
                $categorie = $r.Categorie
                [void]$sb.AppendLine(('<tr class="categorie"><td colspan="7">{0}</td></tr>' -f (Format-Html $categorie)))
            }
            [void]$sb.AppendLine(('<tr><td class="mesure">{0}</td><td class="attack">{1}</td><td class="mono valeur">{2}</td><td class="mono valeur">{3}</td><td>{4}</td><td>{5}</td><td>{6}</td></tr>' -f (Format-Html $r.Mesure), (ConvertTo-LienAttack $r.Attack), (Format-Html $r.Avant), (Format-Html $r.Apres), (Get-PastilleHtml $r.Statut), (Format-Html $r.Detail), (Format-Html $r.Impact)))
        }
        [void]$sb.AppendLine('</table></div>')

        # Applications préservées
        [void]$sb.AppendLine('<h2>Applications préservées</h2>')
        [void]$sb.AppendLine('<p class="aide">Chemins détectés automatiquement. Le motif autorisé (le joker * remplace un dossier de version) est ajouté aux exclusions des règles ASR et aux applications autorisées de l''accès contrôlé aux dossiers. Aucune exclusion antivirus complète n''est créée.</p>')
        if ($script:Applications.Count -eq 0) {
            [void]$sb.AppendLine('<p class="vide">Aucune application détectée.</p>')
        } else {
            [void]$sb.AppendLine('<div class="tableau"><table>')
            [void]$sb.AppendLine('<tr><th>Application</th><th>Exécutable</th><th>Motif autorisé</th><th>Pare-feu entrant</th></tr>')
            foreach ($a in $script:Applications) {
                $motif = $a.Motif
                if (-not $a.Exclure) { $motif = $a.Note }
                $pareFeu = 'non nécessaire'
                if ($a.PareFeu) { $pareFeu = 'autorisé (réseau Privé)' }
                [void]$sb.AppendLine(('<tr><td>{0}</td><td class="mono">{1}</td><td class="mono">{2}</td><td>{3}</td></tr>' -f (Format-Html $a.Application), (Format-Html $a.Executable), (Format-Html $motif), (Format-Html $pareFeu)))
            }
            [void]$sb.AppendLine('</table></div>')
        }

        # Tests de compatibilité
        [void]$sb.AppendLine('<h2>Tests de compatibilité</h2>')
        if ($script:Compatibilite.Count -eq 0) {
            [void]$sb.AppendLine('<p class="vide">Aucun test effectué.</p>')
        } else {
            [void]$sb.AppendLine('<div class="tableau"><table>')
            [void]$sb.AppendLine('<tr><th>Test</th><th>Statut</th><th>Détail</th></tr>')
            foreach ($t in $script:Compatibilite) {
                [void]$sb.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td></tr>' -f (Format-Html $t.Test), (Get-PastilleHtml $t.Statut), (Format-Html $t.Detail)))
            }
            [void]$sb.AppendLine('</table></div>')
        }
        [void]$sb.AppendLine('<h2>Blocages Defender des 7 derniers jours</h2>')
        [void]$sb.AppendLine('<p class="aide">Règles ASR (1121), accès contrôlé aux dossiers (1123) et protection réseau (1126). Relancez le script après un problème : cette liste sera à jour.</p>')
        if (@($script:EvenementsRecents).Count -eq 0) {
            [void]$sb.AppendLine('<p class="vide">Aucun blocage.</p>')
        } else {
            [void]$sb.AppendLine('<div class="tableau"><table>')
            [void]$sb.AppendLine('<tr><th>Date</th><th>Type</th><th>Message</th></tr>')
            foreach ($e in $script:EvenementsRecents) {
                [void]$sb.AppendLine(('<tr><td class="etroit">{0}</td><td>{1}</td><td>{2}</td></tr>' -f (Format-Html ([datetime]$e.Date).ToString('dd/MM/yyyy HH:mm')), (Format-Html $e.Type), (Format-Html $e.Message)))
            }
            [void]$sb.AppendLine('</table></div>')
        }

        # Persistance
        [void]$sb.AppendLine('<h2>Programmes au démarrage et persistance</h2>')
        [void]$sb.AppendLine('<p class="aide">Inventaire seulement : rien n''a été supprimé. « Suspect » mérite une vérification rapide ; « À vérifier » signale une entrée non signée, orpheline ou inhabituelle, souvent légitime.</p>')
        if ($script:Persistance.Count -eq 0) {
            [void]$sb.AppendLine('<p class="vide">Aucune entrée.</p>')
        } else {
            $ordre = @{ 'SUSPECT' = 0; 'A_VERIFIER' = 1; 'OK' = 2; 'CONNUE' = 3 }
            $classesEval = @{ 'SUSPECT' = 'echec'; 'A_VERIFIER' = 'alerte'; 'OK' = 'ok'; 'CONNUE' = 'info' }
            [void]$sb.AppendLine('<div class="tableau"><table>')
            [void]$sb.AppendLine('<tr><th>Évaluation</th><th>Emplacement</th><th>Nom</th><th>Commande</th><th>Signataire</th><th>Raison</th></tr>')
            foreach ($p in @($script:Persistance | Sort-Object -Property @{ Expression = { $ordre[$_.Evaluation] } }, Emplacement, Nom)) {
                $pastille = '<span class="pastille {0}">{1}</span>' -f $classesEval[$p.Evaluation], (Format-Html $LibellesEvaluation[$p.Evaluation])
                [void]$sb.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td class="mono">{3}</td><td>{4}</td><td>{5}</td></tr>' -f $pastille, (Format-Html $p.Emplacement), (Format-Html $p.Nom), (Format-Html $p.Commande), (Format-Html $p.Signataire), (Format-Html $p.Raison)))
            }
            [void]$sb.AppendLine('</table></div>')
        }

        # Mises à jour
        [void]$sb.AppendLine('<h2>Mises à jour en attente</h2>')
        if (-not $script:MisesAJour) {
            [void]$sb.AppendLine('<p class="vide">Recherche non effectuée.</p>')
        } elseif ($script:MisesAJour.Erreur) {
            [void]$sb.AppendLine(('<p class="vide">Recherche impossible ({0}) : ouvrez Paramètres &gt; Windows Update.</p>' -f (Format-Html $script:MisesAJour.Erreur)))
        } elseif (@($script:MisesAJour.Manquantes).Count -eq 0) {
            [void]$sb.AppendLine('<p class="vide">Aucune mise à jour en attente.</p>')
        } else {
            [void]$sb.AppendLine('<div class="encadre"><ul>')
            foreach ($u in $script:MisesAJour.Manquantes) { [void]$sb.AppendLine(('<li>{0}</li>' -f (Format-Html $u))) }
            [void]$sb.AppendLine('</ul></div>')
        }

        # Annulation et dépannage
        [void]$sb.AppendLine('<h2>Annuler ou dépanner</h2>')
        [void]$sb.AppendLine('<div class="encadre"><b>Tout annuler</b><ul>')
        [void]$sb.AppendLine(('<li>Double-cliquez sur <code>Annuler-Durcissement.bat</code> dans <code>{0}</code> (raccourci « Durcissement-Sauvegarde » sur le Bureau). Les réglages d''origine sont restaurés, puis un redémarrage est proposé.</li>' -f (Format-Html $script:Dossier)))
        [void]$sb.AppendLine('<li>En dernier recours : touche Windows, tapez <code>rstrui</code>, puis choisissez le point de restauration « Avant durcissement Windows ».</li>')
        [void]$sb.AppendLine('<li>Ne supprimez pas ce dossier tant que vous voulez pouvoir annuler.</li>')
        [void]$sb.AppendLine('</ul></div>')
        [void]$sb.AppendLine('<div class="encadre"><b>Un jeu ou une application est bloqué</b><ol>')
        [void]$sb.AppendLine('<li>Ouvrez Sécurité Windows &gt; Protection contre les virus et menaces &gt; <b>Historique de protection</b> : le blocage récent indique le programme et la protection en cause (règle ASR, accès contrôlé aux dossiers ou protection réseau).</li>')
        [void]$sb.AppendLine('<li><b>Accès contrôlé aux dossiers</b> (le programme ne peut pas enregistrer) : Protection contre les virus et menaces &gt; Gérer la protection contre les rançongiciels &gt; Autoriser une application via l''Accès contrôlé aux dossiers &gt; Applications récemment bloquées.</li>')
        [void]$sb.AppendLine('<li><b>Règle ASR</b> (le programme ne démarre pas) : ajoutez son chemin dans <code>$AppsSupplementaires</code> en tête de Durcissement-Windows.ps1, puis relancez le script.</li>')
        [void]$sb.AppendLine('<li>Après une grosse mise à jour de Battle.net, d''un jeu ou de Claude, <b>relancez simplement le script</b> : il détecte les nouveaux chemins et liste les blocages des 7 derniers jours.</li>')
        [void]$sb.AppendLine('<li>Si rien n''y fait : <code>Annuler-Durcissement.bat</code>, puis redémarrez.</li>')
        [void]$sb.AppendLine('</ol></div>')

        [void]$sb.AppendLine(('<footer>Généré par Durcissement-Windows.ps1 le {0}. Sauvegarde : {1}. Journal : {2}.</footer>' -f (Format-Html (Get-Date).ToString('dd/MM/yyyy HH:mm')), (Format-Html $script:FichierSauvegarde), (Format-Html $script:FichierJournal)))
        [void]$sb.AppendLine('</div></main>')
        [void]$sb.AppendLine('</body>')
        [void]$sb.AppendLine('</html>')

        [System.IO.File]::WriteAllText($script:FichierRapport, $sb.ToString(), $script:Utf8Bom)
    } catch {
        Write-Ligne -Statut 'ECHEC' -Texte ('Rapport HTML impossible : {0}' -f $_.Exception.Message)
    }
}

function Export-Journal {
    if (-not $script:FichierJournal) { return }
    try {
        $lignes = New-Object System.Collections.Generic.List[string]
        $lignes.Add(('Durcissement Windows — {0}' -f $script:Debut.ToString('dd/MM/yyyy HH:mm:ss')))
        $lignes.Add(('Ordinateur : {0} — {1} (build {2}.{3})' -f $env:COMPUTERNAME, $script:Systeme.Libelle, $script:Systeme.Build, $script:Systeme.Ubr))
        $lignes.Add(('Compte protégé : {0}' -f $script:Utilisateur.Nom))
        $lignes.Add('')
        $lignes.Add('--- Déroulement ---')
        foreach ($l in $script:Journal) { $lignes.Add($l) }
        $lignes.Add('')
        $lignes.Add('--- Résultats détaillés (statut | catégorie | mesure | ATT&CK | avant | après | détail | impact) ---')
        foreach ($r in $script:Resultats) {
            $lignes.Add(('[{0}] {1} | {2} | {3} | avant : {4} | après : {5} | {6} | {7}' -f $LibellesStatut[$r.Statut], $r.Categorie, $r.Mesure, $r.Attack, $r.Avant, $r.Apres, $r.Detail, $r.Impact))
        }
        $lignes.Add('')
        $lignes.Add('--- Persistance (inventaire, rien n''a été supprimé) ---')
        foreach ($p in $script:Persistance) {
            $lignes.Add(('[{0}] {1} | {2} | {3} | {4} | {5}' -f $LibellesEvaluation[$p.Evaluation], $p.Emplacement, $p.Nom, $p.Commande, $p.Signataire, $p.Raison))
        }
        [System.IO.File]::WriteAllLines($script:FichierJournal, [string[]]$lignes.ToArray(), $script:Utf8Bom)
    } catch { }
}

function Show-Resume {
    $duree = (Get-Date) - $script:Debut
    $compte = @{}
    foreach ($s in 'OK', 'ALERTE', 'ECHEC', 'IGNORE', 'INFO') { $compte[$s] = @($script:Resultats | Where-Object { $_.Statut -eq $s }).Count }
    $ligne = '=' * 74
    Write-Host ''
    Write-Host $ligne -ForegroundColor Cyan
    Write-Host ('  TERMINÉ en {0} min {1:00} s' -f [int][math]::Floor($duree.TotalMinutes), $duree.Seconds) -ForegroundColor Cyan
    Write-Host ('  OK : {0}   Alertes : {1}   Échecs : {2}   Ignorés : {3}   Infos : {4}' -f $compte['OK'], $compte['ALERTE'], $compte['ECHEC'], $compte['IGNORE'], $compte['INFO'])
    Write-Host ('  Rapport : {0}' -f $script:FichierRapport)
    Write-Host '  Annuler : Bureau > Durcissement-Sauvegarde > Annuler-Durcissement.bat'
    Write-Host $ligne -ForegroundColor Cyan
    $points = @($script:Resultats | Where-Object { $_.Statut -eq 'ALERTE' -or $_.Statut -eq 'ECHEC' })
    if ($points.Count -gt 0) {
        Write-Host '  Points à vérifier :' -ForegroundColor Yellow
        foreach ($p in $points) { Write-Host ('   - {0} : {1}' -f $p.Mesure, $p.Detail) -ForegroundColor Yellow }
    }
    # Ouvre le rapport avec le navigateur, dans la session de l'utilisateur (pas en administrateur).
    try {
        if (Test-Path -LiteralPath $script:FichierRapport) {
            Start-Process -FilePath (Join-Path $env:SystemRoot 'explorer.exe') -ArgumentList ('"{0}"' -f $script:FichierRapport)
        }
    } catch { }
    Write-Host ''
    if ($script:RedemarrageRequis) {
        $reponse = Read-Host '  Un redémarrage est nécessaire pour terminer. Redémarrer maintenant ? (O/N)'
        if ($reponse -match '^\s*[oOyY]') {
            Write-Host '  Redémarrage dans 10 secondes...' -ForegroundColor Cyan
            & shutdown.exe /r /t 10 /c 'Redémarrage pour terminer le durcissement de Windows'
            Start-Sleep -Seconds 3
            return
        }
        Write-Host '  Pensez à redémarrer l''ordinateur dès que possible.' -ForegroundColor Yellow
    }
    Read-Host '  Appuyez sur Entrée pour fermer'
}

# =====================================================================
#  SCRIPT D'ANNULATION (écrit dans le dossier de sauvegarde)
# =====================================================================

$CodeAnnulation = @'
#Requires -Version 5.1
<#
    Annuler-Durcissement.ps1
    Généré automatiquement par Durcissement-Windows.ps1 : ne pas modifier.

    Remet les réglages d'origine enregistrés dans les fichiers Sauvegarde-*.json de ce dossier,
    du plus récent au plus ancien : registre, services, fonctionnalités Windows, Microsoft Defender,
    règles ASR, exclusions, pare-feu, stratégie d'audit et taille des journaux.
    Lancement : double-clic sur Annuler-Durcissement.bat, dans le même dossier.
#>

if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
    Write-Host 'PowerShell fonctionne ici en mode restreint : l''annulation automatique est impossible.' -ForegroundColor Red
    Write-Host 'Utilisez le point de restauration « Avant durcissement Windows » : touche Windows, tapez rstrui, Entrée.' -ForegroundColor Red
    Read-Host 'Appuyez sur Entrée pour fermer'
    exit 1
}

$estAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$bonMoteur = ($PSVersionTable.PSEdition -eq 'Desktop') -and ([Environment]::Is64BitProcess -or -not [Environment]::Is64BitOperatingSystem)
if (-not ($estAdmin -and $bonMoteur)) {
    if ($args -contains '-Relance') {
        Write-Host 'Impossible d''obtenir les droits administrateur.' -ForegroundColor Red
        Read-Host 'Appuyez sur Entrée pour fermer'
        exit 1
    }
    $moteur = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
        $moteur = Join-Path $env:SystemRoot 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    }
    try {
        Start-Process -FilePath $moteur -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -File "{0}" -Relance' -f $PSCommandPath) -Verb RunAs -ErrorAction Stop
    } catch {
        Write-Host 'Droits administrateur refusés : rien n''a été modifié.' -ForegroundColor Yellow
        Read-Host 'Appuyez sur Entrée pour fermer'
        exit 1
    }
    exit 0
}

$ErrorActionPreference = 'Stop'
try { $Host.UI.RawUI.WindowTitle = 'Annulation du durcissement Windows' } catch { }
$Dossier = $PSScriptRoot
$Journal = New-Object System.Collections.Generic.List[string]
$Utf8Bom = New-Object System.Text.UTF8Encoding $true
$script:Reussites = 0
$script:Echecs = 0

$NomsActionsAsr = @{ 0 = 'Disabled'; 1 = 'Enabled'; 2 = 'AuditMode'; 6 = 'Warn' }
$EnumsDefender = @{
    'PUAProtection'                = @{ '0' = 'Disabled'; '1' = 'Enabled'; '2' = 'AuditMode' }
    'MAPSReporting'                = @{ '0' = 'Disabled'; '1' = 'Basic'; '2' = 'Advanced' }
    'CloudBlockLevel'              = @{ '0' = 'Default'; '1' = 'Moderate'; '2' = 'High'; '4' = 'HighPlus'; '6' = 'ZeroTolerance' }
    'SubmitSamplesConsent'         = @{ '0' = 'AlwaysPrompt'; '1' = 'SendSafeSamples'; '2' = 'NeverSend'; '3' = 'SendAllSamples' }
    'EnableNetworkProtection'      = @{ '0' = 'Disabled'; '1' = 'Enabled'; '2' = 'AuditMode' }
    'EnableControlledFolderAccess' = @{ '0' = 'Disabled'; '1' = 'Enabled'; '2' = 'AuditMode'; '3' = 'BlockDiskModificationOnly'; '4' = 'AuditDiskModificationOnly' }
}

function Write-Ligne {
    param([string]$Statut, [string]$Texte)
    $couleur = 'Gray'
    if ($Statut -eq 'OK') { $couleur = 'Green' } elseif ($Statut -eq 'ECHEC') { $couleur = 'Red' } elseif ($Statut -eq 'INFO') { $couleur = 'Cyan' }
    $libelle = $Statut
    if ($Statut -eq 'ECHEC') { $libelle = 'ÉCHEC' }
    Write-Host ('  [{0}]' -f $libelle).PadRight(11) -ForegroundColor $couleur -NoNewline
    Write-Host $Texte
    $Journal.Add(('{0}  [{1}] {2}' -f (Get-Date).ToString('HH:mm:ss'), $libelle, $Texte))
}

function Invoke-Natif {
    param([string]$Fichier, [string[]]$Arguments)
    $ErrorActionPreference = 'Continue'
    $sortie = & $Fichier @Arguments 2>&1 | ForEach-Object { [string]$_ }
    [pscustomobject]@{ Code = $LASTEXITCODE; Sortie = (($sortie | Out-String).Trim()) }
}

function Remove-ValeurRegistre {
    # Suppression littérale d'une valeur (Remove-ItemProperty interpréterait « * » comme un joker).
    param([string]$Chemin, [string]$Nom)
    $item = Get-Item -LiteralPath $Chemin
    $parties = $item.Name.Split([char[]]@('\'), 2)
    $racine = $null
    if ($parties[0] -eq 'HKEY_LOCAL_MACHINE') { $racine = [Microsoft.Win32.Registry]::LocalMachine }
    elseif ($parties[0] -eq 'HKEY_USERS') { $racine = [Microsoft.Win32.Registry]::Users }
    elseif ($parties[0] -eq 'HKEY_CURRENT_USER') { $racine = [Microsoft.Win32.Registry]::CurrentUser }
    if (-not $racine) { throw ('ruche non prise en charge : {0}' -f $parties[0]) }
    $cle = $racine.OpenSubKey($parties[1], $true)
    if ($cle) {
        try { $cle.DeleteValue($Nom, $false) } finally { $cle.Close() }
    }
}

function Restore-Element {
    param($e)
    $type = [string]$e.Type
    if ($type -eq 'Registre') {
        $chemin = [string]$e.Chemin
        $nom = [string]$e.Nom
        if ($e.Existait) {
            if (-not (Test-Path -LiteralPath $chemin)) { New-Item -Path $chemin -Force | Out-Null }
            $typeValeur = [string]$e.TypeValeur
            $valeur = $e.Valeur
            if ($typeValeur -eq 'DWord') { $valeur = [int]$valeur }
            elseif ($typeValeur -eq 'QWord') { $valeur = [long]$valeur }
            elseif ($typeValeur -eq 'Binary') { $valeur = [byte[]]@($valeur) }
            elseif ($typeValeur -eq 'MultiString') { $valeur = [string[]]@($valeur) }
            else { $valeur = [string]$valeur }
            New-ItemProperty -LiteralPath $chemin -Name $nom -Value $valeur -PropertyType $typeValeur -Force | Out-Null
            return ('Registre : valeur d''origine remise ({0} \ {1})' -f $chemin, $nom)
        }
        if (Test-Path -LiteralPath $chemin) { Remove-ValeurRegistre -Chemin $chemin -Nom $nom }
        $cles = @()
        if ($e.ClesCreees) { $cles = @($e.ClesCreees) }
        [array]::Reverse($cles)
        foreach ($k in $cles) {
            if (Test-Path -LiteralPath $k) {
                $item = Get-Item -LiteralPath $k
                if ($item.ValueCount -eq 0 -and $item.SubKeyCount -eq 0) { Remove-Item -LiteralPath $k -Force }
            }
        }
        return ('Registre : valeur ajoutée supprimée ({0} \ {1})' -f $chemin, $nom)
    }
    if ($type -eq 'Service') {
        $nom = [string]$e.Nom
        $start = -1
        if ($null -ne $e.Start) { $start = [int]$e.Start }
        $mode = 'demand'
        if ($start -eq 0) { $mode = 'boot' }
        elseif ($start -eq 1) { $mode = 'system' }
        elseif ($start -eq 2) { if ($e.Delai -eq 1) { $mode = 'delayed-auto' } else { $mode = 'auto' } }
        elseif ($start -eq 4) { $mode = 'disabled' }
        $r = Invoke-Natif -Fichier 'sc.exe' -Arguments @('config', $nom, 'start=', $mode)
        if ($r.Code -ne 0) { throw ('sc.exe : {0}' -f $r.Sortie) }
        if ($e.EnCours) { Start-Service -Name $nom -ErrorAction SilentlyContinue }
        return ('Service {0} : démarrage « {1} » rétabli' -f $nom, $mode)
    }
    if ($type -eq 'Fonctionnalite') {
        Enable-WindowsOptionalFeature -Online -FeatureName ([string]$e.Nom) -All -NoRestart -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
        return ('Fonctionnalité réactivée : {0}' -f $e.Nom)
    }
    if ($type -eq 'DefenderPreference') {
        $nom = [string]$e.Nom
        $valeur = $e.Valeur
        if ($null -eq $valeur) { return ('Defender : {0} sans valeur d''origine, laissé tel quel' -f $nom) }
        if ($EnumsDefender.ContainsKey($nom) -and $EnumsDefender[$nom].ContainsKey([string]$valeur)) { $valeur = $EnumsDefender[$nom][[string]$valeur] }
        $parametres = @{ $nom = $valeur }
        Set-MpPreference @parametres -ErrorAction Stop
        return ('Defender : {0} remis à « {1} »' -f $nom, $valeur)
    }
    if ($type -eq 'DefenderAsr') {
        $id = [string]$e.Id
        if ($null -eq $e.Avant -or [int]$e.Avant -eq 5) {
            Remove-MpPreference -AttackSurfaceReductionRules_Ids $id -ErrorAction Stop
            return ('Règle ASR {0} retirée' -f $id)
        }
        $action = 'Disabled'
        if ($NomsActionsAsr.ContainsKey([int]$e.Avant)) { $action = $NomsActionsAsr[[int]$e.Avant] }
        Remove-MpPreference -AttackSurfaceReductionRules_Ids $id -ErrorAction SilentlyContinue
        Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions $action -ErrorAction Stop
        return ('Règle ASR {0} remise en mode {1}' -f $id, $action)
    }
    if ($type -eq 'DefenderAsrExclusion') {
        Remove-MpPreference -AttackSurfaceReductionOnlyExclusions ([string]$e.Chemin) -ErrorAction Stop
        return ('Exclusion ASR retirée : {0}' -f $e.Chemin)
    }
    if ($type -eq 'DefenderCfaApp') {
        Remove-MpPreference -ControlledFolderAccessAllowedApplications ([string]$e.Chemin) -ErrorAction Stop
        return ('Application retirée de l''accès contrôlé aux dossiers : {0}' -f $e.Chemin)
    }
    if ($type -eq 'PareFeuProfil') {
        $parametres = @{}
        foreach ($p in $e.Parametres.PSObject.Properties) { $parametres[$p.Name] = $p.Value }
        Set-NetFirewallProfile -Name ([string]$e.Profil) @parametres -ErrorAction Stop
        return ('Pare-feu : profil {0} restauré' -f $e.Profil)
    }
    if ($type -eq 'PareFeuRegle') {
        Remove-NetFirewallRule -Name ([string]$e.Nom) -ErrorAction SilentlyContinue
        return ('Pare-feu : règle {0} supprimée' -f $e.Nom)
    }
    if ($type -eq 'AuditPol') {
        $fichier = [string]$e.Fichier
        if (-not (Test-Path -LiteralPath (Join-Path $Dossier $fichier))) { throw ('fichier introuvable : {0}' -f $fichier) }
        Push-Location -LiteralPath $Dossier
        try { $r = Invoke-Natif -Fichier 'auditpol.exe' -Arguments @('/restore', ('/file:{0}' -f $fichier)) } finally { Pop-Location }
        if ($r.Code -ne 0) { throw ('auditpol : {0}' -f $r.Sortie) }
        return 'Stratégie d''audit d''origine restaurée'
    }
    if ($type -eq 'Journal') {
        try {
            $cfg = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration ([string]$e.Nom)
            if ($null -ne $e.TailleOctets) { $cfg.MaximumSizeInBytes = [long]$e.TailleOctets }
            if ($null -ne $e.Active) { $cfg.IsEnabled = [bool]$e.Active }
            $cfg.SaveChanges()
            return ('Journal {0} : réglages d''origine remis' -f $e.Nom)
        } catch {
            return ('Journal {0} : taille actuelle conservée (journal déjà plus volumineux)' -f $e.Nom)
        }
    }
    throw ('type d''élément inconnu : {0}' -f $type)
}

try { Clear-Host } catch { }
$ligne = '=' * 74
Write-Host $ligne -ForegroundColor Cyan
Write-Host '  ANNULATION DU DURCISSEMENT DE WINDOWS' -ForegroundColor Cyan
Write-Host $ligne -ForegroundColor Cyan

$fichiers = @(Get-ChildItem -LiteralPath $Dossier -Filter 'Sauvegarde-*.json' -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like 'Sauvegarde-*.json' } | Sort-Object -Property Name -Descending)
if ($fichiers.Count -eq 0) {
    Write-Host '  Aucune sauvegarde à restaurer dans ce dossier (annulation déjà faite ?).' -ForegroundColor Yellow
    Read-Host '  Appuyez sur Entrée pour fermer'
    exit 0
}
$total = 0
foreach ($f in $fichiers) {
    try {
        $d = Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($d.Elements) { $total += @($d.Elements).Count }
    } catch { }
}
Write-Host ('  {0} sauvegarde(s), {1} réglage(s) à remettre comme avant le durcissement.' -f $fichiers.Count, $total)
Write-Host '  Le point de restauration et la protection du système ne sont pas touchés.'
Write-Host ''
Write-Host '  Appuyez sur Entrée pour lancer l''annulation, ou fermez la fenêtre pour abandonner.' -ForegroundColor Yellow
[void](Read-Host)

foreach ($f in $fichiers) {
    Write-Host ''
    Write-Host ('── {0}' -f $f.Name) -ForegroundColor Cyan
    $donnees = $null
    try {
        $donnees = Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        Write-Ligne -Statut 'ECHEC' -Texte ('lecture impossible : {0}' -f $_.Exception.Message)
        $script:Echecs++
        continue
    }
    $elements = @()
    if ($donnees.Elements) { $elements = @($donnees.Elements) }
    [array]::Reverse($elements)
    $echecsFichier = 0
    foreach ($e in $elements) {
        try {
            $texte = Restore-Element -e $e
            Write-Ligne -Statut 'OK' -Texte $texte
            $script:Reussites++
        } catch {
            Write-Ligne -Statut 'ECHEC' -Texte ('{0} {1}{2} : {3}' -f $e.Type, $e.Nom, $e.Chemin, $_.Exception.Message)
            $script:Echecs++
            $echecsFichier++
        }
    }
    if ($echecsFichier -eq 0) {
        try { Rename-Item -LiteralPath $f.FullName -NewName ($f.Name + '.restaure') -ErrorAction Stop } catch { }
    }
}

try {
    $fichierJournal = Join-Path $Dossier ('Journal-Annulation-{0}.log' -f (Get-Date).ToString('yyyyMMdd-HHmmss'))
    [System.IO.File]::WriteAllLines($fichierJournal, [string[]]$Journal.ToArray(), $Utf8Bom)
} catch { }

Write-Host ''
Write-Host $ligne -ForegroundColor Cyan
Write-Host ('  Annulation terminée : {0} réglage(s) restauré(s), {1} échec(s).' -f $script:Reussites, $script:Echecs) -ForegroundColor Cyan
if ($script:Echecs -gt 0) {
    Write-Host '  Relancez l''annulation après redémarrage, ou utilisez le point de restauration (rstrui).' -ForegroundColor Yellow
}
Write-Host $ligne -ForegroundColor Cyan
$reponse = Read-Host '  Un redémarrage est nécessaire pour terminer. Redémarrer maintenant ? (O/N)'
if ($reponse -match '^\s*[oOyY]') {
    & shutdown.exe /r /t 10 /c 'Redémarrage pour terminer l''annulation du durcissement'
    Write-Host '  Redémarrage dans 10 secondes...' -ForegroundColor Cyan
    Start-Sleep -Seconds 3
} else {
    Write-Host '  Pensez à redémarrer l''ordinateur.' -ForegroundColor Yellow
    Read-Host '  Appuyez sur Entrée pour fermer'
}
'@

# =====================================================================
#  EXÉCUTION
# =====================================================================

$script:Debut = Get-Date
$script:Horodatage = $script:Debut.ToString('yyyyMMdd-HHmmss')
$script:Resultats = New-Object System.Collections.Generic.List[object]
$script:Sauvegarde = New-Object System.Collections.Generic.List[object]
$script:DejaSauvegarde = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
$script:Journal = New-Object System.Collections.Generic.List[string]
$script:Persistance = New-Object System.Collections.Generic.List[object]
$script:Compatibilite = New-Object System.Collections.Generic.List[object]
$script:Applications = New-Object System.Collections.Generic.List[object]
$script:EvenementsRecents = @()
$script:MisesAJour = $null
$script:RedemarrageRequis = $false
$script:DefenderActif = $false
$script:NumeroEtape = 0
$script:Utf8Bom = New-Object System.Text.UTF8Encoding $true
$script:Dossier = $null
$script:FichierSauvegarde = $null
$script:FichierJournal = $null
$script:FichierRapport = $null

$script:Systeme = Get-InfosSysteme
$script:Utilisateur = Get-ContexteUtilisateur

Show-Accueil

# Préparation obligatoire : sans dossier de sauvegarde ni script d'annulation, rien n'est modifié.
try {
    Initialize-Dossier
    Export-ScriptAnnulation
} catch {
    Write-Host ''
    Write-Host ('Impossible de préparer la sauvegarde : {0}' -f $_.Exception.Message) -ForegroundColor Red
    Write-Host 'Aucune modification n''a été faite.' -ForegroundColor Red
    Read-Host 'Appuyez sur Entrée pour fermer'
    exit 1
}

try {
    Invoke-Etape -Titre $TitresEtapes[0] -Actions { New-RaccourciBureau }, { New-PointRestauration }, { Find-ApplicationsPreservees }
    Invoke-Etape -Titre $TitresEtapes[1] -Actions { Set-DurcissementDefender }
    Invoke-Etape -Titre $TitresEtapes[2] -Actions { Test-ProtectionFalsification }
    Invoke-Etape -Titre $TitresEtapes[3] -Actions { Set-DurcissementPareFeu }
    Invoke-Etape -Titre $TitresEtapes[4] -Actions { Set-DurcissementProtocoles }
    Invoke-Etape -Titre $TitresEtapes[5] -Actions { Set-DurcissementIdentifiants }
    Invoke-Etape -Titre $TitresEtapes[6] -Actions { Set-DurcissementExecution }
    Invoke-Etape -Titre $TitresEtapes[7] -Actions { Test-Persistance }
    Invoke-Etape -Titre $TitresEtapes[8] -Actions { Set-DurcissementElevation }
    Invoke-Etape -Titre $TitresEtapes[9] -Actions { Test-ProtectionsExploitation }
    Invoke-Etape -Titre $TitresEtapes[10] -Actions { Set-DurcissementJournalisation }
    Invoke-Etape -Titre $TitresEtapes[11] -Actions { Set-DurcissementServices }
    Invoke-Etape -Titre $TitresEtapes[12] -Actions { Test-MisesAJour }
    Invoke-Etape -Titre $TitresEtapes[13] -Actions { Test-Compatibilite }
} finally {
    Write-Progress -Activity 'Durcissement de Windows' -Completed
    Save-Sauvegarde
    Export-Rapport
    Export-Journal
}

Show-Resume
