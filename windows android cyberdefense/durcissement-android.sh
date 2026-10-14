#!/bin/sh
# shellcheck shell=sh
# =====================================================================
#  durcissement-android.sh
#  Durcissement de sécurité d'un téléphone Android depuis Termux ou une
#  distribution proot (proot-distro), en une seule exécution, sans paramètre.
#
#  LANCEMENT
#    Dans la distribution proot :  sudo sh durcissement-android.sh
#    Directement dans Termux    :  sh durcissement-android.sh
#
#  À SAVOIR
#    Le « root » de proot est simulé : il ne donne AUCUN droit sur Android
#    lui-même (pare-feu, réglages système, applis). Le script agit donc là
#    où il le peut réellement :
#      1. Termux et la distribution proot : SSH, scripts de démarrage,
#         dépôts, mises à jour, clés ;
#      2. Android, en lecture : correctifs de sécurité, chiffrement,
#         démarrage vérifié, SELinux, débogage, root ;
#      3. Android, via le débogage sans fil (ADB), s'il est associé :
#         audit des applis à risque (accessibilité, superposition,
#         administrateurs, sources inconnues...) et quelques réglages sûrs,
#         puis le débogage est COUPÉ à la fin.
#    Chaque mesure indique la technique MITRE ATT&CK (Mobile ou Linux) contrée.
#
#  SÉCURITÉ DE L'OPÉRATION
#    Chaque fichier ou réglage modifié est sauvegardé avant modification dans
#    ~/durcissement-android/, avec un script d'annulation :
#      sudo sh ~/durcissement-android/annuler-durcissement.sh
#    Le script est idempotent : il peut être relancé sans effet de bord.
#    Rien n'est supprimé : les éléments suspects sont seulement signalés.
#
#  Compatible sh POSIX (dash, ash de BusyBox, bash) : Termux, Debian, Ubuntu,
#  Alpine, Arch Linux ARM...
# =====================================================================

# ---------------------------------------------------------------------
#  RÉGLAGES MODIFIABLES (facultatif : le script fonctionne sans y toucher)
# ---------------------------------------------------------------------

# Couper aussi le débogage USB à la fin (oui/non). Le débogage sans fil, lui,
# est toujours coupé à la fin s'il était actif.
COUPER_DEBOGAGE_USB=oui

# Magasins d'applications de confiance : les applis qu'ils ont installées ne
# sont pas signalées comme « installées hors magasin ».
MAGASINS_CONFIANCE='com.android.vending com.sec.android.app.samsungapps com.huawei.appmarket com.xiaomi.market com.xiaomi.mipicks com.heytap.market com.oppo.market com.amazon.venezia org.fdroid.fdroid com.aurora.store'

# Préfixes des applis du système ou du constructeur (non signalées).
PREFIXES_SYSTEME='android com.android. com.google. com.samsung. com.sec. com.miui. com.xiaomi. com.huawei. com.hihonor. com.oneplus. com.oplus. com.coloros. com.heytap. com.motorola. com.sony. com.lge. com.asus. com.nothing. com.transsion. com.realme.'

# ---------------------------------------------------------------------
#  Variables internes (les variables DURCI_* ne servent qu'aux tests)
# ---------------------------------------------------------------------
TERMUX_RACINE=${DURCI_TERMUX_RACINE:-/data/data/com.termux/files}
RACINE=${DURCI_RACINE:-}
HORODATAGE=$(date +%Y%m%d-%H%M%S)
DEBUT=$(date +%s)
NUM_ETAPE=0
NB_ETAPES=7
ADB=''
ADB_SERIE=''
GETPROP=''
REDEMARRAGE_SSHD=non
COMMANDE_SSHD=''

# Motifs recherchés dans les scripts de démarrage (expressions régulières étendues).
# Suspect : téléchargement suivi d'une exécution, shell inversé, charge encodée.
MOTIFS_SUSPECTS='(curl|wget)[^|;]*[|][[:space:]]*(ba|z|da)?sh|base64[[:space:]]+(-d|--decode)|/dev/tcp/|(^|[[:space:];&|])(nc|ncat|netcat)[[:space:]][^#]*-[ec]([[:space:]]|$)|socat[[:space:]][^#]*exec|python[0-9.]*[[:space:]]+-c[^#]*socket|perl[[:space:]]+-e[^#]*socket|mkfifo[[:space:]]'
# À vérifier : souvent légitime (alias sudo vers proot...), mais détournable.
MOTIFS_A_VERIFIER='alias[[:space:]]+(sudo|su|ssh)=|LD_PRELOAD=|PROMPT_COMMAND=|eval[[:space:]]+"?[$][(]'

# =====================================================================
#  OUTILS : affichage, résultats, sauvegarde
# =====================================================================

initialiser_couleurs() {
    if [ -t 1 ]; then
        C_VERT=$(printf '\033[32m'); C_JAUNE=$(printf '\033[33m'); C_ROUGE=$(printf '\033[31m')
        C_GRIS=$(printf '\033[90m'); C_CYAN=$(printf '\033[36m'); C_GRAS=$(printf '\033[1m'); C_RAZ=$(printf '\033[0m')
    else
        C_VERT=''; C_JAUNE=''; C_ROUGE=''; C_GRIS=''; C_CYAN=''; C_GRAS=''; C_RAZ=''
    fi
}

ligne() {   # $1 = statut (OK, ALERTE, ECHEC, IGNORE, INFO), $2 = texte
    case $1 in
        OK) _c=$C_VERT; _l='OK' ;;
        ALERTE) _c=$C_JAUNE; _l='ALERTE' ;;
        ECHEC) _c=$C_ROUGE; _l='ÉCHEC' ;;
        IGNORE) _c=$C_GRIS; _l='IGNORÉ' ;;
        *) _c=''; _l='INFO' ;;
    esac
    printf '  %s[%s]%s %s\n' "$_c" "$_l" "$C_RAZ" "$2"
}

patience() {
    printf '  %s... %s%s\n' "$C_GRIS" "$1" "$C_RAZ"
}

resultat() {   # $1 catégorie, $2 mesure, $3 ATT&CK, $4 statut, $5 détail, $6 impact
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "${6:-}" >> "$FICHIER_RESULTATS"
    if [ -n "$5" ]; then ligne "$4" "$2 — $5"; else ligne "$4" "$2"; fi
}

compter() {   # $1 = statut ; nombre de mesures ayant ce statut
    awk -F'\t' -v s="$1" '$4 == s { n++ } END { print n + 0 }' "$FICHIER_RESULTATS"
}

etape() {
    NUM_ETAPE=$((NUM_ETAPE + 1))
    printf '\n%s── %s/%s  %s%s\n' "$C_CYAN" "$NUM_ETAPE" "$NB_ETAPES" "$1" "$C_RAZ"
}

avec_delai() {   # $1 = secondes, puis la commande
    _delai=$1
    shift
    if command -v timeout >/dev/null 2>&1; then timeout "$_delai" "$@"; else "$@"; fi
}

noter() {   # ajoute une ligne au fichier de sauvegarde de cette exécution
    printf '%s\n' "$1" >> "$FICHIER_SAUVEGARDE"
}

deja_sauvegarde() {   # $1 = chemin
    awk -F'|' -v p="$1" '$1 == "FICHIER" && $2 == p { t = 1 } END { exit !t }' "$FICHIER_SAUVEGARDE" 2>/dev/null
}

sauvegarder_fichier() {   # $1 = chemin ; copie le fichier avant sa première modification
    deja_sauvegarde "$1" && return 0
    if [ -e "$1" ]; then
        _copie="$DOSSIER_COPIES/$(printf '%s' "$1" | sed 's#[/ ]#_#g')"
        cp -p "$1" "$_copie" 2>/dev/null || return 1
        noter "FICHIER|$1|$_copie"
    else
        noter "FICHIER|$1|"
    fi
    return 0
}

restaurer_fichier() {   # $1 = chemin : remet la copie de cette exécution (en cas d'échec)
    _copie=$(awk -F'|' -v p="$1" '$1 == "FICHIER" && $2 == p { print $3; exit }' "$FICHIER_SAUVEGARDE")
    if [ -n "$_copie" ] && [ -f "$_copie" ]; then cp -p "$_copie" "$1"; fi
}

remplacer_dans() {   # $1 fichier, $2 expression sed (en conservant droits et propriétaire)
    sed "$2" "$1" > "$1.durci-tmp" && cat "$1.durci-tmp" > "$1"
    _rc=$?
    rm -f "$1.durci-tmp"
    return $_rc
}

droits_restreints() {   # $1 = chemin, $2 = mode voulu (700, 600...) ; sauvegarde l'ancien mode
    [ -e "$1" ] || return 0
    _mode=$(stat -c %a "$1" 2>/dev/null)
    [ -z "$_mode" ] && return 0
    [ "$_mode" = "$2" ] && return 0
    noter "DROITS|$1|$_mode"
    chmod "$2" "$1" 2>/dev/null
    DROITS_MODIFIES=$((DROITS_MODIFIES + 1))
}

est_systeme() {   # $1 = nom de paquet Android
    for _p in $PREFIXES_SYSTEME; do
        case $1 in "$_p" | "$_p"*) return 0 ;; esac
    done
    return 1
}

est_magasin() {   # $1 = nom de paquet de l'installateur
    for _m in $MAGASINS_CONFIANCE; do
        [ "$1" = "$_m" ] && return 0
    done
    return 1
}

# =====================================================================
#  CONTEXTE : Termux ou distribution proot, droits, dossier de sauvegarde
# =====================================================================

detecter_environnement() {
    if [ -n "${DURCI_ENV:-}" ]; then
        ENV_TYPE=$DURCI_ENV
    elif [ -n "${TERMUX_VERSION:-}" ] || [ "${PREFIX:-}" = "$TERMUX_RACINE/usr" ]; then
        ENV_TYPE=termux
    elif [ -f "$RACINE/etc/os-release" ]; then
        ENV_TYPE=proot
    else
        ENV_TYPE=inconnu
    fi

    # Sous proot, les processus sont tracés (ptrace) : TracerPid n'est pas nul.
    SOUS_PROOT=non
    _traceur=$(awk '/^TracerPid:/ { print $2 }' /proc/self/status 2>/dev/null)
    [ -n "$_traceur" ] && [ "$_traceur" != 0 ] && SOUS_PROOT=oui

    # Termux est-il accessible (directement, ou depuis la distribution) ?
    TERMUX_HOME=''
    TERMUX_PREFIX=''
    if [ "$ENV_TYPE" = termux ]; then
        TERMUX_HOME=$HOME
        TERMUX_PREFIX=${PREFIX:-$TERMUX_RACINE/usr}
    else
        [ -d "$TERMUX_RACINE/home" ] && [ -w "$TERMUX_RACINE/home" ] && TERMUX_HOME=$TERMUX_RACINE/home
        [ -d "$TERMUX_RACINE/usr/etc" ] && [ -w "$TERMUX_RACINE/usr/etc" ] && TERMUX_PREFIX=$TERMUX_RACINE/usr
    fi

    DISTRIB=''
    if [ "$ENV_TYPE" = proot ]; then
        # shellcheck source=/dev/null
        DISTRIB=$(. "$RACINE/etc/os-release" 2>/dev/null; printf '%s' "${PRETTY_NAME:-${NAME:-Linux}}")
    fi

    # getprop d'Android (directement dans Termux ; parfois aussi depuis proot)
    for _g in getprop /system/bin/getprop; do
        if command -v "$_g" >/dev/null 2>&1 && [ -n "$("$_g" ro.build.version.sdk 2>/dev/null)" ]; then
            GETPROP=$_g
            break
        fi
    done
}

verifier_droits() {
    if [ "$ENV_TYPE" = inconnu ]; then
        printf '%sCe script est prévu pour Termux ou une distribution proot sur Android.%s\n' "$C_ROUGE" "$C_RAZ"
        exit 1
    fi
    if [ "$ENV_TYPE" = proot ] && [ "$(id -u)" != 0 ]; then
        printf '%sDans la distribution proot, lancez-le avec sudo :%s\n' "$C_JAUNE" "$C_RAZ"
        printf '    sudo sh %s\n' "$0"
        exit 1
    fi
}

dossier_sauvegarde() {
    if [ -n "${DURCI_DOSSIER:-}" ]; then printf '%s' "$DURCI_DOSSIER"; return; fi
    _maison=$HOME
    # Lancé avec sudo : on range les fichiers chez l'utilisateur qui a lancé sudo.
    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ] && command -v getent >/dev/null 2>&1; then
        _m=$(getent passwd "$SUDO_USER" | cut -d: -f6)
        [ -n "$_m" ] && [ -d "$_m" ] && _maison=$_m
    fi
    printf '%s/durcissement-android' "$_maison"
}

preparer_dossier() {
    DOSSIER=$(dossier_sauvegarde)
    DOSSIER_COPIES="$DOSSIER/copies-$HORODATAGE"
    FICHIER_SAUVEGARDE="$DOSSIER/sauvegarde-$HORODATAGE.txt"
    FICHIER_RAPPORT="$DOSSIER/rapport-$HORODATAGE.txt"
    FICHIER_RESULTATS="$DOSSIER/.resultats-$HORODATAGE.tsv"
    FICHIER_PERSIST="$DOSSIER/.persistance-$HORODATAGE.tsv"
    FICHIER_APPLIS="$DOSSIER/.applis-$HORODATAGE.tsv"
    if ! mkdir -p "$DOSSIER_COPIES" 2>/dev/null; then
        printf '%sImpossible de créer %s : aucune modification faite.%s\n' "$C_ROUGE" "$DOSSIER" "$C_RAZ"
        exit 1
    fi
    chmod 700 "$DOSSIER" "$DOSSIER_COPIES" 2>/dev/null
    : > "$FICHIER_SAUVEGARDE"
    : > "$FICHIER_RESULTATS"
    : > "$FICHIER_PERSIST"
    : > "$FICHIER_APPLIS"
    if [ ! -f "$FICHIER_SAUVEGARDE" ]; then
        printf '%sImpossible d'"'"'écrire la sauvegarde : aucune modification faite.%s\n' "$C_ROUGE" "$C_RAZ"
        exit 1
    fi
}

accueil() {
    printf '%s%s\n' "$C_CYAN" '=========================================================================='
    printf '  DURCISSEMENT DE SÉCURITÉ — ANDROID (Termux / proot)\n'
    printf '%s%s\n' '==========================================================================' "$C_RAZ"
    if [ "$ENV_TYPE" = termux ]; then
        printf '  Environnement : Termux'
    else
        printf '  Environnement : %s (proot)' "$DISTRIB"
    fi
    if [ -n "$TERMUX_HOME" ]; then printf ' — dossiers de Termux accessibles\n'; else printf '\n'; fi
    if [ "$SOUS_PROOT" = oui ] && [ "$(id -u)" = 0 ]; then
        printf '  Droits : root simulé par proot (aucun droit réel sur Android)\n'
    fi
    printf '\n  Ce script va, en une seule fois :\n'
    printf '    1. sauvegarder chaque réglage modifié et préparer un script d'"'"'annulation ;\n'
    printf '    2. durcir Termux et la distribution proot (SSH, démarrage, dépôts, clés) ;\n'
    printf '    3. contrôler Android : correctifs, chiffrement, démarrage vérifié, SELinux ;\n'
    printf '    4. si le débogage sans fil est associé : contrôler les applis à risque,\n'
    printf '       appliquer quelques réglages sûrs, puis COUPER le débogage.\n'
    printf '\n  %sÀ savoir :%s le « root » de proot est simulé. Il ne donne aucun droit sur\n' "$C_GRAS" "$C_RAZ"
    printf '  Android lui-même : rien n'"'"'est modifié dans le système sans le débogage sans fil.\n'
    printf '\n  Durée estimée : 1 à 5 minutes. Rien n'"'"'est supprimé.\n'
    printf '\n  %sAppuyez sur Entrée pour continuer, ou Ctrl+C pour annuler.%s ' "$C_JAUNE" "$C_RAZ"
    read -r _reponse
}

# =====================================================================
#  ANDROID : lecture des propriétés et connexion ADB (débogage sans fil)
# =====================================================================

prop() {   # $1 = nom de propriété Android
    if [ -n "$GETPROP" ]; then
        "$GETPROP" "$1" 2>/dev/null | tr -d '\r'
        return
    fi
    if [ -n "$ADB_SERIE" ]; then
        adb_shell getprop "$1"
        return
    fi
    for _f in /system/build.prop /vendor/build.prop; do
        if [ -r "$_f" ]; then
            _v=$(sed -n "s/^$1=//p" "$_f" | head -n 1)
            if [ -n "$_v" ]; then printf '%s' "$_v"; return; fi
        fi
    done
}

adb_shell() {
    avec_delai 30 "$ADB" -s "$ADB_SERIE" shell "$@" 2>/dev/null | tr -d '\r'
}

reglage_lire() {   # $1 = espace (global, secure, system), $2 = clé
    _val=$(adb_shell settings get "$1" "$2")
    printf '%s' "${_val:-null}"
}

reglage_ecrire() {   # $1 espace, $2 clé, $3 valeur ; renvoie 0 appliqué, 1 échec
    _ancien=$(reglage_lire "$1" "$2")
    noter "ADB|$1|$2|$_ancien"
    adb_shell settings put "$1" "$2" "$3" > /dev/null
    [ "$(reglage_lire "$1" "$2")" = "$3" ]
}

premier_appareil() {
    avec_delai 15 "$ADB" devices 2>/dev/null | awk 'NR > 1 && $2 == "device" { print $1; exit }'
}

preparer_adb() {
    _cat='Android (ADB)'
    _mesure='Connexion au téléphone par le débogage sans fil'
    ADB=$(command -v adb 2>/dev/null)
    if [ -z "$ADB" ]; then
        resultat "$_cat" "$_mesure" 'T1458' IGNORE 'adb non installé : contrôle des applis et réglages Android ignorés (facultatif, voir le rapport)'
        return
    fi
    _version=$("$ADB" version 2>/dev/null | sed -n 's/^Version \([0-9][0-9]*\).*/\1/p' | head -n 1)
    avec_delai 20 "$ADB" start-server > /dev/null 2>&1
    ADB_SERIE=$(premier_appareil)

    # 1. Port du débogage sans fil publié par Android (association déjà faite)
    if [ -z "$ADB_SERIE" ]; then
        _port=$(prop service.adb.tls.port)
        if [ -n "$_port" ] && [ "$_port" != 0 ] && [ "$_port" != -1 ]; then
            avec_delai 15 "$ADB" connect "127.0.0.1:$_port" > /dev/null 2>&1
            ADB_SERIE=$(premier_appareil)
        fi
    fi
    # 2. Découverte automatique (mDNS)
    if [ -z "$ADB_SERIE" ]; then
        for _adresse in $(avec_delai 10 "$ADB" mdns services 2>/dev/null | awk '/_adb-tls-connect/ { print $NF }'); do
            avec_delai 15 "$ADB" connect "$_adresse" > /dev/null 2>&1
        done
        ADB_SERIE=$(premier_appareil)
    fi
    # 3. Saisie facultative du port, et association si besoin (une seule fois)
    if [ -z "$ADB_SERIE" ] && [ -t 0 ]; then
        printf '\n  Débogage sans fil (facultatif, pour contrôler les applis et régler Android) :\n'
        printf '  Options pour les développeurs > Débogage sans fil > « Adresse IP et port ».\n'
        printf '  Tapez le port (les chiffres après « : »), ou Entrée pour passer : '
        read -r _port
        case $_port in
            *[!0-9]* | '') _port='' ;;
        esac
        if [ -n "$_port" ]; then
            avec_delai 15 "$ADB" connect "127.0.0.1:$_port" > /dev/null 2>&1
            ADB_SERIE=$(premier_appareil)
            if [ -z "$ADB_SERIE" ]; then
                if [ -n "$_version" ] && [ "$_version" -lt 30 ]; then
                    printf '  %sadb %s est trop ancien pour l'"'"'association (version 30 ou plus).%s\n' "$C_JAUNE" "$_version" "$C_RAZ"
                else
                    printf '  Première fois : touchez « Associer l'"'"'appareil avec un code ».\n'
                    printf '  Port d'"'"'association (Entrée pour passer) : '
                    read -r _port_assoc
                    case $_port_assoc in *[!0-9]* | '') _port_assoc='' ;; esac
                    if [ -n "$_port_assoc" ]; then
                        printf '  Code à 6 chiffres : '
                        read -r _code
                        avec_delai 30 "$ADB" pair "127.0.0.1:$_port_assoc" "$_code" > /dev/null 2>&1
                        avec_delai 15 "$ADB" connect "127.0.0.1:$_port" > /dev/null 2>&1
                        ADB_SERIE=$(premier_appareil)
                    fi
                fi
            fi
        fi
    fi

    if [ -n "$ADB_SERIE" ]; then
        resultat "$_cat" "$_mesure" 'T1458' OK "connecté ($ADB_SERIE) — le débogage sera coupé à la fin"
    else
        resultat "$_cat" "$_mesure" 'T1458' IGNORE 'non connecté : contrôle des applis et réglages Android ignorés (facultatif, voir le rapport)'
    fi
}

# =====================================================================
#  OUTILS : inventaire des scripts lancés automatiquement (persistance)
# =====================================================================

analyser_script() {   # $1 fichier, $2 groupe, $3 libellé ; rien n'est modifié
    [ -f "$1" ] && [ -r "$1" ] || return 0
    NB_ENTREES=$((NB_ENTREES + 1))
    _niveau='OK'
    _raison='aucun motif suspect'
    # Les lignes de commentaire sont ignorées.
    _trouve=$(grep -v '^[[:space:]]*#' "$1" 2>/dev/null | grep -Ei "$MOTIFS_SUSPECTS" | head -n 1)
    if [ -n "$_trouve" ]; then
        _niveau='SUSPECT'
        NB_SUSPECTS=$((NB_SUSPECTS + 1))
    else
        _trouve=$(grep -v '^[[:space:]]*#' "$1" 2>/dev/null | grep -Ei "$MOTIFS_A_VERIFIER" | head -n 1)
        if [ -n "$_trouve" ]; then
            _niveau='A_VERIFIER'
            NB_A_VERIFIER=$((NB_A_VERIFIER + 1))
        fi
    fi
    [ -n "$_trouve" ] && _raison="ligne : $(printf '%s' "$_trouve" | cut -c1-160 | tr '\t' ' ')"
    printf '%s\t%s\t%s\t%s\n' "$2" "$3: $1" "$_niveau" "$_raison" >> "$FICHIER_PERSIST"
}

debut_inventaire() {
    NB_ENTREES=0
    NB_SUSPECTS=0
    NB_A_VERIFIER=0
}

fin_inventaire() {   # $1 catégorie, $2 mesure, $3 ATT&CK
    if [ "$NB_ENTREES" -eq 0 ]; then
        resultat "$1" "$2" "$3" OK 'aucun'
    elif [ "$NB_SUSPECTS" -gt 0 ]; then
        resultat "$1" "$2" "$3" ALERTE "$NB_ENTREES fichier(s) : $NB_SUSPECTS SUSPECT(S), $NB_A_VERIFIER à vérifier — détail dans le rapport, rien n'a été supprimé"
    else
        resultat "$1" "$2" "$3" INFO "$NB_ENTREES fichier(s) : aucun suspect, $NB_A_VERIFIER à vérifier — détail dans le rapport"
    fi
}

# =====================================================================
#  SSH (Termux et distribution) — T1021.004, T1110
# =====================================================================

durcir_sshd() {   # $1 config, $2 clés présentes (oui/non), $3 interdire root (oui/non), $4 binaire sshd, $5 catégorie
    _cfg=$1
    _bloc='# >>> durcissement-android >>>
# Ajouté par durcissement-android.sh. Placé en tête : dans sshd_config,
# la première valeur lue l'"'"'emporte.
PermitEmptyPasswords no
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no'
    if [ "$3" = oui ]; then _bloc="$_bloc
PermitRootLogin no"; fi
    if [ "$2" = oui ]; then _bloc="$_bloc
PasswordAuthentication no
ChallengeResponseAuthentication no"; fi
    _bloc="$_bloc
# <<< durcissement-android <<<"

    _sans=$(sed '/^# >>> durcissement-android >>>$/,/^# <<< durcissement-android <<<$/d' "$_cfg")
    _nouveau=$(printf '%s\n%s' "$_bloc" "$_sans")
    _mesure='Durcir le serveur SSH'
    if [ "$_nouveau" = "$(cat "$_cfg")" ]; then
        resultat "$5" "$_mesure" 'T1021.004, T1110' OK 'déjà en place' 'Aucun'
    else
        _valide_avant=non
        if [ -x "$4" ] && "$4" -t -f "$_cfg" > /dev/null 2>&1; then _valide_avant=oui; fi
        if ! sauvegarder_fichier "$_cfg"; then
            resultat "$5" "$_mesure" 'T1021.004, T1110' ECHEC 'sauvegarde impossible : rien modifié'
            return
        fi
        printf '%s\n' "$_nouveau" > "$_cfg"
        if [ "$_valide_avant" = oui ] && ! "$4" -t -f "$_cfg" > /dev/null 2>&1; then
            restaurer_fichier "$_cfg"
            resultat "$5" "$_mesure" 'T1021.004, T1110' ECHEC 'configuration refusée par sshd : fichier d'"'"'origine remis'
            return
        fi
        REDEMARRAGE_SSHD=oui
        if [ "$5" = Termux ]; then
            COMMANDE_SSHD='dans Termux : pkill sshd puis sshd'
        else
            COMMANDE_SSHD='dans la distribution : sudo pkill sshd puis sudo /usr/sbin/sshd (ou sudo service ssh restart)'
        fi
        resultat "$5" "$_mesure" 'T1021.004, T1110' OK 'appliqué (3 essais maximum, pas de mot de passe vide)' 'Aucun pour un usage normal de SSH'
    fi
    if [ "$2" = oui ]; then
        resultat "$5" 'Connexion SSH par clé uniquement' 'T1110, T1021.004' OK 'mots de passe refusés : une clé est autorisée' 'Il faut votre clé SSH pour vous connecter'
    else
        resultat "$5" 'Connexion SSH par clé uniquement' 'T1110, T1021.004' ALERTE 'aucune clé autorisée : la connexion par mot de passe reste possible (ajoutez une clé dans ~/.ssh/authorized_keys puis relancez le script)'
    fi
}

# =====================================================================
#  1. TERMUX
# =====================================================================

termux_proprietes() {
    # Les autres applis Android ne peuvent plus lancer de commandes dans Termux — T1623
    _cat='Termux'
    _mesure='Interdire aux autres applis de lancer des commandes (allow-external-apps)'
    _modifie=non
    _echec=non
    for _f in "$TERMUX_HOME/.termux/termux.properties" "$TERMUX_HOME/.config/termux/termux.properties"; do
        [ -f "$_f" ] || continue
        if grep -Eq '^[[:space:]]*allow-external-apps[[:space:]]*[=:][[:space:]]*true[[:space:]]*$' "$_f"; then
            if sauvegarder_fichier "$_f" && remplacer_dans "$_f" 's/^\([[:space:]]*allow-external-apps[[:space:]]*[=:][[:space:]]*\)true[[:space:]]*$/\1false/'; then
                _modifie=oui
            else
                _echec=oui
            fi
        fi
    done
    if [ "$_echec" = oui ]; then
        resultat "$_cat" "$_mesure" 'T1623' ECHEC 'modification impossible'
    elif [ "$_modifie" = oui ]; then
        _detail='désactivé (true → false), effectif au prochain démarrage de Termux'
        if [ "$ENV_TYPE" = termux ] && command -v termux-reload-settings > /dev/null 2>&1 && termux-reload-settings > /dev/null 2>&1; then
            _detail='désactivé (true → false) et appliqué'
        fi
        resultat "$_cat" "$_mesure" 'T1623' OK "$_detail" 'Les applis tierces (Tasker...) ne peuvent plus lancer de commandes dans Termux'
    else
        resultat "$_cat" "$_mesure" 'T1623' OK 'déjà désactivé' 'Aucun'
    fi
}

termux_demarrage() {
    # Scripts lancés au démarrage du téléphone (Termux:Boot) et tâches cron — T1398, T1603
    debut_inventaire
    for _f in "$TERMUX_HOME"/.termux/boot/*; do
        analyser_script "$_f" 'Termux:Boot' 'Démarrage Termux:Boot'
    done
    fin_inventaire 'Termux' 'Scripts lancés au démarrage du téléphone (Termux:Boot)' 'T1398'

    debut_inventaire
    if [ -n "$TERMUX_PREFIX" ]; then
        for _f in "$TERMUX_PREFIX"/var/spool/cron/crontabs/* "$TERMUX_PREFIX"/var/spool/cron/*; do
            analyser_script "$_f" 'Cron Termux' 'Tâche cron'
        done
    fi
    fin_inventaire 'Termux' 'Tâches planifiées (cron) de Termux' 'T1603'

    if [ -n "$TERMUX_PREFIX" ] && [ -d "$TERMUX_PREFIX/var/service" ]; then
        _actifs=''
        for _s in "$TERMUX_PREFIX"/var/service/*; do
            [ -d "$_s" ] || continue
            [ -f "$_s/down" ] && continue
            _actifs="$_actifs ${_s##*/}"
        done
        if [ -n "$_actifs" ]; then
            resultat 'Termux' 'Services lancés automatiquement (termux-services)' 'T1398' INFO "actifs :$_actifs (sv-disable <nom> pour en couper un)"
        else
            resultat 'Termux' 'Services lancés automatiquement (termux-services)' 'T1398' OK 'aucun'
        fi
    fi
}

termux_shell() {
    # Fichiers de démarrage du shell — T1546.004
    debut_inventaire
    for _f in "$TERMUX_HOME/.bashrc" "$TERMUX_HOME/.bash_profile" "$TERMUX_HOME/.profile" "$TERMUX_HOME/.zshrc" \
        "$TERMUX_HOME/.zprofile" "$TERMUX_HOME/.config/fish/config.fish"; do
        analyser_script "$_f" 'Shell Termux' 'Démarrage du shell'
    done
    if [ -n "$TERMUX_PREFIX" ]; then
        for _f in "$TERMUX_PREFIX/etc/bash.bashrc" "$TERMUX_PREFIX/etc/profile" "$TERMUX_PREFIX/etc/zshrc" "$TERMUX_PREFIX"/etc/profile.d/*; do
            analyser_script "$_f" 'Shell Termux' 'Démarrage du shell'
        done
    fi
    fin_inventaire 'Termux' 'Fichiers de démarrage du shell (.bashrc, profile...)' 'T1546.004'
}

termux_ssh() {
    if [ -z "$TERMUX_PREFIX" ] || [ ! -f "$TERMUX_PREFIX/etc/ssh/sshd_config" ]; then
        resultat 'Termux' 'Durcir le serveur SSH' 'T1021.004, T1110' IGNORE 'serveur SSH non installé'
        return
    fi
    _cles=non
    [ -s "$TERMUX_HOME/.ssh/authorized_keys" ] && _cles=oui
    durcir_sshd "$TERMUX_PREFIX/etc/ssh/sshd_config" "$_cles" non "$TERMUX_PREFIX/bin/sshd" 'Termux'
}

termux_cles() {
    # Droits des clés SSH — T1552.004 ; clés autorisées — T1098.004
    DROITS_MODIFIES=0
    _d="$TERMUX_HOME/.ssh"
    if [ ! -d "$_d" ]; then
        resultat 'Termux' 'Droits des clés SSH' 'T1552.004' OK 'aucun dossier .ssh'
        return
    fi
    droits_restreints "$_d" 700
    for _f in "$_d"/*; do
        [ -f "$_f" ] || continue
        case $_f in
            *.pub | */known_hosts | */known_hosts.old) ;;
            *) droits_restreints "$_f" 600 ;;
        esac
    done
    if [ "$DROITS_MODIFIES" -gt 0 ]; then
        resultat 'Termux' 'Droits des clés SSH' 'T1552.004' OK "$DROITS_MODIFIES droit(s) restreint(s) (700/600)" 'Aucun'
    else
        resultat 'Termux' 'Droits des clés SSH' 'T1552.004' OK 'déjà en place'
    fi
    if [ -s "$_d/authorized_keys" ]; then
        _n=$(grep -c '^[^#[:space:]]' "$_d/authorized_keys")
        resultat 'Termux' 'Clés autorisées à se connecter en SSH' 'T1098.004' INFO "$_n clé(s) dans ~/.ssh/authorized_keys : vérifiez que vous les connaissez toutes"
    fi
}

termux_depots() {
    # Dépôts de paquets chiffrés (HTTPS) — T1474, T1638
    [ -n "$TERMUX_PREFIX" ] || return 0
    _http=''
    for _f in "$TERMUX_PREFIX/etc/apt/sources.list" "$TERMUX_PREFIX"/etc/apt/sources.list.d/*.list; do
        [ -f "$_f" ] || continue
        if grep -Eq '^[[:space:]]*deb[[:space:]]+(\[[^]]*\][[:space:]]+)?http://' "$_f"; then _http="$_http ${_f##*/}"; fi
    done
    if [ -n "$_http" ]; then
        resultat 'Termux' 'Dépôts de paquets en HTTPS' 'T1474, T1638' ALERTE "dépôt non chiffré (http) dans :$_http — lancez termux-change-repo et choisissez un miroir"
    else
        resultat 'Termux' 'Dépôts de paquets en HTTPS' 'T1474, T1638' OK 'tous les dépôts sont en HTTPS'
    fi
}

verifier_maj_apt() {   # $1 catégorie, $2 commande conseillée
    if [ -n "${DURCI_SANS_RESEAU:-}" ]; then
        resultat "$1" 'Paquets à mettre à jour' 'T1404, T1664' IGNORE 'vérification sautée (mode test)'
        return
    fi
    patience 'recherche des mises à jour de paquets (jusqu'"'"'à 3 minutes)'
    if ! avec_delai 180 apt-get update -qq > /dev/null 2>&1; then
        resultat "$1" 'Paquets à mettre à jour' 'T1404, T1664' ALERTE "vérification impossible (pas de réseau ?) : lancez « $2 »"
        return
    fi
    _n=$(apt-get -s upgrade 2>/dev/null | grep -c '^Inst ')
    if [ "${_n:-0}" -gt 0 ]; then
        resultat "$1" 'Paquets à mettre à jour' 'T1404, T1664' ALERTE "$_n paquet(s) à mettre à jour : lancez « $2 »"
    else
        resultat "$1" 'Paquets à mettre à jour' 'T1404, T1664' OK 'tout est à jour'
    fi
}

termux_divers() {
    if [ "$ENV_TYPE" = termux ] && command -v apt-get > /dev/null 2>&1; then
        verifier_maj_apt 'Termux' 'pkg upgrade'
    fi
    # Accès au stockage partagé — T1533
    if [ -e "$TERMUX_HOME/storage" ]; then
        resultat 'Termux' 'Accès au stockage partagé (photos, téléchargements)' 'T1533' INFO 'autorisé : tout script lancé dans Termux peut lire ces fichiers. Si inutile : Paramètres > Applis > Termux > Autorisations > Fichiers > Refuser'
    else
        resultat 'Termux' 'Accès au stockage partagé (photos, téléchargements)' 'T1533' OK 'non autorisé'
    fi
    # Termux:API — T1636
    if [ -n "$TERMUX_PREFIX" ] && [ -x "$TERMUX_PREFIX/bin/termux-sms-list" ]; then
        resultat 'Termux' 'Termux:API (SMS, contacts, position)' 'T1636' INFO 'installé : selon les autorisations données à l'"'"'appli Termux:API, un script peut lire SMS, contacts et position. Retirez celles qui ne servent pas'
    fi
}

# =====================================================================
#  2. DISTRIBUTION PROOT
# =====================================================================

distro_ssh() {
    _cfg="$RACINE/etc/ssh/sshd_config"
    if [ ! -f "$_cfg" ]; then
        resultat 'Distribution proot' 'Durcir le serveur SSH' 'T1021.004, T1110' IGNORE 'serveur SSH non installé'
        return
    fi
    _cles=non
    for _k in "$RACINE"/root/.ssh/authorized_keys "$RACINE"/home/*/.ssh/authorized_keys; do
        [ -s "$_k" ] && _cles=oui
    done
    durcir_sshd "$_cfg" "$_cles" oui "$RACINE/usr/sbin/sshd" 'Distribution proot'
}

distro_comptes() {
    _cat='Distribution proot'
    # Comptes avec l'identifiant 0 en plus de root — T1078.003, T1136.001
    _uid0=$(awk -F: '$3 == 0 && $1 != "root" { printf "%s%s", s, $1; s = ", " }' "$RACINE/etc/passwd" 2>/dev/null)
    if [ -n "$_uid0" ]; then
        resultat "$_cat" 'Comptes avec les droits root' 'T1078.003, T1136.001' ALERTE "comptes en plus de root : $_uid0"
    else
        resultat "$_cat" 'Comptes avec les droits root' 'T1078.003, T1136.001' OK 'root uniquement'
    fi
    # Comptes sans mot de passe — T1078.003
    if [ -r "$RACINE/etc/shadow" ]; then
        _vides=$(awk -F: '$2 == "" { printf "%s%s", s, $1; s = ", " }' "$RACINE/etc/shadow")
        if [ -n "$_vides" ]; then
            resultat "$_cat" 'Comptes sans mot de passe' 'T1078.003' ALERTE "comptes : $_vides — donnez-leur un mot de passe (sudo passwd <compte>) ou verrouillez-les (sudo passwd -l <compte>)"
        else
            resultat "$_cat" 'Comptes sans mot de passe' 'T1078.003' OK 'aucun'
        fi
    fi
    # sudo sans mot de passe — T1548.003
    _nopass=$(cat "$RACINE/etc/sudoers" "$RACINE"/etc/sudoers.d/* 2>/dev/null | grep -E '^[^#]*NOPASSWD' | awk '{ printf "%s%s", s, $1; s = ", " }')
    if [ -n "$_nopass" ]; then
        resultat "$_cat" 'sudo sans mot de passe' 'T1548.003' INFO "pour : $_nopass (courant avec proot-distro ; le root y est de toute façon simulé)"
    else
        resultat "$_cat" 'sudo sans mot de passe' 'T1548.003' OK 'non'
    fi
    # Clés SSH autorisées — T1098.004
    _n=0
    for _k in "$RACINE"/root/.ssh/authorized_keys "$RACINE"/home/*/.ssh/authorized_keys; do
        [ -s "$_k" ] || continue
        _n=$((_n + $(grep -c '^[^#[:space:]]' "$_k")))
    done
    if [ "$_n" -gt 0 ]; then
        resultat "$_cat" 'Clés autorisées à se connecter en SSH' 'T1098.004' INFO "$_n clé(s) : vérifiez que vous les connaissez toutes"
    fi
}

distro_demarrage() {
    _cat='Distribution proot'
    # Tâches cron — T1053.003
    debut_inventaire
    for _f in "$RACINE/etc/crontab" "$RACINE"/etc/cron.d/* "$RACINE"/var/spool/cron/crontabs/* "$RACINE"/var/spool/cron/*; do
        analyser_script "$_f" 'Cron distribution' 'Tâche cron'
    done
    fin_inventaire "$_cat" 'Tâches planifiées (cron)' 'T1053.003'
    # Fichiers de démarrage du shell — T1546.004
    debut_inventaire
    for _f in "$RACINE/etc/profile" "$RACINE/etc/bash.bashrc" "$RACINE/etc/zsh/zshrc" "$RACINE"/etc/profile.d/*.sh \
        "$RACINE/root/.bashrc" "$RACINE/root/.profile" "$RACINE/root/.zshrc" \
        "$RACINE"/home/*/.bashrc "$RACINE"/home/*/.profile "$RACINE"/home/*/.zshrc; do
        analyser_script "$_f" 'Shell distribution' 'Démarrage du shell'
    done
    fin_inventaire "$_cat" 'Fichiers de démarrage du shell (.bashrc, profile...)' 'T1546.004'
}

distro_maj() {
    _cat='Distribution proot'
    if command -v apt-get > /dev/null 2>&1; then
        verifier_maj_apt "$_cat" 'sudo apt full-upgrade'
    elif [ -n "${DURCI_SANS_RESEAU:-}" ]; then
        resultat "$_cat" 'Paquets à mettre à jour' 'T1404, T1664' IGNORE 'vérification sautée (mode test)'
    elif command -v apk > /dev/null 2>&1; then
        patience 'recherche des mises à jour de paquets'
        if avec_delai 180 apk update -q > /dev/null 2>&1; then
            _n=$(apk version -l '<' 2>/dev/null | grep -c ' < ')
            if [ "$_n" -gt 0 ]; then
                resultat "$_cat" 'Paquets à mettre à jour' 'T1404, T1664' ALERTE "$_n paquet(s) : lancez « sudo apk upgrade »"
            else
                resultat "$_cat" 'Paquets à mettre à jour' 'T1404, T1664' OK 'tout est à jour'
            fi
        else
            resultat "$_cat" 'Paquets à mettre à jour' 'T1404, T1664' ALERTE 'vérification impossible (pas de réseau ?)'
        fi
    elif command -v pacman > /dev/null 2>&1; then
        patience 'recherche des mises à jour de paquets'
        if avec_delai 180 pacman -Sy > /dev/null 2>&1; then
            _n=$(pacman -Qu 2>/dev/null | wc -l | tr -d ' ')
            if [ "$_n" -gt 0 ]; then
                resultat "$_cat" 'Paquets à mettre à jour' 'T1404, T1664' ALERTE "$_n paquet(s) : lancez « sudo pacman -Su »"
            else
                resultat "$_cat" 'Paquets à mettre à jour' 'T1404, T1664' OK 'tout est à jour'
            fi
        else
            resultat "$_cat" 'Paquets à mettre à jour' 'T1404, T1664' ALERTE 'vérification impossible (pas de réseau ?)'
        fi
    else
        resultat "$_cat" 'Paquets à mettre à jour' 'T1404, T1664' IGNORE 'gestionnaire de paquets non reconnu'
    fi
}

# =====================================================================
#  3. ANDROID : état de sécurité (lecture seule)
# =====================================================================

age_jours() {   # $1 = AAAA-MM-JJ ; nombre de jours écoulés
    if _t=$(date -d "$1" +%s 2>/dev/null) && [ -n "$_t" ]; then
        printf '%s' $(( ($(date +%s) - _t) / 86400 ))
        return
    fi
    _a=${1%%-*}
    _m=${1#*-}
    _m=${_m%%-*}
    _m=${_m#0}
    _na=$(date +%Y)
    _nm=$(date +%m)
    _nm=${_nm#0}
    printf '%s' $(( ((_na - _a) * 12 + _nm - _m) * 30 ))
}

android_etat() {
    _cat='Android'
    _version=$(prop ro.build.version.release)
    _correctif=$(prop ro.build.version.security_patch)
    if [ -z "$_version" ] && [ -z "$_correctif" ]; then
        resultat "$_cat" 'État de sécurité d'"'"'Android' '' IGNORE 'propriétés d'"'"'Android illisibles depuis cet environnement (lancez le script dans Termux, ou associez le débogage sans fil)'
        return
    fi
    ANDROID_RESUME="Android $_version, correctifs du $_correctif"

    # Correctifs de sécurité — T1404, T1664
    case $_correctif in
        [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]) ;;
        *) _correctif='' ;;
    esac
    if [ -z "$_correctif" ]; then
        resultat "$_cat" 'Correctifs de sécurité' 'T1404, T1664' IGNORE "Android $_version : date des correctifs illisible"
    else
        _age=$(age_jours "$_correctif")
        if [ "$_age" -le 100 ]; then
            resultat "$_cat" 'Correctifs de sécurité' 'T1404, T1664' OK "Android $_version, correctifs du $_correctif ($_age jours)"
        elif [ "$_age" -le 400 ]; then
            resultat "$_cat" 'Correctifs de sécurité' 'T1404, T1664' ALERTE "correctifs du $_correctif ($_age jours) : Paramètres > Système > Mise à jour, et Sécurité > Mise à jour du système Google Play"
        else
            resultat "$_cat" 'Correctifs de sécurité' 'T1404, T1664' ALERTE "correctifs du $_correctif (plus d'un an) : le téléphone n'est probablement plus suivi par le constructeur"
        fi
    fi

    # Chiffrement des données — T1533 (accès physique)
    _chiffre=$(prop ro.crypto.state)
    case $_chiffre in
        encrypted) resultat "$_cat" 'Chiffrement des données' 'T1533' OK "chiffré ($(prop ro.crypto.type))" ;;
        '') resultat "$_cat" 'Chiffrement des données' 'T1533' IGNORE 'information illisible' ;;
        *) resultat "$_cat" 'Chiffrement des données' 'T1533' ALERTE 'NON chiffré : Paramètres > Sécurité > Chiffrement (sauvegardez avant)' ;;
    esac

    # Démarrage vérifié et bootloader — T1474, T1632
    _vb=$(prop ro.boot.verifiedbootstate)
    case $_vb in
        green) resultat "$_cat" 'Démarrage vérifié (bootloader verrouillé)' 'T1474, T1632' OK 'vert : système d'"'"'origine vérifié' ;;
        yellow) resultat "$_cat" 'Démarrage vérifié (bootloader verrouillé)' 'T1474, T1632' INFO 'jaune : système signé par une clé personnelle (ROM alternative verrouillée)' ;;
        orange) resultat "$_cat" 'Démarrage vérifié (bootloader verrouillé)' 'T1474, T1632' ALERTE 'orange : bootloader DÉVERROUILLÉ — une personne ayant le téléphone en main peut modifier le système' ;;
        red) resultat "$_cat" 'Démarrage vérifié (bootloader verrouillé)' 'T1474, T1632' ALERTE 'rouge : vérification du système en échec' ;;
        *) resultat "$_cat" 'Démarrage vérifié (bootloader verrouillé)' 'T1474, T1632' IGNORE 'information illisible' ;;
    esac

    # SELinux — T1404
    _se=''
    command -v getenforce > /dev/null 2>&1 && _se=$(getenforce 2>/dev/null)
    [ -z "$_se" ] && [ -x /system/bin/getenforce ] && _se=$(/system/bin/getenforce 2>/dev/null)
    [ -z "$_se" ] && [ -n "$ADB_SERIE" ] && _se=$(adb_shell getenforce)
    case $_se in
        Enforcing) resultat "$_cat" 'SELinux en mode strict' 'T1404' OK 'Enforcing' ;;
        Permissive) resultat "$_cat" 'SELinux en mode strict' 'T1404' ALERTE 'Permissive : la principale barrière entre applis est affaiblie' ;;
        *) resultat "$_cat" 'SELinux en mode strict' 'T1404' IGNORE 'information illisible' ;;
    esac

    # Système de production (pas de version de débogage) — T1404
    _type=$(prop ro.build.type)
    _debug=$(prop ro.debuggable)
    if [ "$_type" = user ] && [ "$_debug" != 1 ]; then
        resultat "$_cat" 'Système de production (non débogable)' 'T1404' OK 'build « user »'
    elif [ -n "$_type" ]; then
        resultat "$_cat" 'Système de production (non débogable)' 'T1404' ALERTE "build « $_type », débogable=$_debug : système de développement, moins protégé"
    fi

    # Débogage actif — T1458
    if [ "$(prop init.svc.adbd)" = running ]; then
        if [ -n "$ADB_SERIE" ]; then
            resultat "$_cat" 'Débogage USB / sans fil' 'T1458' INFO 'actif pour ce script : coupé à la fin'
        else
            resultat "$_cat" 'Débogage USB / sans fil' 'T1458' ALERTE 'ACTIF : Paramètres > Système > Options pour les développeurs > désactivez Débogage USB et Débogage sans fil'
        fi
    elif [ -n "$(prop init.svc.adbd)" ]; then
        resultat "$_cat" 'Débogage USB / sans fil' 'T1458' OK 'inactif'
    fi

    # Root — T1404
    _su=''
    for _s in /system/bin/su /system/xbin/su /sbin/su /su/bin/su /system/sbin/su /vendor/bin/su /debug_ramdisk/su; do
        [ -e "$_s" ] && _su=$_s
    done
    if [ -z "$_su" ] && [ -n "$ADB_SERIE" ]; then
        _su=$(adb_shell 'command -v su 2>/dev/null')
    fi
    if [ -n "$_su" ]; then
        resultat "$_cat" 'Téléphone rooté' 'T1404' ALERTE "su présent ($_su) : une appli malveillante qui obtient le root contourne toutes les protections"
    else
        resultat "$_cat" 'Téléphone rooté' 'T1404' OK 'non rooté'
    fi
}

# =====================================================================
#  4. ANDROID via ADB : applis à risque (lecture seule)
# =====================================================================

noter_appli() {   # $1 catégorie, $2 paquet ou composant, $3 remarque
    printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$FICHIER_APPLIS"
}

lister_tiers() {   # lit des noms de paquets/composants sur l'entrée, garde les applis tierces
    while IFS= read -r _x; do
        [ -n "$_x" ] || continue
        _pq=${_x%%/*}
        est_systeme "$_pq" && continue
        printf '%s\n' "$_x"
    done
}

controler_liste() {   # $1 catégorie du rapport, $2 mesure, $3 ATT&CK, $4 liste (une par ligne), $5 conseil, $6 « tout » pour ne pas exclure les applis système
    if [ "${6:-}" = tout ]; then
        _tiers=$(printf '%s\n' "$4" | grep -v '^[[:space:]]*$')
    else
        _tiers=$(printf '%s\n' "$4" | lister_tiers)
    fi
    if [ -z "$_tiers" ]; then
        resultat 'Applis à risque (ADB)' "$2" "$3" OK 'aucune appli concernée'
        return
    fi
    _n=0
    while IFS= read -r _x; do
        [ -n "$_x" ] || continue
        _n=$((_n + 1))
        noter_appli "$1" "$_x" "$5"
    done <<FIN_LISTE
$_tiers
FIN_LISTE
    resultat 'Applis à risque (ADB)' "$2" "$3" ALERTE "$_n appli(s) à vérifier — liste dans le rapport. $5"
}

android_applis() {
    # Services d'accessibilité : lecture de l'écran et clics à votre place — T1453, T1516, T1417
    _brut=$(reglage_lire secure enabled_accessibility_services)
    [ "$_brut" = null ] && _brut=''
    controler_liste 'Accessibilité' 'Services d'"'"'accessibilité actifs' 'T1453, T1516, T1417' \
        "$(printf '%s' "$_brut" | tr ':' '\n')" \
        'Normal pour un lecteur d'"'"'écran ou un gestionnaire de mots de passe ; sinon : Paramètres > Accessibilité > désactiver.'

    # Accès aux notifications : lecture des codes reçus — T1517
    _brut=$(reglage_lire secure enabled_notification_listeners)
    [ "$_brut" = null ] && _brut=''
    controler_liste 'Notifications' 'Applis qui lisent vos notifications' 'T1517' \
        "$(printf '%s' "$_brut" | tr ':' '\n')" \
        'Une appli inconnue ici peut lire vos codes de validation : Paramètres > Notifications > Accès aux notifications.'

    # Administrateurs de l'appareil — T1626
    _admins=$(adb_shell dumpsys device_policy | awk '
        /Enabled Device Admins/ { f = 1; next }
        f && /^    [A-Za-z][A-Za-z0-9_.]*\/[^ ]*:$/ { sub(/^ +/, ""); sub(/:$/, ""); print; next }
        f && !/^    / && /[^ ]/ { f = 0 }')
    controler_liste 'Administrateur' 'Applis administrateurs de l'"'"'appareil' 'T1626' "$_admins" \
        'Elles empêchent leur propre désinstallation : Paramètres > Sécurité > Applis d'"'"'administration.'

    # Superposition à d'autres applis (fausses fenêtres de saisie) — T1417.002
    _sup=$(adb_shell cmd appops query-op SYSTEM_ALERT_WINDOW allow | grep -E '^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$')
    controler_liste 'Superposition' 'Applis autorisées à se superposer aux autres' 'T1417.002' "$_sup" \
        'Retirez ce droit aux applis qui n'"'"'en ont pas besoin : Paramètres > Applis > Accès spéciaux > Superposition.'

    # Installation d'applis inconnues — T1476
    _inst=$(adb_shell cmd appops query-op REQUEST_INSTALL_PACKAGES allow | grep -E '^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$')
    _inst_filtre=''
    for _pq in $_inst; do
        est_magasin "$_pq" && continue
        _inst_filtre="$_inst_filtre
$_pq"
    done
    controler_liste 'Sources inconnues' 'Applis autorisées à installer d'"'"'autres applis' 'T1476' "$_inst_filtre" \
        'Paramètres > Applis > Accès spéciaux > Installer des applis inconnues : laissez seulement les magasins de confiance.' tout

    # Applis installées hors magasin de confiance — T1476 (information)
    _hors=''
    _nb_hors=0
    while IFS= read -r _l; do
        case $_l in package:*) ;; *) continue ;; esac
        _pq=$(printf '%s' "$_l" | sed 's/^package:\([^ ]*\).*/\1/')
        _inst=$(printf '%s' "$_l" | sed -n 's/.*installer=\([^ ]*\).*/\1/p')
        est_magasin "${_inst:-null}" && continue
        est_systeme "$_pq" && continue
        _nb_hors=$((_nb_hors + 1))
        case ${_inst:-null} in
            null) _par='installation manuelle (fichier APK)' ;;
            *) _par="installée par : $_inst" ;;
        esac
        noter_appli 'Hors magasin' "$_pq" "$_par"
    done <<FIN_PAQUETS
$(adb_shell pm list packages -3 -i)
FIN_PAQUETS
    if [ "$_nb_hors" -gt 0 ]; then
        resultat 'Applis à risque (ADB)' 'Applis installées hors magasin de confiance' 'T1476' INFO "$_nb_hors appli(s) (Termux depuis F-Droid ou GitHub en fait souvent partie) — liste dans le rapport"
    else
        resultat 'Applis à risque (ADB)' 'Applis installées hors magasin de confiance' 'T1476' OK 'aucune'
    fi
}

android_verrouillage() {
    _cat='Verrouillage (ADB)'
    # Verrouillage de l'écran — T1461
    _type=$(adb_shell dumpsys lock_settings | sed -n 's/.*CredentialType: *\([A-Za-z_]*\).*/\1/p' | head -n 1)
    case $_type in
        PIN | PASSWORD | PASSWORD_OR_PIN) resultat "$_cat" 'Verrouillage de l'"'"'écran' 'T1461' OK "code ($_type)" ;;
        PATTERN) resultat "$_cat" 'Verrouillage de l'"'"'écran' 'T1461' INFO 'schéma : plus facile à observer par-dessus l'"'"'épaule qu'"'"'un code à 6 chiffres' ;;
        NONE) resultat "$_cat" 'Verrouillage de l'"'"'écran' 'T1461' ALERTE 'AUCUN : Paramètres > Sécurité > Verrouillage de l'"'"'écran > Code (6 chiffres ou plus)' ;;
        *)
            if [ "$(adb_shell cmd lock_settings get-disabled)" = true ]; then
                resultat "$_cat" 'Verrouillage de l'"'"'écran' 'T1461' ALERTE 'désactivé : Paramètres > Sécurité > Verrouillage de l'"'"'écran'
            else
                resultat "$_cat" 'Verrouillage de l'"'"'écran' 'T1461' IGNORE 'type de verrouillage illisible'
            fi
            ;;
    esac
    # Contenu des notifications sur l'écran verrouillé (codes reçus par SMS) — T1517
    if [ "$(reglage_lire secure lock_screen_allow_private_notifications)" = 1 ]; then
        resultat "$_cat" 'Notifications sensibles sur l'"'"'écran verrouillé' 'T1517' INFO 'contenu visible (codes reçus par SMS...) : Paramètres > Notifications > Écran de verrouillage > Masquer le contenu sensible'
    else
        resultat "$_cat" 'Notifications sensibles sur l'"'"'écran verrouillé' 'T1517' OK 'contenu masqué ou par défaut'
    fi
    # Mise en veille — T1461
    _veille=$(reglage_lire system screen_off_timeout)
    case $_veille in
        '' | null | *[!0-9]*) ;;
        *)
            if [ "$_veille" -gt 120000 ]; then
                resultat "$_cat" 'Mise en veille de l'"'"'écran' 'T1461' INFO "après $((_veille / 1000)) s : 1 minute ou moins limite les accès quand le téléphone est posé"
            else
                resultat "$_cat" 'Mise en veille de l'"'"'écran' 'T1461' OK "après $((_veille / 1000)) s"
            fi
            ;;
    esac
}

# =====================================================================
#  5. ANDROID via ADB : réglages sûrs (sauvegardés, annulables)
# =====================================================================

appliquer_reglage() {   # $1 espace, $2 clé, $3 valeur voulue, $4 mesure, $5 ATT&CK, $6 impact, $7 valeurs acceptées sans changement
    _actuel=$(reglage_lire "$1" "$2")
    for _ok in $3 $7; do
        if [ "$_actuel" = "$_ok" ]; then
            if [ "$_actuel" = null ]; then
                resultat 'Réglages Android (ADB)' "$4" "$5" OK 'déjà en place (valeur par défaut)' "$6"
            else
                resultat 'Réglages Android (ADB)' "$4" "$5" OK "déjà en place ($2=$_actuel)" "$6"
            fi
            return
        fi
    done
    if reglage_ecrire "$1" "$2" "$3"; then
        resultat 'Réglages Android (ADB)' "$4" "$5" OK "appliqué ($2 : $_actuel → $3)" "$6"
    else
        resultat 'Réglages Android (ADB)' "$4" "$5" ECHEC "refusé par Android ($2)" "$6"
    fi
}

android_reglages() {
    # Vérification des applis par Play Protect — T1476
    appliquer_reglage global package_verifier_enable 1 'Analyse des applis installées (Play Protect)' 'T1476' 'Aucun' 'null'
    # Analyse des applis installées par ADB — T1458, T1476
    appliquer_reglage global verifier_verify_adb_installs 1 'Analyse des applis installées par débogage' 'T1458, T1476' 'Aucun' 'null'
    # DNS privé (DNS chiffré) : seulement s'il a été désactivé ; le mode automatique reste le défaut — T1638
    if [ "$(reglage_lire global private_dns_mode)" = off ]; then
        appliquer_reglage global private_dns_mode opportunistic 'DNS privé (DNS chiffré quand le réseau le permet)' 'T1638' 'Aucun (mode automatique d'"'"'Android)' ''
    else
        resultat 'Réglages Android (ADB)' 'DNS privé (DNS chiffré quand le réseau le permet)' 'T1638' OK "déjà actif ($(reglage_lire global private_dns_mode))" 'Aucun'
    fi
    # Recherche Wi-Fi et Bluetooth permanente (pistage de position) — T1430
    appliquer_reglage global wifi_scan_always_enabled 0 'Recherche Wi-Fi en permanence (même Wi-Fi coupé)' 'T1430' 'Position un peu moins précise quand le Wi-Fi est coupé' ''
    appliquer_reglage global ble_scan_always_enabled 0 'Recherche Bluetooth en permanence (même Bluetooth coupé)' 'T1430' 'Position un peu moins précise quand le Bluetooth est coupé' ''
}

android_couper_debogage() {
    # Dernière action : coupe le débogage (ce script perd alors sa connexion) — T1458
    _cat='Réglages Android (ADB)'
    # États lus avant toute coupure. USB d'abord : adbd reste actif tant que le
    # débogage sans fil l'est ; couper le sans-fil met fin à la connexion.
    _usb=$(reglage_lire global adb_enabled)
    _wifi=$(reglage_lire global adb_wifi_enabled)
    if [ "$COUPER_DEBOGAGE_USB" = oui ] && [ "$_usb" = 1 ]; then
        noter 'ADB|global|adb_enabled|1'
        if adb_shell settings put global adb_enabled 0 > /dev/null; then
            resultat "$_cat" 'Couper le débogage USB' 'T1458' OK 'coupé (réactivable dans Options pour les développeurs)' 'scrcpy et les outils par USB demandent de le réactiver'
        else
            resultat "$_cat" 'Couper le débogage USB' 'T1458' ALERTE 'à couper à la main : Options pour les développeurs > Débogage USB'
        fi
    fi
    if [ "$_wifi" = 1 ]; then
        noter 'ADB|global|adb_wifi_enabled|1'
        if avec_delai 20 "$ADB" -s "$ADB_SERIE" shell settings put global adb_wifi_enabled 0 > /dev/null 2>&1; then
            resultat "$_cat" 'Couper le débogage sans fil' 'T1458' OK 'coupé (réactivable dans Options pour les développeurs)' 'Shizuku et les outils par Wi-Fi demandent de le réactiver'
        else
            resultat "$_cat" 'Couper le débogage sans fil' 'T1458' ALERTE 'à couper à la main : Options pour les développeurs > Débogage sans fil'
        fi
    elif [ "$_wifi" = null ] || [ -z "$_wifi" ]; then
        resultat "$_cat" 'Couper le débogage sans fil' 'T1458' ALERTE 'état illisible : vérifiez Options pour les développeurs > Débogage sans fil'
    fi
    avec_delai 10 "$ADB" disconnect > /dev/null 2>&1
}

# =====================================================================
#  SCRIPT D'ANNULATION (écrit avant toute modification)
# =====================================================================

ecrire_annulation() {
    cat > "$DOSSIER/annuler-durcissement.sh" <<'FIN_ANNULATION'
#!/bin/sh
# shellcheck shell=sh
# annuler-durcissement.sh — généré par durcissement-android.sh : ne pas modifier.
# Remet les fichiers et réglages d'origine enregistrés dans les fichiers
# sauvegarde-*.txt de ce dossier, du plus récent au plus ancien.
# Lancement : sudo sh annuler-durcissement.sh   (sh annuler-durcissement.sh dans Termux)
DOSSIER=$(cd "$(dirname "$0")" && pwd)
# shellcheck disable=SC2012
LISTE=$(ls -1 "$DOSSIER"/sauvegarde-*.txt 2>/dev/null | sort -r)
printf '==========================================================================\n'
printf '  ANNULATION DU DURCISSEMENT (Android / Termux / proot)\n'
printf '==========================================================================\n'
if [ -z "$LISTE" ]; then
    printf '  Aucune sauvegarde à restaurer (annulation déjà faite ?).\n'
    exit 0
fi
ADB=$(command -v adb 2>/dev/null)
SERIE=''
[ -n "$ADB" ] && SERIE=$("$ADB" devices 2>/dev/null | awk 'NR > 1 && $2 == "device" { print $1; exit }')
printf '  Les fichiers et réglages modifiés vont retrouver leur état d'"'"'origine.\n'
if [ -z "$SERIE" ]; then
    printf '  Débogage sans fil non connecté : les réglages Android seront à remettre\n'
    printf '  plus tard (réassociez le débogage sans fil puis relancez ce script).\n'
fi
printf '\n  Appuyez sur Entrée pour annuler le durcissement, ou Ctrl+C pour abandonner. '
read -r _reponse
OK=0
KO=0
RESTE=0
while IFS= read -r FICHIER; do
    [ -n "$FICHIER" ] || continue
    printf '\n── %s\n' "${FICHIER##*/}"
    ECHECS=0
    ATTENTE=0
    while IFS='|' read -r TYPE A B C; do
        case $TYPE in
            FICHIER)
                if [ -n "$B" ]; then
                    if cp -p "$B" "$A" 2>/dev/null; then printf '  [OK] fichier remis : %s\n' "$A"; OK=$((OK + 1)); else printf '  [ÉCHEC] %s\n' "$A"; KO=$((KO + 1)); ECHECS=$((ECHECS + 1)); fi
                else
                    rm -f "$A" && printf '  [OK] fichier ajouté supprimé : %s\n' "$A"
                    OK=$((OK + 1))
                fi
                ;;
            DROITS)
                if chmod "$B" "$A" 2>/dev/null; then printf '  [OK] droits remis (%s) : %s\n' "$B" "$A"; OK=$((OK + 1)); fi
                ;;
            ADB)
                if [ -z "$SERIE" ]; then
                    ATTENTE=$((ATTENTE + 1))
                    RESTE=$((RESTE + 1))
                elif [ "$C" = null ]; then
                    "$ADB" -s "$SERIE" shell settings delete "$A" "$B" > /dev/null 2>&1
                    printf '  [OK] réglage Android remis par défaut : %s\n' "$B"
                    OK=$((OK + 1))
                elif "$ADB" -s "$SERIE" shell settings put "$A" "$B" "$C" > /dev/null 2>&1; then
                    printf '  [OK] réglage Android remis : %s = %s\n' "$B" "$C"
                    OK=$((OK + 1))
                else
                    printf '  [ÉCHEC] réglage Android %s\n' "$B"
                    KO=$((KO + 1))
                    ECHECS=$((ECHECS + 1))
                fi
                ;;
        esac
    done <<FIN_ENTREES
$(awk '{ l[NR] = $0 } END { for (i = NR; i > 0; i--) print l[i] }' "$FICHIER")
FIN_ENTREES
    if [ "$ECHECS" -eq 0 ] && [ "$ATTENTE" -eq 0 ]; then
        mv "$FICHIER" "$FICHIER.restaure"
    fi
done <<FIN_LISTE
$LISTE
FIN_LISTE
printf '\n==========================================================================\n'
printf '  Annulation : %s élément(s) remis, %s échec(s), %s réglage(s) Android en attente.\n' "$OK" "$KO" "$RESTE"
printf '  Redémarrez Termux (et sshd s'"'"'il tourne) pour appliquer.\n'
printf '==========================================================================\n'
FIN_ANNULATION
    chmod 700 "$DOSSIER/annuler-durcissement.sh" 2>/dev/null
}

# =====================================================================
#  RAPPORT
# =====================================================================

ecrire_rapport() {
    {
        printf 'RAPPORT DE DURCISSEMENT — ANDROID (Termux / proot)\n'
        printf 'Date : %s\n' "$(date '+%d/%m/%Y %H:%M')"
        if [ "$ENV_TYPE" = termux ]; then printf 'Environnement : Termux\n'; else printf 'Environnement : %s (proot)\n' "$DISTRIB"; fi
        printf 'Téléphone : %s\n' "${ANDROID_RESUME:-information illisible}"
        if [ -n "$ADB_SERIE" ]; then printf 'Débogage sans fil : utilisé puis coupé\n'; else printf 'Débogage sans fil : non utilisé\n'; fi
        printf '\nRésumé : %s OK, %s alerte(s), %s échec(s), %s ignoré(s), %s info(s)\n' \
            "$(compter OK)" "$(compter ALERTE)" "$(compter ECHEC)" "$(compter IGNORE)" "$(compter INFO)"

        printf '\n=== À FAIRE À LA MAIN ===\n'
        if [ $(( $(compter ALERTE) + $(compter ECHEC) )) -gt 0 ]; then
            awk -F'\t' '$4 == "ALERTE" || $4 == "ECHEC" { printf "- %s : %s\n", $2, $5 }' "$FICHIER_RESULTATS"
        else
            printf 'Rien.\n'
        fi
        if [ "$REDEMARRAGE_SSHD" = oui ]; then
            printf '%s\n' "- Redémarrez sshd s'il tourne, pour appliquer la nouvelle configuration SSH ($COMMANDE_SSHD)"
        fi

        printf '\n=== TOUTES LES MESURES (statut | catégorie | mesure | ATT&CK | détail | impact) ===\n'
        awk -F'\t' '{
            s = $4; if (s == "ECHEC") s = "ÉCHEC"; if (s == "IGNORE") s = "IGNORÉ"
            printf "[%s] %s | %s | %s | %s", s, $1, $2, ($3 == "" ? "—" : $3), $5
            if ($6 != "") printf " | impact : %s", $6
            printf "\n" }' "$FICHIER_RESULTATS"

        printf '\n=== APPLIS À VÉRIFIER (débogage sans fil) ===\n'
        if [ -s "$FICHIER_APPLIS" ]; then
            awk -F'\t' '{ printf "- [%s] %s — %s\n", $1, $2, $3 }' "$FICHIER_APPLIS"
        elif [ -n "$ADB_SERIE" ]; then
            printf 'Aucune.\n'
        else
            printf 'Non contrôlé (débogage sans fil non associé).\n'
        fi

        printf '\n=== SCRIPTS LANCÉS AUTOMATIQUEMENT (inventaire, rien n'"'"'a été supprimé) ===\n'
        if [ -s "$FICHIER_PERSIST" ]; then
            awk -F'\t' '{
                n = $3; if (n == "A_VERIFIER") n = "À VÉRIFIER"
                printf "- [%s] %s — %s\n", n, $2, $4 }' "$FICHIER_PERSIST"
        else
            printf 'Aucun.\n'
        fi

        printf '\n=== ANNULER ===\n'
        printf 'sudo sh %s/annuler-durcissement.sh   (dans Termux : sh ...)\n' "$DOSSIER"
        printf 'Sauvegarde de cette exécution : %s\n' "$FICHIER_SAUVEGARDE"

        printf '\n=== DÉBOGAGE SANS FIL (FACULTATIF, POUR LE CONTRÔLE DES APPLIS) ===\n'
        printf '1. Paramètres > À propos du téléphone : touchez 7 fois « Numéro de build ».\n'
        printf '2. Options pour les développeurs > Débogage sans fil : activez-le.\n'
        printf '3. Installez adb (Termux : pkg install android-tools ; Debian/Ubuntu : sudo apt install adb).\n'
        printf '4. Relancez ce script : il demande le port, puis, la première fois, le code d'"'"'association\n'
        printf '   (« Associer l'"'"'appareil avec un code » ; écran partagé avec Termux conseillé).\n'
        printf '   Le script coupe le débogage à la fin.\n'
    } > "$FICHIER_RAPPORT"
    chmod 600 "$FICHIER_RAPPORT" 2>/dev/null
}

resume() {
    _duree=$(( $(date +%s) - DEBUT ))
    printf '\n%s==========================================================================%s\n' "$C_CYAN" "$C_RAZ"
    printf '  %sTERMINÉ en %s min %s s%s\n' "$C_CYAN" $((_duree / 60)) $((_duree % 60)) "$C_RAZ"
    printf '  OK : %s   Alertes : %s   Échecs : %s   Ignorés : %s\n' \
        "$(compter OK)" "$(compter ALERTE)" "$(compter ECHEC)" "$(compter IGNORE)"
    printf '  Rapport : %s\n' "$FICHIER_RAPPORT"
    printf '  Lire    : less %s\n' "$FICHIER_RAPPORT"
    printf '  Annuler : sudo sh %s/annuler-durcissement.sh\n' "$DOSSIER"
    printf '%s==========================================================================%s\n' "$C_CYAN" "$C_RAZ"
    if [ $(( $(compter ALERTE) + $(compter ECHEC) )) -gt 0 ]; then
        printf '  %sÀ faire :%s\n' "$C_JAUNE" "$C_RAZ"
        awk -F'\t' '$4 == "ALERTE" || $4 == "ECHEC" { printf "   - %s : %s\n", $2, $5 }' "$FICHIER_RESULTATS"
    fi
    if [ "$REDEMARRAGE_SSHD" = oui ]; then
        printf '  %sRedémarrez sshd s'"'"'il tourne (%s).%s\n' "$C_JAUNE" "$COMMANDE_SSHD" "$C_RAZ"
    fi
}

# =====================================================================
#  EXÉCUTION
# =====================================================================

umask 077
initialiser_couleurs
detecter_environnement
verifier_droits
accueil
preparer_dossier
ecrire_annulation
ANDROID_RESUME=''

etape 'Connexion au téléphone (débogage sans fil, facultatif)'
preparer_adb

etape 'Termux'
if [ -n "$TERMUX_HOME" ]; then
    termux_proprietes
    termux_demarrage
    termux_shell
    termux_ssh
    termux_cles
    termux_depots
    termux_divers
else
    resultat 'Termux' 'Durcissement de Termux' '' IGNORE 'dossiers de Termux inaccessibles depuis cette distribution : lancez aussi « sh durcissement-android.sh » dans Termux'
fi

etape 'Distribution proot'
if [ "$ENV_TYPE" = proot ]; then
    distro_ssh
    distro_comptes
    distro_demarrage
    distro_maj
else
    resultat 'Distribution proot' 'Durcissement de la distribution' '' IGNORE 'lancé directement dans Termux'
fi

etape 'Android : état de sécurité'
android_etat

etape 'Android : applis à risque et verrouillage (débogage sans fil)'
if [ -n "$ADB_SERIE" ]; then
    android_applis
    android_verrouillage
else
    resultat 'Applis à risque (ADB)' 'Contrôle des applis à risque et du verrouillage' 'T1453, T1517, T1626' IGNORE 'débogage sans fil non associé (facultatif, voir le rapport)'
fi

etape 'Android : réglages sûrs (débogage sans fil)'
if [ -n "$ADB_SERIE" ]; then
    android_reglages
else
    resultat 'Réglages Android (ADB)' 'Réglages Android' 'T1476, T1638' IGNORE 'débogage sans fil non associé (facultatif, voir le rapport)'
fi

etape 'Fin : coupure du débogage et rapport'
if [ -n "$ADB_SERIE" ]; then
    android_couper_debogage
fi
ecrire_rapport
resume
