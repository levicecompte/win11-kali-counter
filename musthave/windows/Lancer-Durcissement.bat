@echo off
setlocal
title Durcissement de securite - Windows 11
rem Lance Durcissement-Windows.ps1, place dans le meme dossier que ce fichier.
rem Le script demande lui-meme les droits administrateur : une fenetre UAC va s'ouvrir.
rem La strategie d'execution n'est contournee que pour ce lancement : rien n'est change dans Windows.
set "SCRIPT=%~dp0Durcissement-Windows.ps1"
if not exist "%SCRIPT%" (
    echo Le fichier Durcissement-Windows.ps1 est introuvable.
    echo Placez-le dans le meme dossier que ce fichier .bat, puis recommencez.
    echo.
    pause
    exit /b 1
)
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%"
endlocal
