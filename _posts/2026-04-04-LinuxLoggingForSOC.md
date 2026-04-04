---
title: Linux Logging For SOC
tags: [TryHackMe, Facile, Défense, Analyse de logs, Linux]
style: border
color: thm
comments: false
description: Déchiffrer une information en analysant le mode de chiffrement
---
Lien vers l'épreuve : <https://tryhackme.com/room/linuxloggingforsoc>

![Easy](https://img.shields.io/badge/Difficulté-Facile-Green?logo=tryhackme)

## Sommaire <!-- omit in toc -->

* [Travailler avec les Logs Texte](#travailler-avec-les-logs-texte)
* [Logs d'authentification](#logs-dauthentification)
* [Logs Linux communs](#logs-linux-communs)
* [Utiliser Auditd](#utiliser-auditd)

## Travailler avec les Logs Texte

### Quel domaine de serveur de temps a contacté la machine pour synchroniser son temps ? <!-- omit in toc -->

Une rapide recherche sur Internet permet de trouver le nom du service en charge de la synchronisation du temps sur une machine Linux : `systemd-timesyncd`.

En explorant le fichier `/var/log/syslog` nous pouvons rechercher ce service avec l'utilitaire `grep`.

```bash
grep systemd-timesyncd /var/log/syslog | grep server
```

{% capture spoil %}

```txt
2025-08-13T13:42:17.819639+00:00 thm-vm systemd-timesyncd[275]: Contacted time server 185.125.190.58:123 (ntp.[...expurgé...]).
2025-08-13T13:57:49.388678+00:00 thm-vm systemd-timesyncd[268]: Contacted time server 185.125.190.58:123 (ntp.[...expurgé...]).
2025-08-28T14:02:07.694115+00:00 thm-vm systemd-timesyncd[282]: Contacted time server 185.125.190.58:123 (ntp.[...expurgé...]).
2025-09-09T13:45:41.665964+00:00 thm-vm systemd-timesyncd[266]: Contacted time server 185.125.190.58:123 (ntp.[...expurgé...]).
```

{% endcapture %}
{% include elements/spoil.html %}

Solution alternative : utiliser le service `journalctl` :

```bash
journalctl -u systemd-timesyncd | grep server
```

### Quel est le message kernel pour Yama dans /var/log/syslog ? <!-- omit in toc -->

```bash
grep -i kernel /var/log/syslog | grep -i yama
```

{% capture spoil %}

```txt
2025-08-13T13:41:48.176648+00:00 thm-vm kernel: LSM: initializing lsm=lockdown,capability,landlock,yama,apparmor,ima,evm
2025-08-13T13:41:48.176653+00:00 thm-vm kernel: Yama: [...expurgé...].
2025-08-13T13:57:19.908951+00:00 thm-vm kernel: LSM: initializing lsm=lockdown,capability,landlock,yama,apparmor,ima,evm
2025-08-13T13:57:19.908956+00:00 thm-vm kernel: Yama: [...expurgé...].
2025-08-28T14:02:07.691518+00:00 thm-vm kernel: LSM: initializing lsm=lockdown,capability,landlock,yama,apparmor,ima,evm
2025-08-28T14:02:07.691523+00:00 thm-vm kernel: Yama: [...expurgé...].
2025-09-09T13:45:41.659295+00:00 thm-vm kernel: LSM: initializing lsm=lockdown,capability,landlock,yama,apparmor,ima,evm
2025-09-09T13:45:41.659300+00:00 thm-vm kernel: Yama: [...expurgé...].
2026-04-04T09:19:51.643003+00:00 thm-vm kernel: LSM: initializing lsm=lockdown,capability,landlock,yama,apparmor,ima,evm
2026-04-04T09:19:51.643008+00:00 thm-vm kernel: Yama: [...expurgé...].
```

{% endcapture %}
{% include elements/spoil.html %}

Version alternative en utilisant `journalctl` :

```bash
journalctl -t kernel | grep -i yama
```

## Logs d'authentification

### Quelle adresse IP a échoué à se connecter sur plusieurs utilisateur via SSH ? <!-- omit in toc -->

Les logs du service `sshd` du serveur {% include dictionary.html word="SSH" %} permettront de trouver les échecs de connexions.

```bash
grep -i sshd /var/log/auth.log | grep -Ei "fail.*from"
```

Ou

```bash
journalctl -u ssh | grep -Ei "fail.*from"
```

{% capture spoil %}

```txt
2025-08-13T15:56:18.903048+00:00 thm-vm sshd[1176]: Failed password for root from [...expurgé...] port 57696 ssh2
2025-08-13T15:56:31.754409+00:00 thm-vm sshd[1192]: Failed password for invalid user admin from [...expurgé...] port 57697 ssh2
2025-08-13T15:56:36.311951+00:00 thm-vm sshd[1192]: Failed password for invalid user admin from [...expurgé...] port 57697 ssh2
2025-08-13T15:56:47.119851+00:00 thm-vm sshd[1194]: Failed password for invalid user support from [...expurgé...] port 57698 ssh2
2025-08-13T15:56:51.194083+00:00 thm-vm sshd[1194]: Failed password for invalid user support from [...expurgé...] port 57698 ssh2
2025-08-13T15:57:01.783976+00:00 thm-vm sshd[1196]: Failed password for root from [...expurgé...] port 57700 ssh2
```

{% endcapture %}
{% include elements/spoil.html %}

### Quel utilisateur a été créé et ajouté au groupe "sudo" ? <!-- omit in toc -->

```bash
grep -i sudo /var/log/auth.log | grep -Ei "new|add"
```

{% capture spoil %}

```txt
2025-08-13T18:04:29.425939+00:00 thm-vm usermod[1458]: add 'xerxes' to group 'sudo'
2025-08-13T18:04:29.426146+00:00 thm-vm usermod[1458]: add 'xerxes' to shadow group 'sudo'
```

{% endcapture %}
{% include elements/spoil.html %}

## Logs Linux communs

### Quelle est la version de **unzip** qui a été installé sur le système ? <!-- omit in toc -->

La machine utilisant une distribution Ubuntu, basée sur Debian, les logs de paquets se trouvent dans le fichier `/var/log/dpkg.log`

```bash
grep -i unzip /var/log/dpkg.log
```

{% capture spoil %}

```txt
2025-08-12 16:41:24 install unzip:amd64 <none> [...expurgé...]
2025-08-12 16:41:24 status half-installed unzip:amd64 [...expurgé...]
2025-08-12 16:41:25 status unpacked unzip:amd64 [...expurgé...]
2025-08-12 16:41:25 configure unzip:amd64 [...expurgé...] <none>
2025-08-12 16:41:25 status unpacked unzip:amd64 [...expurgé...]
2025-08-12 16:41:25 status half-configured unzip:amd64 [...expurgé...]
2025-08-12 16:41:25 status installed unzip:amd64 [...expurgé...]
```

{% endcapture %}
{% include elements/spoil.html %}

### Quel flag peut-on voir dans un des bash_history d'un utilisateur ? <!-- omit in toc -->

Le nom ou le nombre d'utilisateurs n'étant pas fourni, il est possible d'énumérer manuellement le dossier `/home` pour trouver les différents utilisateurs, ou automatiser l'opération à l'aide de la commande `find`

```bash
find / -type f -name .bash_history -exec cat {} \; 2>/dev/null
```

>Cette commande permet de lister tous les fichiers répondant au nom `.bash_history` et de les ouvrir pour afficher le résultat avec `cat`

{% capture spoil %}

```txt
nano /etc/ssh/sshd_config
exit
ll -h /var/log
echo "THM{[...expurgé...]}" >> notes.txt
apt install auditd
cd /etc/audit/
ls
cd rules.d/
nano audit.rules 
ll `which python3`
systemctl restart auditd
systemctl status auditd
nano audit.rules 
cd /etc/logrotate.d
ls
rm *
exit
sudo su
sudo su
sudo su
sudo apt install zip unzip
passwd
```

{% endcapture %}
{% include elements/spoil.html %}

## Utiliser Auditd

### Quand a été ouvert pour la première fois le fichier **secret.thm** ? <!-- omit in toc -->

>Note : L'accès à ce fichier est enregistré avec la clé "file_thmsecret"

```bash
ausearch -i -k file_thmsecret | grep cat
```

{% capture spoil %}

```txt
type=PROCTITLE msg=audit([..expurgé...].574:1600) : proctitle=cat /secret.thm 
type=SYSCALL msg=audit([..expurgé...].574:1600) : arch=x86_64 syscall=openat success=yes exit=3 a0=AT_FDCWD a1=0x7ffd133b973a a2=O_RDONLY a3=0x0 items=1 ppid=1542 pid=1578 auid=ubuntu uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts1 ses=30 comm=cat exe=/usr/bin/cat subj=unconfined key=file_thmsecret
```

{% endcapture %}
{% include elements/spoil.html %}

### Quel est le nom original du fichier téléchargé depuis Github via wget ? <!-- omit in toc -->

>Note : La création de processus wget est enregistré avec la clé "proc_wget"

```bash
ausearch -i -k proc_wget | grep github
```

{% capture spoil %}

```txt
type=PROCTITLE msg=audit(08/13/25 18:29:14.700:1523) : proctitle=wget https://github.com/projectdiscovery/naabu/releases/download/v2.3.5/[...expurgé...].zip -O /tmp/naabu.zip 
type=EXECVE msg=audit(08/13/25 18:29:14.700:1523) : argc=4 a0=wget a1=https://github.com/projectdiscovery/naabu/releases/download/v2.3.5/[...expurgé...].zip a2=-O a3=/tmp/naabu.zip
```

{% endcapture %}
{% include elements/spoil.html %}

### Quel plage réseau a été scanné en utilisant l'outil précédemment téléchargé ? <!-- omit in toc -->

>Note : Il n'y a pas de clé dédiée pour cet événement, mais ça apparaît quand-même dans les logs auditd.

```bash
ausearch -i | grep -i naabu
```

{% capture spoil %}

```txt
type=PROCTITLE msg=audit([...expurgé...].700:1523) : proctitle=wget https://github.com/projectdiscovery/naabu/releases/download/v2.3.5/[...expurgé...].zip -O /tmp/naabu.zip
type=EXECVE msg=audit([...expurgé...].700:1523) : argc=4 a0=wget a1=https://github.com/projectdiscovery/naabu/releases/download/v2.3.5/[...expurgé...].zip a2=-O a3=/tmp/naabu.zip
type=PROCTITLE msg=audit(08/13/25 18:29:25.214:1524) : proctitle=unzip naabu.zip
type=EXECVE msg=audit(08/13/25 18:29:25.214:1524) : argc=2 a0=unzip a1=naabu.zip
type=PROCTITLE msg=audit(08/13/25 18:29:45.152:1526) : proctitle=chmod +x naabu
type=EXECVE msg=audit(08/13/25 18:29:45.152:1526) : argc=3 a0=chmod a1=+x a2=naabu
type=PROCTITLE msg=audit(08/13/25 18:29:51.986:1527) : proctitle=./naabu -host [...expurgé...] -top-ports
type=EXECVE msg=audit(08/13/25 18:29:51.986:1527) : argc=5 a0=./naabu a1=-host a2=[...expurgé...] a3=-top-ports a4=100
type=SYSCALL msg=audit(08/13/25 18:29:51.986:1527) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x6252c36af5a0 a1=0x6252c36af630 a2=0x6252f61106d8 a3=0x8 items=2 ppid=1499 pid=1504 auid=ubuntu uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts1 ses=30 comm=naabu exe=/tmp/naabu subj=unconfined key=proc_all
```

{% endcapture %}
{% include elements/spoil.html %}

> En détail, le fichier a été téléchargé depuis Github sous le chemin `/tmp/naabu.zip`, dézippé en utilisant `unzip`, les droits d'exécution ont été appliqués avec `chmod +x` puis un scan a été lancé sur une plage d'adresses IP.

---
L'analyse de logs Linux s'étend sur 3 autres box. Pour passer à la suivante :

{% include elements/button.html link="/Hackministrateur/comptes-rendus/LinuxThreatDetection1" text="Epreuve suivante" style="primary" size="sm" %}
