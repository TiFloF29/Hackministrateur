---
name: Boîte à outils
tools: [Amélioration, Linux, Apprentissage, Cheatsheet]
image: "https://cdn.pixabay.com/photo/2014/04/02/16/18/toolbox-306888_960_720.png"
description: Les outils et commandes les plus utiles
---

# Boîte à outils <!-- omit in toc -->

> Cette partie est en cours de rédaction. Le contenu risque d'être partiellement ou totalement absent. Merci pour votre indulgence.

<div class="text-center">
   <i class="fa-solid fa-spinner fa-spin-pulse fa-2xl text-secondary mt-3"></i>
</div>

{% include elements/figure.html image="images/quincecreative-under-construction-2891888_1280.jpg" caption="Image par QuinceCreative sur Pixabay" %}

## Sommaire <!-- omit in toc -->

* [1. Outillage Linux](#1-outillage-linux)
  * [Starship](#starship)
  * [Les alternatives Rust](#les-alternatives-rust)
* [2. Site web](#2-site-web)

## 1. Outillage Linux

### Starship

On peut améliorer l'apparence du terminal avec [starship](https://starship.rs) pour commencer. Certes l'utilisateur lambda n'aura peut-être pas grand-chose à y gagner, mais quand on s'intéresse à l'administration du système avoir un terminal amélioré peut faciliter l'utilisation en ligne de commande.

### Les alternatives Rust

Les commandes habituelles de Linux font vraiment partie du passage obligatoire pour un administrateur. `ls`, `grep` ou `cat` sont des incontournables.

Des projets open-source ont entrepris de moderniser ces commandes, le plus souvent en optant pour le langage [Rust](https://rust-lang.org/fr/) augmentant à la fois la rapidité d'exécution et la stabilité par rapport aux commandes historiques développées en C.

Ces outils sont également développés dans l'optique d'être plus ergonomique : plus de couleurs pour différencier les résultats ou rendre le code plus lisible, icônes (nécessite l'installation de [Nerd Fonts](https://www.nerdfonts.com/)).

Puisque des images valent mieux qu'un long discours, voici quelques exemples et comparaisons des commandes que j'utilise désormais au quotidien

#### Editer un fichier avec [helix](https://github.com/helix-editor/helix) <!-- omit in toc -->

Une alternative à la commande intégrée `cat`

#### Lire un fichier avec [batcat](https://github.com/sharkdp/bat) <!-- omit in toc -->

Une alternative à la commande intégrée `cat`

#### Se déplacer dans le système avec [zoxide](https://github.com/ajeetdsouza/zoxide) <!-- omit in toc -->

Une alternative plus intelligente à la commande `cd`

#### Lister le contenu du PC avec [LSDeluxe](https://github.com/lsd-rs/lsd) <!-- omit in toc -->

Un remplaçant plus élégant pour `ls`

#### Retrouver mes données avec [fdfind](https://github.com/sharkdp/fd) <!-- omit in toc -->

Beaucoup plus rapide que `find`

#### Rechercher dans les fichiers avec [ripgrep](https://github.com/BurntSushi/ripgrep) <!-- omit in toc -->

Plus rapide et plus simple que `grep`

#### Envoyer des requêtes HTTP avec [xh](https://github.com/ducaale/xh) <!-- omit in toc -->

Plus simple et plus puissant que `curl` et met en forme les résultats

## 2. Site web

1. [TryHackMe](https://tryhackme.com/) : Formations et exercices de cybersécurité
2. [HackTheBox](https://www.hackthebox.com/) : Formations et exercices de cybersécurité (aspect compétitif)
3. [GTFOBins](https://gtfobins.github.io/) : Techniques d'élévation de privilèges en exploitant les failles des binaires Linux
4. [LOLBAS](https://lolbas-project.github.io/#) : Equivalent de GTFOBins pour Windows
5. [PayloadsAllTheThings](https://swisskyrepo.github.io/PayloadsAllTheThings/) : Recueil de nombreuses charges permettant d'exploiter des vulnérabilités
6. [ExploitDB](https://www.exploit-db.com/) : Base recensant des vulnérabilités et les moyens de les exploiter
7. [CyberChef](https://gchq.github.io/CyberChef/) : Manipulation de données, chiffrement, déchiffrement. Le couteau suisse de l'informatique
