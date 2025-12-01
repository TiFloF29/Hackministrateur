---
name: Adopter Linux
tools: [Personnalisation, Linux]
image: "https://cdn.pixabay.com/photo/2022/03/20/03/17/windows-7079876_960_720.png"
description: Se séparer de Windows et passer à Linux
---
# Adopter Linux <!-- omit in toc -->

## Sommaire <!-- omit in toc -->

* [Pourquoi utiliser Windows ?](#pourquoi-utiliser-windows-)
* [Pourquoi quitter Windows ?](#pourquoi-quitter-windows-)
* [Pourquoi passer sur Linux ?](#pourquoi-passer-sur-linux-)
* [Installation sur le PC portable](#installation-sur-le-pc-portable)
* [Pourquoi se contenter d'un Linux de base ?](#pourquoi-se-contenter-dun-linux-de-base-)
  * [Starship](#starship)
  * [Les alternatives Rust](#les-alternatives-rust)
    * [Lire un fichier avec batcat](#lire-un-fichier-avec-batcat)

## Pourquoi utiliser Windows ?

C'est la première question que je me suis posée : pour quelles raisons j'utilise Windows ?

La première raison, est clairement l'habitude. Mon premier contact avec un ordinateur était sur Windows 95. Quelques années plus tard, cette machine devenait mon premier PC. Je suis ensuite passé sur Windows XP. Puis mon premier PC portable était sous Windows 7, le second sous Windows 10, et la tour sur laquelle je rédige ces lignes est actuellement sous Windows 11.

La seconde raison est la compatibilité des jeux vidéos sur d'autres plateformes. La plupart est développée pour Windows, et la compatibilité n'est pas garantie sur d'autres OS. Perdre l'argent investi dans des jeux PC ne fait pas partie de la liste des objectifs dans l'adoption d'une distribution Linux.

## Pourquoi quitter Windows ?

Les conditions actuelles pour conserver Windows sont de plus en plus restrictives : Puce TPM 2.0 (rendant mon PC portable obsolète), une puce dédiée à l'intelligence artificielle pour Copilot+ (rendant également ma tour obsolète).

Ajoutons des fonctionnalités discutables comme Rappel (*Recall*) qui prévoit de prendre des captures d'écran **toutes les 5 secondes** pour lesquelles il faudra définir manuellement les sites sur lesquels on souhaite le désactiver afin d'éviter d'enregistrer des données personnelles ou bancaire, et j'ai plus de raisons que nécessaire pour envisager une alternative moins contraignante.

## Pourquoi passer sur Linux ?

Certes, quitter Windows est en ligne de mire, mais pour aller où ?

Apple et Mac OS ? Vider mon compte en banque n'est pas mon objectif !

Une des innombrables distributions de Linux ? Je peux l'installer sur toutes mes machines, la plupart est relativement légère, et en plus c'est **gratuit** !!

Mais quelle distribution choisir ? C'est qu'il y en a quelques unes :

{% include elements/figure.html image="https://upload.wikimedia.org/wikipedia/commons/1/1b/Linux_Distribution_Timeline.svg" caption="Chronologie des distributions Linux" %}

Grâce au site [DistroSea](https://distrosea.com/fr/) j'ai pu tester quelques distributions, et j'en ai choisi deux qui me conviennent le plus :

* [LMDE](https://linuxmint.com/download_lmde.php) (Linux Mint Debian Edition) : Réputée fiable, stable et légère
* [Garuda Linux](https://garudalinux.org/) : Basée sur Arch Linux, elle est récente, moderne, et orientée vers les joueurs

Mon intention est d'installer Garuda sur mon PC portable pour m'assurer que la distribution corresponde bien à mes besoins, puis d'installer Garuda à côté de Windows dans un premier temps sur mon PC fixe afin d'évaluer Garuda sur une utilisation quotidienne en gardant Windows "au cas où".

## Installation sur le PC portable

Dans mon cas, le PC portable est secondaire, et n'est utile qu'en cas de déplacement ou vacances. Mais puisqu'il est voué à être déplacé, la sécurité des données est primordiale. J'ai donc souhaité faire une installation chiffrée, et séparer les dossiers importants comme `/home` et `/usr` dans des partitions différentes.

J'avais donc utiliser [LVM (*Logical Volume Manager*)](https://en.wikipedia.org/wiki/Logical_Volume_Manager_(Linux)) et commencer par définir un *volume group* chiffré correspondant au SSD, dans lequel je pourrais créer des *logical volumes* qui auraient servi à installer les différentes partitions.

**SAUF QUE** les distributions Linux nécessitent d'avoir une partition particulière `/boot/efi` **non chiffrée**.

Retour sur [GParted](https://gparted.org/) pour revoir les partitions.

<div class="text-center">
    <i class="fa-solid fa-1xl text-info">Redaction en cours</i><br />
    <i class="fa-solid fa-spinner fa-spin-pulse fa-2xl text-info mt-3"></i>
</div>

## Pourquoi se contenter d'un Linux de base ?

Ce que j'entends par Linux "de base" c'est la distribution telle qu'elle est une fois l'installation terminée.

C'est fonctionnel, mais on peut faire mieux.

### Starship

On peut améliorer l'apparence du terminal avec [starship](https://starship.rs) pour commencer. Certes l'utilisateur lambda n'aura peut-être pas grand-chose à y gagner, mais quand on s'intéresse à l'administration du système avoir un terminal amélioré peut faciliter l'utilisation en ligne de commande.

### Les alternatives Rust

Les commandes habituelles de Linux font vraiment partie du passage obligatoire pour un administrateur. `ls`, `grep` ou `cat` sont des incontournables.

Des projets open-source ont entrepris de moderniser ces commandes, le plus souvent en optant pour le langage [Rust](https://rust-lang.org/fr/) augmentant à la fois la rapidité d'exécution et la stabilité par rapport aux commandes historiques développées en C.

Ces outils sont également développés dans l'optique d'être plus ergonomique : plus de couleurs pour différencier les résultats ou rendre le code plus lisible, icônes (nécessite l'installation de [Nerd Fonts](https://www.nerdfonts.com/)).

Puisque des images valent mieux qu'un long discours, voici quelques exemples et comparaisons des commandes que j'utilise désormais au quotidien

#### Lire un fichier avec [batcat](https://github.com/sharkdp/bat)
