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
* [Choix et installation](#choix-et-installation)
  * [PC Portable](#pc-portable)
  * [PC Fixe](#pc-fixe)
* [Pourquoi se contenter d'un Linux de base ?](#pourquoi-se-contenter-dun-linux-de-base-)
  * [Starship](#starship)
  * [Les alternatives Rust](#les-alternatives-rust)
    * [Lire un fichier avec batcat](#lire-un-fichier-avec-batcat)
    * [Lister le contenu du PC avec LSDeluxe](#lister-le-contenu-du-pc-avec-lsdeluxe)
    * [Retrouver mes données avec fdfind](#retrouver-mes-données-avec-fdfind)
    * [Rechercher dans les fichiers avec ripgrep](#rechercher-dans-les-fichiers-avec-ripgrep)
    * [Envoyer des requêtes HTTP avec xh](#envoyer-des-requêtes-http-avec-xh)

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

Grâce au site [DistroSea](https://distrosea.com/fr/) j'ai pu tester quelques distributions, et j'en ai retenu quelques unes qu'il va falloir départager :

* [LMDE](https://linuxmint.com/download_lmde.php) (Linux Mint Debian Edition) : Réputée fiable, stable et légère
* [Garuda Linux](https://garudalinux.org/) : Basée sur Arch Linux, elle est récente, moderne, et orientée vers les joueurs
* [Nobara Linux](https://nobaraproject.org/) : Basée sur Fedora, optimisée pour le jeu vidéo ; mais originaire des États-Unis et je recherche une solution plus souveraine
* [OpenSuse](https://www.opensuse.org/) : Originaire d'Allemagne, réputée pour sa fiabilité, disponible en version *stable* et *rolling* ; mais moins optimisée pour le jeu.

Mon intention est d'installer Garuda sur mon PC portable pour m'assurer que la distribution corresponde bien à mes besoins, puis d'installer Garuda à côté de Windows dans un premier temps sur mon PC fixe afin d'évaluer Garuda sur une utilisation quotidienne en gardant Windows "au cas où".

## Choix et installation

### PC Portable

Dans mon cas, le PC portable est secondaire, et n'est utile qu'en cas de déplacement ou vacances. Mais puisqu'il est voué à être déplacé, la sécurité des données est primordiale. Ce PC n'a pas particulièrement besoin d'être stable, et peut servir de cobaye informatique pour tester différents outils, différentes configuration.

La distribution choisie sera **Garuda**. En cas de problème lors d'une configuration hasardeuse, il sera possible de revenir en arrière grâce aux snapshots de BTRFS.

<div class="text-center">
    <i class="fa-solid fa-1xl text-info">Redaction en cours</i><br />
    <i class="fa-solid fa-spinner fa-spin-pulse fa-2xl text-info mt-3"></i>
</div>

### PC Fixe

Ce choix est plus complexe car il s'agit de la machine principale.

Sur le papier, Nobara semble la meilleure solution. Mais dans un remplacer un outil américain par un autre perd malheureusement en intérêt.

Garuda pourrait ne pas être assez stable pour une utilisation sans contrainte au quotidien.

LMDE et OpenSuse sont stables, viennent de pays européens (Irlande et Allemagne respectivement), mais manquent d'optimisation pour les jeux vidéos qui est une des utilisations principales de cette machine.

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

Une alternative à la commande intégrer `cat`

#### Lister le contenu du PC avec [LSDeluxe](https://github.com/lsd-rs/lsd)

Un remplaçant plus élégant pour `ls`

#### Retrouver mes données avec [fdfind](https://github.com/sharkdp/fd)

Beaucoup plus rapide que `find`

#### Rechercher dans les fichiers avec [ripgrep](https://github.com/BurntSushi/ripgrep)

Plus rapide et plus simple que `grep`

#### Envoyer des requêtes HTTP avec [xh](https://github.com/ducaale/xh)

Plus simple et plus puissant que `curl` et met en forme les résultats
