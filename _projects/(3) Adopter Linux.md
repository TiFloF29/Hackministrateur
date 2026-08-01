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

La question initiale de ma réflexion réside dans la motivation de mon usage actuel de Windows.

Premièrement, cet usage repose sur une habitude ancrée dans le temps. Mon parcours informatique a débuté sous Windows 95, et j'ai ensuite évolué progressivement vers les versions XP, 7, 10, jusqu'à la version 11 actuellement installée sur ma machine de travail.

Deuxièmement, des enjeux de compatibilité logicielle — particulièrement concernant le jeu vidéo — constituent un frein majeur à la migration. La majorité des titres sont optimisés pour Windows ; une transition vers Linux ne doit donc pas compromettre l'investissement réalisé dans ces actifs numériques.

## Pourquoi quitter Windows ?

L’écosystème Windows se restreint progressivement avec des exigences techniques strictes, rendant certains équipements obsolètes avant même leur date de fin de vie. La **puce TPM 2.0**, désormais obligatoire pour les mises à jour logicielles, invalide mon ordinateur portable, tandis que l’intégration d’**une puce dédiée à l’IA** (Copilot+) rend ma station fixe incompatible avec les futures fonctionnalités.

Ajoutons à cela des innovations controversées comme **Recall**, un outil qui prévoit de capturer automatiquement des captures d’écran toutes les 5 secondes sur l’ensemble du système. Pour limiter la collecte de données sensibles (comptes bancaires, informations personnelles), il faudra configurer manuellement une liste d’exclusions – une solution peu pratique et intrusive.

Face à ces contraintes croissantes, envisager une alternative comme **Linux** apparaît comme une option plus flexible, respectueuse des données et adaptée aux besoins des utilisateurs exigeants en termes de liberté et de sécurité.

## Pourquoi passer sur Linux ?

Si l’idée de quitter Windows vous tente, mais que les solutions Apple et macOS ne correspondent pas à vos attentes (ni à votre portefeuille), Linux s’impose comme une alternative idéale ! Gratuite, légère et disponible pour presque toutes les machines, cette famille de systèmes d’exploitation regorge d’options variées.

Mais comment choisir parmi ces nombreuses distributions ? Voici quelques pistes pour affiner votre décision :

{% include elements/figure.html image="https://upload.wikimedia.org/wikipedia/commons/1/1b/Linux_Distribution_Timeline.svg" caption="Chronologie des distributions Linux" %}

Grâce au site [DistroSea](https://distrosea.com/fr/) j'ai pu tester quelques distributions, et j'en ai retenu quelques unes qu'il va falloir départager :

* [LMDE](https://linuxmint.com/download_lmde.php) (Linux Mint Debian Edition) : Réputée fiable, stable et légère
* [Garuda Linux](https://garudalinux.org/) : Basée sur Arch Linux, elle est récente, moderne, et orientée vers les joueurs
* [Nobara Linux](https://nobaraproject.org/) : Basée sur Fedora, optimisée pour le jeu vidéo ; mais originaire des États-Unis et je recherche une solution plus souveraine
* [OpenSuse](https://www.opensuse.org/) : Originaire d'Allemagne, réputée pour sa fiabilité, disponible en version *stable* et *rolling* ; mais moins optimisée pour le jeu.

Mon intention est d'installer Garuda sur mon PC portable pour m'assurer que la distribution corresponde bien à mes besoins, puis d'installer une autre distribution à côté de Windows dans un premier temps sur mon PC fixe afin d'évaluer cette  sur une utilisation quotidienne en gardant Windows "au cas où".

## Choix et installation

### PC Portable

Dans mon cas, le PC portable est secondaire, et n'est utile qu'en cas de déplacement ou vacances. Mais puisqu'il est voué à être déplacé, la sécurité des données est primordiale. Ce PC n'a pas particulièrement besoin d'être stable, et peut servir de cobaye informatique pour tester différents outils, différentes configuration.

La distribution choisie sera **Garuda**. En cas de problème lors d'une configuration hasardeuse, il sera possible de revenir en arrière grâce aux snapshots de BTRFS.

### PC Fixe

Ce choix est plus complexe car il s'agit de la machine principale.

Sur le papier, Nobara semble la meilleure solution. Mais remplacer un outil américain par un autre perd malheureusement en intérêt.

Garuda pourrait ne pas être assez stable pour une utilisation sans contrainte au quotidien.

LMDE et OpenSuse sont stables, viennent de pays européens (Irlande et Allemagne respectivement), mais manquent d'optimisation pour les jeux vidéos qui est une des utilisations principales de cette machine.

Après avoir testé ces distributions sur machines virtuelles, je pensais installer OpenSuse Tumbleweed. Mais je reconnais avoir été surpris par les corrections à apporter après l'installation sur la machine physique : des paquets installés par défaut appartenant à la version "Micro" (serveur, atomique), Windows non détecté pour pouvoir utiliser le dual-boot pour en citer quelques-unes. Si j'apprécie la liberté qu'offre Linux en matière de personnalisation, j'attends néanmoins que l'installation initiale soit propre.

Finalement, Nobara a été installée, et me permet actuellement d'écrire ces lignes. La distribution est stable, très facilement personnalisable grâce à l'environnement KDE Plasma 6, et permet de lancer des jeux vidéo sans difficulté.

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
