---
name: Explorer les alternatives
tools: [Personnalisation, Open Source, Souveraineté numérique]
image: "https://cdn.pixabay.com/photo/2022/03/20/03/17/windows-7079876_960_720.png"
description: Reprendre le contrôle de mes données
---
# Explorer les outils alternatifs <!-- omit in toc -->

## Sommaire <!-- omit in toc -->

* [Pourquoi changer ce qu'on utilise ?](#pourquoi-changer-ce-quon-utilise-)
* [Service mail](#service-mail)
* [Système d'exploitation](#système-dexploitation)
* [Navigateur](#navigateur)

## Pourquoi changer ce qu'on utilise ?

Service de mail, logiciels, systèmes d'exploitation... Tant que ça marche, pourquoi vouloir changer ?

Dans mon cas, il s'agissait de vouloir réduire ma dépendance aux outils non-Européens, et reprendre le contrôle de mes données personnelles.

Une autre raison était de remplacer certains outils payants et propriétaires par des alternatives **gratuites** et **open-source**.

## Service mail

Le premier chantier consistait à changer de service mail, et passer de Google à un service plus soucieux de la vie privée de ses utilisateurs.

Google fourni tout un écosystème associé à une adresse mail, et les produits sont de très bonnes qualités pour une utilisation quotidienne :

1. Gratuit pour une utilisation personnelle
2. Sécurisé : pas souvenir de compte compromis depuis la création du compte il y a près de 20 ans
3. Permet d'accéder à Drive, YouTube, Android, Agenda
4. Permet de se connecter à divers outils tiers

Mais en contrepartie, Google utilise nos données personnelles pour nous fournir de la publicité ciblée. Ces données incluent (mais ne se limitent pas à) l'historique de recherche, le contenu des mails, et les documents ajoutés dans le Drive.

L'option choisie est [Proton](proton.me), originaire de Suisse, qui fournie un écosystème certes moins mature aujourd'hui, mais davantage orienté sur la protection des données :

1. Service de mails chiffré avec politique zéro accès (Proton n'a pas accès au contenu de nos messages)
2. Gestionnaire de mots de passe et d'identités numériques (dont la force est la gestion d'alias d'adresses mail)
3. Un espace de stockage chiffré
4. Un VPN certifié zéro log
5. Un assistant IA (Lumo)

Mais le respect de la vie privée à un coût. Si l'accès est techniquement gratuit, le contenu reste fortement limité. Mais celà permet de tester les produits et savoir quel abonnement convient le mieux à notre utilisation.

## Système d'exploitation

Comme plus [70% des utilisateurs de PC](https://en.wikipedia.org/wiki/Usage_share_of_operating_systems#Market_share_by_category), et comme plus de [90% des joueurs sur PC](https://en.wikipedia.org/wiki/Usage_share_of_operating_systems#Desktop_computer_games), j'ai utilisé Windows pendant des années, commençant sur 95, puis XP, 10 et 11.

Mais les contraintes pour l'utilisation de l'OS se multiplient depuis des années (TPM 2.0 pour le chiffrement, puce IA pour Copilot+) ainsi que la [fonction controversée Recall](https://www.lemondeinformatique.fr/actualites/lire-microsoft-suspend-le-patch-tuesday-de-juillet-100705.html), l'obligation d'un compte Microsoft pour utiliser son ordinateur m'ont incité à quitter Microsoft.

Deux alternatives se sont donc présentées : Mac et Linux.

D'un côté, un OS réputé pour son écosystème complet, robuste, mais nécessitant d'acheter un matériel spécifique, et connu pour ses prix supérieurs à Windows à puissance équivalente.

De l'autre, un monde complet avec *virtuellement* une infinité de possibilités, open-source, gratuit, tournant sur le matériel en ma possession.

Mon choix s'est naturellement porté vers Linux, mais il a fallu des mois pour trouver la distribution qui me convenait le mieux. Et pour cause 

<details><summary>Montrer la Timeline de Linux</summary>
  <figure class="figure w-100">
    <img src="https://upload.wikimedia.org/wikipedia/commons/1/1b/Linux_Distribution_Timeline.svg?utm_source=commons.wikimedia.org&utm_campaign=index&utm_content=original" class="figure-img img-fluid rounded" alt="Linux Timeline">
      <figcaption class="figure-caption text-center text-secondary">Linux Timeline</figcaption>
  </figure>
</details><br />

La distribution que je souhaitais installé devait :

1. Être stable pour une utilisation quotidienne
2. Être utilisable sans passer des heures à peaufiner les réglages
3. Avoir une communauté active et/ou reposer sur une grande distribution pour faciliter la maintenance malgré tout
4. Être optimisée pour le jeu vidéo
5. Être facilement personnalisable
6. Ne pas être trop "verrouillée"

La distribution qui est ressortie du lot est [Nobara Linux](https://nobaraproject.org/). Les raisons pour ce choix :

1. Basée sur Fedora (Red Hat), donc bénéficie d'une communauté conséquente si celle de Nobara n'a pas la réponse aux problèmes rencontrés
2. Développée par [Glorious Eggroll](https://github.com/GloriousEggroll), ingénieur chez Red Hat, personne derrière GE-Proton (outil de compatibilité pour les jeux vidéos, **GE** correspondant aux initiales de Glorious Eggroll)
3. Arrive avec les pilotes nécessaires pour fonctionner avec la plupart des cartes graphiques

Depuis la mi-juin 2026 Nobara est devenu le système d'exploitation principale de mon PC fixe sans blocage particulier depuis. Je verrais pour mettre à jour ce passage au besoin. (à jour le 03/09/2026).

En parallèle, mon PC portable incompatible avec Windows 11 est intégralement passé sur Garuda Linux, une distribution également optimisée pour le jeu vidéo, basé sur Arch, mais cette distribution ne me paraît pas suffisamment stable pour une utilisation quotidienne paisible.

## Navigateur

Lorsqu'on possède un compte Google, il est aisé de vouloir tout synchroniser, et le navigateur Google Chrome est précisément là pour ça. Mais cela vient avec moins de vie privée, et plus de risque de compromission de compte en mettant tous ses œufs dans le même panier.

Pour remplacer Chrome, je souhaitais un navigateur personnalisable, respectueux de la vie privée

Le navigateur [Zen Browser](https://zen-browser.app/) est basé du Firefox, open-source et dispose d'une bibliothèque de "Mods" permettant de personnaliser son expérience.
