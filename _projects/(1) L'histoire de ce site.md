---
name: L'histoire de ce site
tools: [Personnalisation]
image: "https://cdn.pixabay.com/photo/2021/10/08/18/55/website-6692147_960_720.png"
description: Pourquoi je me suis décidé à faire mon site internet, et comment ?
---

# L'histoire du site

>Le projet est sous licence open-source MIT comme le thème initial. Vous pouvez vous en inspirer, le modifier, et l'utiliser pour votre propre site.

## 1. Pourquoi un site ?

Lorsque j'ai commencé à me former en informatique, je recherchais un moyen didactique de prendre des notes. J'avais alors commencé par un site Google, mais je me suis senti limité par l'interface.

J'envisageais donc de rédiger des contenus en Markdown que j'aurais pu stocker dans un dépôt Github. Mais il était impossible d'avoir un style personnalisé.

Lorsque j'étais en quête d'aide sur comment réaliser certains défis sur TryHackMe, j'arrivais souvent sur des sites "github.io" sans trop savoir la différence avec son équivalent ".com". C'est en cherchant des informations sur le sujet que j'ai découvert qu'on pouvait simplement et gratuitement héberger un site dans un dépôt Github. Certes le site statique, mais il est personnalisable et facile à mettre en oeuvre.

## 2. Des débuts timides

Disons le : je me suis lancé tête baissée, me basant sur le peu d'informations que j'avais lu. Et ça n'a pas marché.

J'ai donc suivi le [tutoriel sur les sites *Github Pages*](https://github.com/skills/github-pages) pour comprendre comment fonctionne concrètement l'outil, comment s'articulent les différents éléments.

Après le tutoriel, je suis parti à la recherche du [thème](https://github.com/topics/jekyll-theme) qui habillera mon site. J'ai simplement suivi les consignes du développeur qui l'a partagé, et il ne me restait plus qu'à créer le contenu.

>Un site clé en main, c'est bien ; mais un site qui me ressemble, c'est mieux.

Je me suis donc lancé dans la personnalisation de l'aspect de mon projet. Création de nouvelles pages, utilisation de plus de couleurs, amélioration des éléments existants...

## 3. Nouvelles pages et système de filtre

Le thème initial [portfolYOU](https://github.com/yousinix/portfolYOU) dispose d'une page pour des projets, et d'une autre recensant les posts de blog. Je cherchais un moyen de filtrer les posts grâce aux tags et faciliter la recherche des comptes-rendus en fonction des plateformes (THM, HTB, RootMe...).

Puisque la simple recherche par tags ne fonctionnait pas malgré l'aide de l'IA, j'ai opté pour l'adaptation de la page de blog originale pour permettre de n'afficher que les posts disposant du même tag que la page.

Les pages filtrées sont accessibles par un système de boutons.

Le code est le suivant :

```html
{% raw %}
<div class="row row-cols-1 row-cols-md-2 row-cols-lg-3 g-4 m-4 mt-5">
  {% assign filtered_posts = site.posts | where: "tags", page.tags %}
  
  {% for post in filtered_posts %}
    {% include blog/post-card.html %}
  {% endfor %}
</div>
{% endraw %}
```

## 4. Amélioration du carrousel

Par défaut, le carrousel ne fait qu'afficher des images. Puisque mon idée était de partager les badges et certificats avec leurs liens respectifs, j'ai dû adapter le code pour que les images soient cliquables, et puissent rediriger vers les pages de vérification des badges.

Une autre modification importante par rapport à l'outil original, la possibilité d'ajouter autant de carrousels que nécessaires par page. Initialement, les flèches permettant de faire défiler les images étaient liées au premier carrousel, rendant les suivants inutiles.

Les carrousels cliquables sont disponibles [ici](https://github.com/TiFloF29/Hackministrateur/blob/main/_includes/elements/carousel-click.html)

## 5. Utilisation de couleurs personnalisées

Le thème existant utilise Bootstrap version 4.6.0 qui permet d'avoir un site uniforme et rapidement fonctionnel. Néanmoins, sa mise en place limitait l'utilisation à quelques mots-clés prédéfinis. Il m'a fallu comprendre le fonctionnement de l'outil et modifier les fichiers SCSS. Le premier objectif était de pouvoir coloriser les *cards* des comptes-rendus avec les couleurs des plateformes correspondantes. Il aura été nécessaire de récupérer l'intégralité des fichiers de style du thème pour mon projet, sans quoi le thème prenait le dessus sur mes modifications.

## 6. Traduction des dates

Le thème utilise le langage Liquid notamment utilisé pour rendre les pages en HTML, statiques, plus dynamique. Liquid permet nativement de convertir une date en format numérique en texte. Mais cela ne fonctionne qu'en Anglais.

Pour avoir des dates automatiquement en Français, j'ai adapté le code de [freakdesign](https://freakdesign.com.au/blogs/news/translate-a-liquid-date-string-in-shopify) pour l'outil Shopify afin de le rendre compatible avec un projet Jekyll. Le fichier modifié est également accessible dans [mon dépôt Github](https://github.com/TiFloF29/Hackministrateur/blob/main/_includes/date-translate.liquid)

## 7. Un dictionnaire commun

J'ai souhaité mettre en place un [dictionnaire](https://github.com/TiFloF29/Hackministrateur/blob/main/_includes/dictionary.html) contenant des explications concernant des abréviations fréquemment utilisées dans les comptes-rendus, comme {% include dictionary.html word="NMAP" %}, et des outils comme {% include dictionary.html word="gobuster" %}. Je peux ainsi facilement ajouter une note accessible au survol du mot souligné par le pointeur de la souris.

## 8. Mise à jour du cœur du site

La dernière version du thème créé par [yousinix](https://github.com/yousinix/portfolYOU) n'a pas été mis à jour depuis août 2021. [Bootstrap est en version 4.6.0](https://getbootstrap.com/docs/4.6/getting-started/introduction/), les animations de [animate.css](https://animate.style/) en v3.7.0 et [WOW](https://github.com/graingert/wow) en v1.1.2, et les icônes de [Font Awesome](https://fontawesome.com/) en v5.15.4.

J'ai donc entrepris de mettre à jour ma version du thème vers les dernières itérations de Bootstrap (v5.3.0) et Font Awesome (v6.0.0) et changer les animations de WOW par celles de AOS (*Animate On Scroll*), WOW étant "temporairement obsolète" d'après l'annonce sur son dépôt Github. Animate.css a été mis à jour vers la version 4.1.1.

<div class="text-center">
    <i class="fa-solid fa-1xl text-info">Redaction en cours</i><br />
    <i class="fa-solid fa-spinner fa-spin-pulse fa-2xl text-info mt-3"></i>
</div>
